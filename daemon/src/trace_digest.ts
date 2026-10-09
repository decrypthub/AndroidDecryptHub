// Turn a raw QBDI instruction stream into something an analyst (or an AI) can read.
//
// `qbdi_trace` returns up to 8192 `{addr, text}` records - accurate but unreadable at that size.
// This digest extracts the parts that actually answer "what does this function do": loops, calls,
// memory access patterns, materialised constants, branch shape and hot instructions. The core is a
// pure function over the instruction list (unit-tested without a device); the MCP handler adds
// symbol names for call targets and hot addresses through module_symbols.
import { loadModuleTable, symbolizeAddresses, parseHex, hex, type ModuleTable, type SymbolizedAddress } from './module_symbols.ts';

export interface TraceInsn { addr: string; text: string }

export interface TraceDigest {
  instructions: number;
  uniqueAddresses: number;
  mnemonics: { mnemonic: string; count: number }[];
  hotInstructions: { addr: string; text: string; count: number }[];
  loops: { target: string; end: string; bodyInstructions: number; iterations: number }[];
  calls: { target: string; via: string; count: number }[];
  memory: { mnemonic: string; base: string; offset: string; count: number }[];
  constants: { value: string; decimal: string; count: number; note?: string }[];
  branches: { conditional: number; unconditional: number; indirect: number; targets: { target: string; count: number }[] };
  notes: string[];
}

// Magic numbers that show up in hand-rolled crypto/hash code. Flagging them is a cheap hint for the
// analyst - it is deliberately a short list of constants people actually see in the wild.
const CRYPTO_CONSTANTS: Record<string, string> = {
  '0x9e3779b9': 'golden ratio (TEA/XXTEA/RC5 style)',
  '0x9e3779b97f4a7c15': 'golden ratio 64-bit (splitmix/xxhash)',
  '0x67452301': 'MD5/SHA1 init A',
  '0xefcdab89': 'MD5/SHA1 init B',
  '0x98badcfe': 'MD5/SHA1 init C',
  '0x10325476': 'MD5/SHA1 init D',
  '0xc3d2e1f0': 'SHA1 init E',
  '0x5a827999': 'SHA1 round constant',
  '0x6ed9eba1': 'SHA1 round constant',
  '0x8f1bbcdc': 'SHA1 round constant',
  '0xca62c1d6': 'SHA1 round constant',
  '0x6a09e667': 'SHA-256 init',
  '0xbb67ae85': 'SHA-256 init',
  '0x3c6ef372': 'SHA-256 init',
  '0xa54ff53a': 'SHA-256 init',
  '0x510e527f': 'SHA-256 init',
  '0x1f83d9ab': 'SHA-256 init',
  '0x5be0cd19': 'SHA-256 init',
  '0xcbf29ce484222325': 'FNV-1a 64 offset basis',
  '0x811c9dc5': 'FNV-1a 32 offset basis',
  '0x1000193': 'FNV-1a prime',
};

const MEMORY_MNEMONICS = new Set([
  'ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldrsw', 'ldur', 'ldurb', 'ldurh', 'ldursw',
  'str', 'strb', 'strh', 'stur', 'sturb', 'sturh',
  'ldp', 'stp', 'ldnp', 'stnp', 'ldxr', 'ldaxr', 'stxr', 'stlxr', 'ldar', 'stlr',
]);

function splitInsn(text: string): { mnemonic: string; operands: string } {
  const t = String(text ?? '').trim();
  if (!t) return { mnemonic: '', operands: '' };
  const sp = t.search(/\s/);
  if (sp < 0) return { mnemonic: t.toLowerCase(), operands: '' };
  return { mnemonic: t.slice(0, sp).toLowerCase(), operands: t.slice(sp + 1).trim() };
}

function parseImm(token: string): bigint | null {
  const m = /^#?(-?)0x([0-9a-f]+)$/i.exec(token.trim());
  if (m) {
    const v = BigInt(`0x${m[2]}`);
    return m[1] === '-' ? -v : v;
  }
  const d = /^#?(-?[0-9]+)$/.exec(token.trim());
  if (d) return BigInt(d[1]);
  return null;
}

/** "[x1, #0x18]" -> base x1, offset #0x18; "[x0]" -> base x0, offset 0. */
function parseMemOperand(operand: string): { base: string; offset: string } | null {
  const open = operand.indexOf('[');
  const close = operand.indexOf(']', open);
  if (open < 0 || close < 0) return null;
  const inner = operand.slice(open + 1, close);
  const parts = inner.split(',').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;
  const base = parts[0].toLowerCase();
  if (!/^[xw][0-9]+$|^sp$|^xzr$|^wzr$/.test(base)) return null;
  let offset = '0';
  for (const part of parts.slice(1)) {
    const imm = parseImm(part.replace(/\s+/g, ''));
    if (imm != null) { offset = `${imm < 0n ? '-' : ''}0x${(imm < 0n ? -imm : imm).toString(16)}`; break; }
  }
  return { base, offset };
}

export function digestTrace(insns: TraceInsn[], opts: { maxHot?: number; maxList?: number } = {}): TraceDigest {
  const maxHot = Math.max(1, Math.min(20, opts.maxHot ?? 5));
  const maxList = Math.max(1, Math.min(50, opts.maxList ?? 10));
  const notes: string[] = [];
  const list = Array.isArray(insns) ? insns.filter((i) => i && typeof i.addr === 'string') : [];
  if (!list.length) {
    return {
      instructions: 0, uniqueAddresses: 0, mnemonics: [], hotInstructions: [], loops: [], calls: [], memory: [],
      constants: [], branches: { conditional: 0, unconditional: 0, indirect: 0, targets: [] },
      notes: ['empty trace: the traced function executed 0 instructions (a failed QBDI start is reported separately as ok:false)'],
    };
  }

  const mnemonicCount = new Map<string, number>();
  const addrCount = new Map<string, number>();
  const addrText = new Map<string, string>();
  const callCount = new Map<string, { via: string; count: number }>();
  const memCount = new Map<string, { mnemonic: string; base: string; offset: string; count: number }>();
  const constCount = new Map<string, { value: bigint; count: number }>();
  const branchTargets = new Map<string, number>();
  let conditional = 0, unconditional = 0, indirect = 0;

  for (const insn of list) {
    const { mnemonic, operands } = splitInsn(insn.text);
    if (!mnemonic) continue;
    mnemonicCount.set(mnemonic, (mnemonicCount.get(mnemonic) ?? 0) + 1);
    const addr = insn.addr.toLowerCase();
    addrCount.set(addr, (addrCount.get(addr) ?? 0) + 1);
    if (!addrText.has(addr)) addrText.set(addr, String(insn.text ?? '').trim());

    // calls
    if (mnemonic === 'bl' || mnemonic === 'blr') {
      const target = parseImm(operands.split(',')[0]);
      const key = target != null ? `0x${target.toString(16)}` : `(${operands.split(',')[0] || 'register'})`;
      const entry = callCount.get(key) ?? { via: mnemonic, count: 0 };
      entry.count++;
      callCount.set(key, entry);
    }

    // memory access shape
    if (MEMORY_MNEMONICS.has(mnemonic)) {
      for (const operand of operands.match(/\[[^\]]*\]/g) ?? []) {
        const mem = parseMemOperand(operand);
        if (!mem) continue;
        const key = `${mnemonic}|${mem.base}|${mem.offset}`;
        const entry = memCount.get(key) ?? { mnemonic, base: mem.base, offset: mem.offset, count: 0 };
        entry.count++;
        memCount.set(key, entry);
      }
    }

    // materialised immediates (mov/movz/movk/orr with an immediate operand)
    if (mnemonic === 'mov' || mnemonic === 'movz' || mnemonic === 'movk' || mnemonic === 'orr' || mnemonic === 'movn') {
      const parts = operands.split(',');
      const immToken = parts.length ? parts[parts.length - 1].trim().replace(/\s+lsl\s+#?\d+$/i, '') : '';
      const imm = parseImm(immToken);
      if (imm != null && imm !== 0n) {
        const key = imm.toString();
        const entry = constCount.get(key) ?? { value: imm, count: 0 };
        entry.count++;
        constCount.set(key, entry);
      }
    }

    // branches
    if (mnemonic === 'b' || mnemonic === 'br') {
      if (mnemonic === 'br') indirect++;
      else {
        unconditional++;
        const target = parseImm(operands.split(',')[0]);
        if (target != null) {
          const key = `0x${target.toString(16)}`;
          branchTargets.set(key, (branchTargets.get(key) ?? 0) + 1);
        }
      }
    } else if (/^b\.[a-z]+$/.test(mnemonic) || mnemonic === 'cbz' || mnemonic === 'cbnz' || mnemonic === 'tbz' || mnemonic === 'tbnz') {
      conditional++;
      const target = parseImm(operands.split(',').pop() ?? '');
      if (target != null) {
        const key = `0x${target.toString(16)}`;
        branchTargets.set(key, (branchTargets.get(key) ?? 0) + 1);
      }
    } else if (mnemonic === 'ret') {
      // RET is the natural end of the traced function; count it but do not call it a branch target.
    }
  }

  // loops: an address executed more than once is a back-edge target. The body is the span between
  // its first occurrence and the instruction before the second one - a heuristic, and reported as
  // such (bodyInstructions + iterations), not as a control-flow graph fact.
  const firstSeen = new Map<string, number>();
  const loops: { target: string; end: string; bodyInstructions: number; iterations: number }[] = [];
  for (let i = 0; i < list.length; i++) {
    const addr = list[i].addr.toLowerCase();
    const first = firstSeen.get(addr);
    if (first == null) { firstSeen.set(addr, i); continue; }
    if (!branchTargets.has(addr)) continue;      // repeated call sites are not loops
    const iterations = addrCount.get(addr) ?? 0;
    const endAddr = i > 0 ? list[i - 1].addr : list[i].addr;
    const bodyInstructions = i - first;
    if (bodyInstructions >= 2 && loops.length < maxList) {
      loops.push({ target: addr, end: endAddr.toLowerCase(), bodyInstructions, iterations });
    }
  }
  // Deduplicate loops by target, keeping the largest body seen for that target.
  const loopByTarget = new Map<string, { target: string; end: string; bodyInstructions: number; iterations: number }>();
  for (const l of loops) {
    const prev = loopByTarget.get(l.target);
    if (!prev || l.bodyInstructions > prev.bodyInstructions) loopByTarget.set(l.target, l);
  }

  const hot = [...addrCount.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, maxHot)
    .map(([addr, count]) => ({ addr, text: addrText.get(addr) ?? '', count }));

  const constants = [...constCount.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, maxList)
    .map(([, v]) => {
      const hexValue = `0x${(v.value < 0n ? -v.value : v.value).toString(16)}`;
      const note = CRYPTO_CONSTANTS[hexValue];
      return {
        value: v.value < 0n ? `-${hexValue}` : hexValue,
        decimal: v.value.toString(),
        count: v.count,
        ...(note ? { note } : {}),
      };
    });

  const calls = [...callCount.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, maxList)
    .map(([target, v]) => ({ target, via: v.via, count: v.count }));

  const memory = [...memCount.values()].sort((a, b) => b.count - a.count).slice(0, maxList);

  const mnemonics = [...mnemonicCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxList)
    .map(([mnemonic, count]) => ({ mnemonic, count }));

  if (calls.some((c) => c.target.startsWith('('))) notes.push('some call targets are register-indirect (blr) and were not resolved');
  if (!loops.length) notes.push('no repeated address found: the traced function looks straight-line (or the loop was inlined away)');

  return {
    instructions: list.length,
    uniqueAddresses: addrCount.size,
    mnemonics,
    hotInstructions: hot,
    loops: [...loopByTarget.values()].sort((a, b) => b.iterations - a.iterations).slice(0, maxList),
    calls,
    memory,
    constants,
    branches: {
      conditional, unconditional, indirect,
      targets: [...branchTargets.entries()].sort((a, b) => b[1] - a[1]).slice(0, maxList).map(([target, count]) => ({ target, count })),
    },
    notes,
  };
}

/**
 * How complete the recorded trace is. The agent sends count == the records it carried, seen == what
 * it collected and a truncated flag; a reply from an older agent has only count, in which case
 * seen is taken from the list length and nothing is claimed about clipping.
 */
export function traceCompleteness(
  raw: { count?: unknown; seen?: unknown; truncated?: unknown; cap?: unknown },
  insnCount: number,
): { seen: number; truncated: boolean; cap: number | null } {
  // Never claim fewer records than the list holds: an old agent's count is what it SAW, so it can
  // only be >= the list length; if it is smaller the list is still the truth.
  const seen = Number.isFinite(Number(raw.seen))
    ? Number(raw.seen)
    : Math.max(Number(raw.count ?? insnCount), insnCount);
  return {
    seen,
    truncated: raw.truncated === true || seen > insnCount,
    cap: raw.cap != null && Number.isFinite(Number(raw.cap)) ? Number(raw.cap) : null,
  };
}

export interface TraceDigestResult {
  retval: string | null;
  /** Instructions in the digest - always the length of the list that was analysed. */
  instructionCount: number;
  /** What the agent collected before the reply was built; > instructionCount means it was clipped. */
  seen: number;
  /** The agent hit its instruction cap or could not fit every record into the reply. */
  truncated: boolean;
  cap: number | null;
  digest: TraceDigest;
  symbolNames: Record<string, SymbolizedAddress>;
}

/** Run qbdi_trace on the session and digest the result, adding symbol names where possible. */
export async function traceDigest(session: string, opts: { symLib: string; symbol: string; args?: unknown[] }): Promise<TraceDigestResult> {
  // The agent refuses a trace without an explicit library since v4.50 (no fixture names there),
  // so fail with a clear message HERE instead of forwarding an empty string.
  if (!opts.symLib) throw new Error('trace_digest needs symLib (the module that defines the symbol)');
  const { sendCmd } = await import('./service.ts');
  const raw = await sendCmd(session, 'qbdi_trace', {
    symLib: opts.symLib ?? '',
    symbol: opts.symbol,
    args: Array.isArray(opts.args) ? opts.args.map((a) => String(a)).join(',') : '',
  }, 60_000);
  if (raw?.ok !== true) throw new Error(raw?.error ?? 'qbdi_trace failed');
  const insns: TraceInsn[] = Array.isArray(raw.insns)
    ? raw.insns.map((i: any) => ({ addr: String(i.addr ?? ''), text: String(i.text ?? '') }))
    : [];
  const digest = digestTrace(insns);

  // Symbolize what the analyst will look at: call targets and the hottest instructions.
  const interesting = new Set<string>();
  for (const call of digest.calls) if (!call.target.startsWith('(')) interesting.add(call.target);
  for (const hot of digest.hotInstructions) interesting.add(hot.addr);
  const symbolNames: Record<string, SymbolizedAddress> = {};
  const addrs = [...interesting].map((a) => parseHex(a)).filter((v): v is bigint => v != null);
  if (addrs.length) {
    try {
      const table: ModuleTable = await loadModuleTable(session);
      const map = await symbolizeAddresses(session, addrs, table);
      for (const [key, value] of map) {
        if (value.module) symbolNames[key] = value;
      }
    } catch (e) {
      digest.notes.push(`symbolization unavailable: ${(e as Error).message}`);
    }
  }
  // The counters must describe the list that was digested: `raw.count` used to be "everything
  // the agent saw" while the list stopped at the reply-buffer limit, so a clipped trace was
  // reported as a complete one. The agent now sends count == records and a truncated flag;
  // either way instructionCount follows the list.
  const { seen, truncated, cap } = traceCompleteness(raw, insns.length);
  if (truncated) {
    digest.notes.push(`trace was clipped: ${insns.length} of ${seen} instructions were recorded`
      + (cap ? ` (cap ${cap})` : '') + ' - the digest describes the recorded prefix only');
  }
  return {
    retval: raw.retval != null ? `0x${BigInt(raw.retval).toString(16)}` : null,
    instructionCount: insns.length,
    seen,
    truncated,
    cap,
    digest,
    symbolNames,
  };
}
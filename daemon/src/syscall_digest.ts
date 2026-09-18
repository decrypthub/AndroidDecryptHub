// Group watched syscall hits into something an analyst can act on.
//
// The watch already reports one NATIVE_HOOK event per syscall hit (with `x8` and, since v4.39, the
// caller chain `bt`). What it does NOT answer is the question the feature exists for: "which app
// function collects this fingerprint, and how often". This module groups the events by
// (syscall number, caller symbol) and keeps the runtime x8 next to the statically attributed number,
// so a wrong attribution shows up as a mismatch instead of silently mislabelling the hook.
import { captures } from './state.ts';
import { sendCmd } from './service.ts';
import { loadModuleTable, symbolizeAddresses, parseHex, hex, type SymbolizedAddress } from './module_symbols.ts';
import { argPlan, decodeArgs, pathOf, summarizeArgs, type DecodedArg } from './syscall_args.ts';

export interface SyscallCaller {
  module: string | null;
  symbol: string | null;
  offset: string | null;
  /** Raw frame address, kept even when no module/symbol could be resolved. */
  address?: string;
  /** false = the symbol is the nearest PRECEDING one, not one whose size covers the address. */
  exact?: boolean;
}
export interface SyscallSample {
  hookId: number;
  ts: number;
  tid: number;
  observedNr: number | null;
  callers: SyscallCaller[];
  regs?: bigint[];
  args?: DecodedArg[];
  /** The immediate frame (bt[0]) even when a wrapper is the interesting caller. */
  immediate?: SyscallCaller | null;
}

export interface SyscallGroup {
  nr: number | null;
  name: string;
  caller: string;
  count: number;
  firstTs: number;
  lastTs: number;
  tids: number[];
  example?: string;
}

export interface SyscallDigest {
  samples: number;
  groups: SyscallGroup[];
  observed: { nr: number | null; count: number }[];
  mismatches: { hookId: number; attributed: number; observed: number; count: number }[];
  hooksSeen: number[];
  // "which files/names did it probe": the path-like argument per sample, grouped. This is the
  // fingerprint-collection signal the whole watch exists for.
  paths: { path: string; count: number }[];
  decodedSamples: number;
  /** Timestamps the samples actually span (the caller's sinceMs window may be wider). */
  observedFrom: number | null;
  observedTo: number | null;
  notes: string[];
}

// Frames that merely WRAP the syscall: the interesting one is the first outside these, i.e. the code
// that decided to make the call. libc is the common case; the ART/runtime libraries show up when the
// VM itself (GC, JIT, class loading) issues syscalls and there is no app frame above it.
const LIBC_FAMILY = /(^|\/)(libc|libc\+\+|libm|libdl|libbinder_ndk|libbase)\.so$/;
const RUNTIME_FAMILY = /(^|\/)(libart|libartbase|libandroid_runtime|libnativehelper|libutils|libbinder|libopenjdk)\.so$/;

export function pickCaller(callers: SyscallCaller[]): SyscallCaller | null {
  for (const c of callers) {
    if (c.module && (LIBC_FAMILY.test(c.module) || RUNTIME_FAMILY.test(c.module))) continue;
    // Unmapped / JIT frames are accepted (they carry the raw address) instead of being skipped: a
    // JITted caller is a real caller, and skipping it would attribute the syscall to a deeper frame.
    if (!c.module && !c.address) continue;
    return c;
  }
  return callers.length ? callers[0] : null;
}

export function callerLabel(caller: SyscallCaller | null): string {
  if (!caller) return '(unknown)';
  if (caller.symbol) {
    const base = `${caller.module ?? '?'}:${caller.symbol}`;
    return caller.exact === false ? `${base} (near)` : base;
  }
  if (caller.module && caller.offset) return `${caller.module}+${caller.offset}`;
  if (caller.address) return `${caller.address} (no module)`;
  return caller.module ?? '(unknown)';
}

export function digestSyscallSamples(samples: SyscallSample[], opts: {
  expected?: Record<number, number>;
  names?: Record<number, string>;
  maxGroups?: number;
  maxTids?: number;
} = {}): SyscallDigest {
  const maxGroups = Math.max(1, Math.min(200, opts.maxGroups ?? 50));
  const maxTids = Math.max(1, Math.min(16, opts.maxTids ?? 6));
  const notes: string[] = [];
  const list = Array.isArray(samples) ? samples : [];

  const groupMap = new Map<string, SyscallGroup>();
  const pathMap = new Map<string, number>();
  let decodedSamples = 0;
  let observedFrom: number | null = null;
  let observedTo: number | null = null;
  const observedMap = new Map<string, { nr: number | null; count: number }>();
  const mismatchMap = new Map<string, { hookId: number; attributed: number; observed: number; count: number }>();
  const hooksSeen = new Set<number>();

  for (const s of list) {
    if (!s || typeof s.hookId !== 'number') continue;
    hooksSeen.add(s.hookId);
    const caller = pickCaller(s.callers ?? []);
    const label = callerLabel(caller);
    if (s.ts && (observedFrom === null || s.ts < observedFrom)) observedFrom = s.ts;
    if (s.ts && (observedTo === null || s.ts > observedTo)) observedTo = s.ts;
    const key = `${s.observedNr ?? '?'}|${label}`;
    const g = groupMap.get(key);
    if (g) {
      g.count++;
      if (s.ts < g.firstTs) g.firstTs = s.ts;
      if (s.ts > g.lastTs) g.lastTs = s.ts;
      if (g.tids.length < maxTids && !g.tids.includes(s.tid)) g.tids.push(s.tid);
    } else {
      groupMap.set(key, {
        nr: s.observedNr,
        name: s.observedNr == null ? 'unknown' : (opts.names?.[s.observedNr] ?? `syscall_${s.observedNr}`),
        caller: label,
        count: 1,
        firstTs: s.ts,
        lastTs: s.ts,
        tids: [s.tid],
      });
    }
    if (Array.isArray(s.args) && s.args.length) {
      decodedSamples++;
      const g2 = groupMap.get(key)!;
      if (!g2.example) g2.example = summarizeArgs(s.args);
      const p = s.observedNr == null ? null : pathOf(s.observedNr, s.args);
      if (p) pathMap.set(p, (pathMap.get(p) ?? 0) + 1);
    }
    const obsKey = String(s.observedNr ?? '?');
    const obs = observedMap.get(obsKey) ?? { nr: s.observedNr, count: 0 };
    obs.count++;
    observedMap.set(obsKey, obs);

    const attributed = s.observedNr != null ? opts.expected?.[s.hookId] : undefined;
    if (attributed != null && s.observedNr != null && attributed !== s.observedNr) {
      const mk = `${s.hookId}|${attributed}|${s.observedNr}`;
      const mm = mismatchMap.get(mk) ?? { hookId: s.hookId, attributed, observed: s.observedNr, count: 0 };
      mm.count++;
      mismatchMap.set(mk, mm);
    }
  }

  const groups = [...groupMap.values()].sort((a, b) => b.count - a.count).slice(0, maxGroups);
  if (groupMap.size > maxGroups) notes.push(`grouped by (nr, caller): showing the top ${maxGroups} of ${groupMap.size}`);
  if (pathMap.size > maxGroups) notes.push(`paths: showing the top ${maxGroups} of ${pathMap.size}`);
  if (!list.length) notes.push('no syscall events in scope: install a watch first (syscall_watch) and trigger the target');
  if (mismatchMap.size) notes.push('attribution mismatch: the static x8 guess and the runtime x8 disagree for at least one hook - the hook sits at a site whose number is not the one that was decoded');

  return {
    samples: list.length,
    groups,
    observed: [...observedMap.values()].sort((a, b) => b.count - a.count),
    mismatches: [...mismatchMap.values()],
    hooksSeen: [...hooksSeen].sort((a, b) => a - b),
    paths: [...pathMap.entries()].map(([path, count]) => ({ path, count })).sort((a, b) => b.count - a.count).slice(0, maxGroups),
    decodedSamples,
    observedFrom,
    observedTo,
    notes,
  };
}

export interface SyscallDigestResult extends SyscallDigest {
  window: { sinceMs: number | null; limit: number };
  symbolSource: string;
}

/** Read the session's NATIVE_HOOK captures, parse them and digest the syscall hits. */
export async function syscallDigest(session: string, opts: {
  hookIds?: number[];
  expected?: Record<string, number>;
  sinceMs?: number;
  limit?: number;
  maxGroups?: number;
  // Argument decoding reads the target's memory through pointer arguments (paths, sockaddrs,
  // utsname). Bounded by decodeLimit samples so a busy watch cannot turn the digest into a
  // memory-read storm.
  decode?: boolean;
  decodeLimit?: number;
} = {}): Promise<SyscallDigestResult> {
  const limit = Math.max(1, Math.min(5000, Math.trunc(Number(opts.limit ?? 1000))));
  const sinceMs = Number.isFinite(Number(opts.sinceMs)) ? Number(opts.sinceMs) : null;
  const wanted = new Set((opts.hookIds ?? []).map((v) => Number(v)).filter((v) => Number.isFinite(v)));
  const expected: Record<number, number> = {};
  for (const [k, v] of Object.entries(opts.expected ?? {})) {
    const id = Number(k), nr = Number(v);
    if (Number.isFinite(id) && Number.isFinite(nr)) expected[id] = nr;
  }

  const raw: { hookId: number; ts: number; tid: number; observedNr: number | null; bt: bigint[]; regs: bigint[] }[] = [];
  for (let i = captures.length - 1; i >= 0 && raw.length < limit; i--) {
    const c: any = captures[i];
    if (c.sessionId !== session || c.func !== 'NATIVE_HOOK') continue;
    if (sinceMs != null && Number(c.ts) < sinceMs) break;      // the store is append-ordered
    let text = '';
    try { text = Buffer.from(String(c.hex ?? ''), 'hex').toString('utf8'); } catch { text = ''; }
    if (!text) continue;
    let event: any = null;
    try { event = JSON.parse(text); } catch { continue; }
    const hookId = Number(event.hookId);
    if (!Number.isFinite(hookId)) continue;
    if (wanted.size && !wanted.has(hookId)) continue;
    const observedNr = event.x8 != null ? Number(BigInt(event.x8)) : null;
    const bt: bigint[] = Array.isArray(event.bt)
      ? event.bt.map((v: any) => parseHex(v)).filter((v: bigint | null): v is bigint => v != null)
      : [];
    const regs: bigint[] = [];
    for (const key of ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8']) {
      const v = event[key];
      const parsed = parseHex(v);
      regs.push(parsed ?? 0n);
    }
    raw.push({ hookId, ts: Number(c.ts ?? 0), tid: Number(c.tid ?? 0), observedNr, bt, regs });
  }

  // Symbolize every frame we might report as the caller (bounded by the sample count).
  const addrSet = new Set<string>();
  for (const r of raw) for (const a of r.bt.slice(0, 4)) addrSet.add(hex(a));
  const symbolMap = new Map<string, SymbolizedAddress>();
  let symbolSource = 'none';
  if (addrSet.size) {
    try {
      const table = await loadModuleTable(session);
      const m = await symbolizeAddresses(session, [...addrSet].map((a) => parseHex(a)!).filter(Boolean), table);
      for (const [k, v] of m) symbolMap.set(k, v);
      symbolSource = (m as any).symbolSource ?? 'dynsym';
    } catch { symbolSource = 'unavailable'; }
  }

  const samples: SyscallSample[] = raw.map((r) => ({
    hookId: r.hookId,
    ts: r.ts,
    tid: r.tid,
    observedNr: r.observedNr,
    regs: r.regs,
    callers: r.bt.slice(0, 4).map((a) => {
      const s = symbolMap.get(hex(a));
      return s
        ? { module: s.module, symbol: s.symbol, offset: s.moduleOffset, address: hex(a), exact: s.symbolExact }
        : { module: null, symbol: null, offset: null, address: hex(a) };   // keep the address either way
    }),
    immediate: (() => {
      if (!r.bt.length) return null;
      const s = symbolMap.get(hex(r.bt[0]));
      return s
        ? { module: s.module, symbol: s.symbol, offset: s.moduleOffset, address: hex(r.bt[0]), exact: s.symbolExact }
        : { module: null, symbol: null, offset: null, address: hex(r.bt[0]) };
    })(),
  }));

  // Argument decoding: bounded, and only for the samples that actually have a number to decode.
  const decodeNotes: string[] = [];
  let decodedCount = 0;
  if (opts.decode !== false) {
    const decodeLimit = Math.max(0, Math.min(200, Math.trunc(Number(opts.decodeLimit ?? 40))));
    for (const s of samples) {
      if (decodedCount >= decodeLimit) break;
      if (s.observedNr == null) continue;
      const plan = argPlan(s.observedNr, s.regs ?? []);
      const mem: Record<number, Buffer | null> = {};
      let unreadable = false;
      for (const read of plan.reads.slice(0, 2)) {
        if (read.addr === 0n || read.len <= 0) { mem[read.reg] = null; continue; }
        let buf: Buffer = Buffer.alloc(0);
        try {
          // 4s per read instead of readMem's 20s: decoding is bounded by decodeLimit samples and a
          // wedged agent would otherwise multiply the timeout by the sample count.
          const r = await sendCmd(session, 'read', { addr: read.addr.toString(16), size: Math.min(read.len, 512) }, 4_000);
          buf = (r && r.ok && r.b64) ? Buffer.from(r.b64, 'base64') : Buffer.alloc(0);
        } catch { buf = Buffer.alloc(0); }
        mem[read.reg] = buf && buf.length ? buf : null;
        if (!mem[read.reg]) unreadable = true;
      }
      s.args = decodeArgs(s.observedNr, s.regs ?? [], mem);
      decodedCount++;
      if (unreadable && !decodeNotes.includes('some pointer arguments could not be read (the address may have been freed or unmapped by the time the digest ran)')) {
        decodeNotes.push('some pointer arguments could not be read (the address may have been freed or unmapped by the time the digest ran)');
      }
    }
    if (samples.length > decodedCount) decodeNotes.push(`argument decoding stopped after ${decodedCount} of ${samples.length} samples (decodeLimit)`);
  } else {
    decodeNotes.push('argument decoding disabled (decode:false): numbers and callers only');
  }

  const result = digestSyscallSamples(samples, { expected, maxGroups: opts.maxGroups });
  result.notes.push(...decodeNotes);
  if (symbolSource === 'unavailable') result.notes.push('symbolization unavailable: caller frames are shown as module+offset only');
  if (symbolSource === 'none') result.notes.push('no caller chain in the events: install the watch through syscall_watch (it sets backtrace:true)');
  return { ...result, window: { sinceMs, limit }, symbolSource };
}
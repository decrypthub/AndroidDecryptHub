// Hook-hit caller backtrace (the native analogue of Thread.backtrace()).
//
// The inline-hook stub already saves x29/x30 at the hit (regs[10]/regs[11]); the NATIVE_HOOK event
// now publishes them. x29 is the frame record of the CALLER (arm64 writes it in the prologue), whose
// [fp] / [fp+8] words are the previous frame pointer and the return address of the next frame up, so
// the host can walk the chain by reading the target stack - no unwinder, no DWARF, no crash risk.
//
// Honesty rules: the walk stops at the first unreadable/invalid record and says so (`truncated`,
// `stopReason`); symbols are "exact" only when the symbol table gives a size that covers the address,
// otherwise the nearest preceding function is named and marked, and a module with no usable symbol
// table reports `symbol: null` rather than inventing a name.
import { captures } from './state.ts';
import { modulesFromMaps, reconstructSo, readMem, sendCmd } from './service.ts';

export interface BacktraceOptions {
  session: string;
  hookId?: number;
  fp?: string | number;
  lr?: string | number;
  maxFrames?: number;
}

export interface DynSymbol { addr: bigint; size: bigint; name: string; kind: 'func' | 'object'; }

function toBigInt(value: string | number | bigint | undefined | null): bigint | null {
  if (value == null) return null;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? BigInt(Math.trunc(value)) : null;
  const t = String(value).trim();
  if (!t) return null;
  try { return BigInt(/^0x/i.test(t) ? t : `0x${t}`); } catch { return null; }
}
export function hex(v: bigint): string { return `0x${v.toString(16)}`; }

// ---- minimal ELF64 dynamic-symbol reader (works on memory reconstructions, where the section
// header table is gone: everything is resolved through PT_DYNAMIC) ------------------------------
const SHT_TYPES: Record<number, 'func' | 'object'> = { 2: 'func', 1: 'object' }; // STT_FUNC / STT_OBJECT

export function parseDynSymbols(buf: Buffer): DynSymbol[] {
  if (buf.length < 64 || buf.readUInt32LE(0) !== 0x464c457f || buf[4] !== 2) return [];
  const phoff = Number(buf.readBigUInt64LE(32));
  const phentsize = buf.readUInt16LE(54);
  const phnum = buf.readUInt16LE(56);
  const loads: { vaddr: bigint; offset: bigint; filesz: bigint }[] = [];
  let dynamic: { vaddr: bigint; offset: bigint; filesz: bigint } | null = null;
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + 56 > buf.length) break;
    const type = buf.readUInt32LE(o);
    const offset = buf.readBigUInt64LE(o + 8);
    const vaddr = buf.readBigUInt64LE(o + 16);
    const filesz = buf.readBigUInt64LE(o + 32);
    if (type === 1) loads.push({ vaddr, offset, filesz });          // PT_LOAD
    else if (type === 2) dynamic = { vaddr, offset, filesz };       // PT_DYNAMIC
  }
  // Reconstructed dumps keep file offsets == virtual addresses, so identity is the fallback.
  const at = (v: bigint): number | null => {
    for (const l of loads) {
      if (v >= l.vaddr && v < l.vaddr + l.filesz) return Number(l.offset + (v - l.vaddr));
    }
    const n = Number(v);
    return n >= 0 && n < buf.length ? n : null;
  };
  const dynOff = dynamic ? at(dynamic.vaddr) ?? Number(dynamic.offset) : null;
  if (dynOff == null || dynOff + 16 > buf.length) return [];
  let symtab: bigint | null = null, strtab: bigint | null = null, strsz = 0n;
  let hash: bigint | null = null, gnuHash: bigint | null = null;
  for (let o = dynOff; o + 16 <= buf.length && o + 16 <= dynOff + Number(dynamic!.filesz); o += 16) {
    const tag = buf.readBigUInt64LE(o);
    const val = buf.readBigUInt64LE(o + 8);
    if (tag === 0n) break;                       // DT_NULL
    if (tag === 6n) symtab = val;                // DT_SYMTAB
    else if (tag === 5n) strtab = val;           // DT_STRTAB
    else if (tag === 10n) strsz = val;           // DT_STRSZ
    else if (tag === 4n) hash = val;             // DT_HASH
    else if (tag === 0x6ffffef5n) gnuHash = val; // DT_GNU_HASH
  }
  if (symtab == null || strtab == null) return [];
  const symOff = at(symtab);
  const strOff = at(strtab);
  if (symOff == null || strOff == null) return [];

  // Symbol count: DT_HASH.nchain, else the GNU-hash chain walk, else the gap to DT_STRTAB (the
  // layout every linker produces), always bounded by the buffer.
  let count = 0;
  const hashOff = hash == null ? null : at(hash);
  if (hashOff != null && hashOff + 8 <= buf.length) count = buf.readUInt32LE(hashOff + 4);
  if (!count || count > 200000) {
    const ghOff = gnuHash == null ? null : at(gnuHash);
    if (ghOff != null && ghOff + 16 <= buf.length) {
      const nbuckets = buf.readUInt32LE(ghOff);
      const symoffset = buf.readUInt32LE(ghOff + 4);
      const bloomSize = buf.readUInt32LE(ghOff + 8);
      const bucketsOff = ghOff + 16 + bloomSize * 8;
      const chainsOff = bucketsOff + nbuckets * 4;
      let maxIdx = 0;
      if (nbuckets > 0 && bucketsOff + nbuckets * 4 <= buf.length) {
        for (let b = 0; b < nbuckets; b++) {
          let idx = buf.readUInt32LE(bucketsOff + b * 4);
          if (idx === 0) continue;
          if (idx < symoffset) { idx = symoffset; }
          let chainOff = chainsOff + (idx - symoffset) * 4;
          for (let guard = 0; guard < 200000 && chainOff + 4 <= buf.length; guard++, idx++, chainOff += 4) {
            if (idx > maxIdx) maxIdx = idx;
            const w = buf.readUInt32LE(chainOff);
            if (w & 1) break;
          }
        }
      }
      count = maxIdx + 1;
    }
  }
  if (!count || count > 200000) {
    const gap = strOff > symOff ? Math.floor((strOff - symOff) / 24) : 0;
    count = Math.max(0, Math.min(gap, 200000));
  }
  if (!count) return [];
  const maxByBuf = Math.floor((buf.length - symOff) / 24);
  count = Math.min(count, maxByBuf);
  const strEnd = strsz > 0n ? Math.min(buf.length, strOff + Number(strsz)) : buf.length;
  const syms: DynSymbol[] = [];
  for (let i = 0; i < count; i++) {
    const o = symOff + i * 24;
    const nameOff = buf.readUInt32LE(o);
    const info = buf[o + 4];
    const shndx = buf.readUInt16LE(o + 6);
    const value = buf.readBigUInt64LE(o + 8);
    const size = buf.readBigUInt64LE(o + 16);
    if (!nameOff || shndx === 0 || value === 0n) continue;            // undefined / empty name
    const at2 = strOff + nameOff;
    if (at2 < strOff || at2 >= strEnd) continue;
    let end = at2;
    while (end < strEnd && buf[end] !== 0) end++;
    if (end === at2) continue;
    const type = info & 0xf;
    const kind = SHT_TYPES[type];
    if (!kind) continue;
    syms.push({ addr: value, size, name: buf.toString('utf8', at2, Math.min(end, at2 + 200)), kind });
  }
  syms.sort((a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0));
  return syms;
}

export interface SymbolHit { symbol: string | null; exact: boolean; symbolOffset: string | null; symbolSize: string | null; }

export function symbolize(offset: bigint, symbols: DynSymbol[]): SymbolHit {
  const miss: SymbolHit = { symbol: null, exact: false, symbolOffset: null, symbolSize: null };
  if (!symbols.length) return miss;
  let lo = 0, hi = symbols.length - 1, best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (symbols[mid].addr <= offset) { best = mid; lo = mid + 1; } else hi = mid - 1;
  }
  if (best < 0) return miss;
  const s = symbols[best];
  const delta = offset - s.addr;
  const exact = s.size > 0n && delta < s.size;
  // "exact" here means the symbol's declared size COVERS this offset (the strongest statement a
  // dynamic symbol table supports); outside that range the nearest preceding function is returned
  // and flagged inexact.
  return { symbol: s.name, exact, symbolOffset: hex(delta), symbolSize: s.size > 0n ? hex(s.size) : null };
}

interface FrameInfo {
  index: number; pc: string; module: string | null; moduleOffset: string | null; symbol: string | null;
  symbolExact: boolean; symbolOffset: string | null;
}

export async function nativeBacktrace(opts: BacktraceOptions): Promise<any> {
  const maxFrames = Math.max(1, Math.min(32, Math.trunc(Number(opts.maxFrames ?? 12))));
  let pcs: bigint[] | null = null;      // at-hit chain from the event (preferred)
  let fp = toBigInt(opts.fp);
  let lr = toBigInt(opts.lr);
  let source = 'explicit-fp-lr';
  let atHitCount: number | null = null;
  let atHitTruncated = false;

  if (fp == null && lr == null) {
    if (opts.hookId == null) throw new Error('need hookId (uses the newest event of that hook) or explicit fp/lr');
    // Newest NATIVE_HOOK capture for this hook: the event text is stored hex-encoded.
    let hit: any = null;
    for (let i = captures.length - 1; i >= 0 && !hit; i--) {
      const c: any = captures[i];
      if (c.sessionId !== opts.session || c.func !== 'NATIVE_HOOK') continue;
      let text = '';
      try { text = Buffer.from(String(c.hex ?? ''), 'hex').toString('utf8'); } catch { text = ''; }
      if (!text || !text.includes(`"hookId":${Number(opts.hookId)}`)) continue;
      try { hit = JSON.parse(text); } catch { hit = null; }
    }
    if (!hit) throw new Error(`no NATIVE_HOOK event for hookId=${opts.hookId} in this session (trigger the hook first)`);
    if (Array.isArray(hit.bt) && hit.bt.length) {
      // Captured by the agent AT THE HIT (x30 + the x29 chain). Reading the stack later would read
      // memory the process has long since reused, so this is the only trustworthy chain.
      // Every entry is a RETURN ADDRESS (x30 at the hit, then [fp+8] up the chain): step back one
      // instruction so the symbol lookup lands inside the calling function instead of the next one.
      const parsed = hit.bt
        .map((v: any) => toBigInt(v))
        .filter((v: bigint | null): v is bigint => v != null && v !== 0n)
        .map((v) => (v > 4n ? v - 4n : v));
      if (!parsed.length) throw new Error('the event carried an empty caller chain (agent backtrace capture failed)');
      pcs = parsed.slice(0, maxFrames);
      atHitCount = Number(hit.btCount ?? parsed.length);
      atHitTruncated = hit.btTruncated === true || /true/i.test(String(hit.btTruncated ?? ''));
      source = `hook-hit(at-hit, hookId=${Number(opts.hookId)})`;
    } else if (hit.x29 !== undefined && hit.x30 !== undefined) {
      fp = toBigInt(hit.x29);
      lr = toBigInt(hit.x30);
      source = `hook-hit(live-walk, hookId=${Number(opts.hookId)})`;
    } else {
      throw new Error('the event has no caller chain: install the hook with backtrace:true (or redeploy an agent that captures x29/x30)');
    }
  }

  const maps = await sendCmd(opts.session, 'maps');
  if (!maps?.ok) throw new Error(maps?.error ?? 'maps command failed');
  const regions = (maps.regions ?? []) as any[];
  const modules = modulesFromMaps(regions);
  const inRegion = (addr: bigint) => regions.find((r) => addr >= BigInt(`0x${r.start}`) && addr < BigInt(`0x${r.end}`));
  // Resolve the module by the region that CONTAINS the address: several paths (base.apk, anon
  // ranges, driver nodes) have scattered mappings whose naive [min,max) span swallows the whole
  // address space - min/max matching attributed sandbox frames to base.apk. Fall back to the
  // smallest containing span for the rare case where the region has no path.
  const moduleOf = (addr: bigint) => {
    const region = inRegion(addr);
    if (region?.path) {
      const exact = modules.find((m) => m.path === region.path);
      if (exact) return exact;
    }
    let best: any = null, bestSpan = 0n;
    for (const m of modules) {
      const base = BigInt(`0x${m.base}`), end = BigInt(`0x${m.end}`);
      if (addr < base || addr >= end) continue;
      const span = end - base;
      if (!best || span < bestSpan) { best = m; bestSpan = span; }
    }
    return best;
  };
  const fromArchive = (path: string) => /\.(apk|jar|zip|apex)$/i.test(path);

  let symbolSource = 'dynsym';
  const symbolCache = new Map<string, DynSymbol[]>();
  const symbolsFor = async (mod: any): Promise<DynSymbol[]> => {
    // A library mapped straight out of an APK has no standalone ELF image in memory to reconstruct
    // (the mapping is a slice of the archive), so symbolization is skipped - loudly, not silently.
    if (fromArchive(String(mod.path ?? ''))) { symbolSource = 'archive-mapped'; return []; }
    const key = `${opts.session}:${mod.base}`;
    if (!symbolCache.has(key)) {
      try {
        const buf = await reconstructSo(opts.session, String(mod.base));
        symbolCache.set(key, parseDynSymbols(buf));
      } catch { symbolCache.set(key, []); }
    }
    return symbolCache.get(key)!;
  };

  const frames: FrameInfo[] = [];
  const describe = async (pc: bigint, index: number): Promise<FrameInfo> => {
    const mod = moduleOf(pc);
    if (!mod) {
      return { index, pc: hex(pc), module: null, moduleOffset: null, symbol: null, symbolExact: false, symbolOffset: null };
    }
    const base = BigInt(`0x${mod.base}`);
    const offset = pc - base;
    const hit = symbolize(offset, await symbolsFor(mod));
    return {
      index, pc: hex(pc), module: mod.name, moduleOffset: hex(offset),
      symbol: hit.symbol, symbolExact: hit.exact, symbolOffset: hit.symbolOffset,
    };
  };

  let stopReason: string | null = null;
  let truncated = false;
  if (pcs) {
    for (const pc of pcs) {
      // The agent walks the frame records without the maps, so a corrupt chain can end in a value
      // that is not mapped at all. Stop there instead of listing garbage as if it were a frame.
      if (!inRegion(pc)) { stopReason = 'return-address-not-mapped'; truncated = true; break; }
      frames.push(await describe(pc, frames.length));
    }
    if (atHitCount != null && atHitCount > pcs.length) truncated = true;
    if (atHitTruncated) {
      truncated = true;
      stopReason = stopReason ?? 'frame-cap-reached';
    }
  } else {
    if (lr == null || lr === 0n) throw new Error('no return address (x30) captured for this hit');
    // Live walk (explicit fp/lr): best effort - the stack may already have been reused.
    frames.push(await describe(lr, 0));
    stopReason = fp == null || fp === 0n ? 'no-frame-pointer' : null;
    let cur = fp;
    const visited = new Set<string>();
    while (!stopReason && frames.length < maxFrames && cur != null && cur !== 0n) {
      const key = hex(cur);
      if (visited.has(key)) { stopReason = 'frame-pointer-loop'; break; }
      visited.add(key);
      const region = inRegion(cur);
      if (!region || !String(region.perms ?? '').includes('w')) { stopReason = 'frame-pointer-outside-stack'; break; }
      const mem = await readMem(opts.session, cur, 16);
      if (mem.length < 16) { stopReason = 'stack-unreadable'; break; }
      const nextFp = mem.readBigUInt64LE(0);
      const ret = mem.readBigUInt64LE(8);
      if (ret === 0n) { stopReason = 'zero-return-address'; break; }
      // The stored return address points AFTER the bl: step back one instruction so the symbol lookup
      // lands inside the calling function instead of the next one.
      frames.push(await describe(ret - 4n > 0n ? ret - 4n : ret, frames.length));
      if (nextFp <= cur) { stopReason = 'frame-pointer-not-ascending'; break; }
      cur = nextFp;
      if (frames.length >= maxFrames) truncated = true;
    }
  }

  return {
    source,
    symbolSource,
    fp: fp == null ? null : hex(fp),
    lr: lr == null ? null : hex(lr),
    frameCount: frames.length,
    frames,
    truncated,
    stopReason,
    trusted: frames.length >= 2,
    note: frames.length >= 2
      ? (pcs
        ? 'frames[0] is the immediate caller; the chain was captured at the hook hit (no later stack read). Return addresses are adjusted by -4 so a frame resolved at a function boundary still lands in the caller.'
        : 'frames[0] is the immediate caller (from x30); the rest come from a live x29 walk - prefer backtrace:true for an at-hit chain.')
      : 'only the immediate caller is known: no usable frame-pointer chain at the hit (leaf callers, -fomit-frame-pointer builds, or the agent stopped early - see stopReason).',
  };
}

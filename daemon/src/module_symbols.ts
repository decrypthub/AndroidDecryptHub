// Shared "address -> module + symbol" resolution for the host-side analysis tools.
//
// Extracted from backtrace.ts when the trace digest needed the same answers: which module contains
// this address, what is its file offset, and which dynamic symbol covers it. Everything works on
// memory reconstructions (PT_DYNAMIC only - the section header table is gone after a dump), and a
// library mapped straight out of an APK is reported as archive-mapped instead of being guessed at.
import { modulesFromMaps, reconstructSo, sendCmd } from './service.ts';
import { parseDynSymbols, symbolize, type DynSymbol } from './backtrace.ts';

export interface Region { start: string; end: string; perms?: string; offset?: string; path?: string; [k: string]: unknown }
export interface ModuleInfo { name: string; path: string; base: string; end: string; size: number; segs: number }

export interface ModuleTable {
  regions: Region[];
  modules: ModuleInfo[];
  inRegion: (addr: bigint) => Region | undefined;
  moduleOf: (addr: bigint) => ModuleInfo | null;
}

export function hex(v: bigint): string { return `0x${v.toString(16)}`; }

export function parseHex(value: string | number | bigint | undefined | null): bigint | null {
  if (value == null) return null;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? BigInt(Math.trunc(value)) : null;
  const t = String(value).trim();
  if (!t) return null;
  try { return BigInt(/^0x/i.test(t) ? t : `0x${t}`); } catch { return null; }
}

export const fromArchive = (path: string) => /\.(apk|jar|zip|apex)$/i.test(path);

export async function loadModuleTable(session: string): Promise<ModuleTable> {
  const maps = await sendCmd(session, 'maps');
  if (!maps?.ok) throw new Error(maps?.error ?? 'maps command failed');
  const regions = (maps.regions ?? []) as Region[];
  const modules = modulesFromMaps(regions as any) as ModuleInfo[];
  const inRegion = (addr: bigint) =>
    regions.find((r) => addr >= BigInt(`0x${r.start}`) && addr < BigInt(`0x${r.end}`));
  // Resolve by the region that CONTAINS the address: several paths (base.apk, anon ranges, driver
  // nodes) have scattered mappings whose naive [min,max) span swallows the whole address space.
  // Fall back to the smallest containing span when the region has no path.
  const moduleOf = (addr: bigint): ModuleInfo | null => {
    const region = inRegion(addr);
    if (region?.path) {
      const exact = modules.find((m) => m.path === region.path);
      if (exact) return exact;
      // The region HAS a path but the module table does not know it (memfd JIT caches, anonymous
      // mappings, a library mapped from an archive). Do NOT fall back to a min/max span match here:
      // base.apk's mappings span gigabytes and would swallow the frame, attributing it to a module it
      // was never in. "no module" is the honest answer; callers keep the raw address.
      return null;
    }
    // No path at all: only accept a module whose OWN base is this region's start.
    for (const m of modules) {
      const base = BigInt(`0x${m.base}`), end = BigInt(`0x${m.end}`);
      if (addr >= base && addr < end && BigInt(`0x${region.start}`) === base) return m;
    }
    return null;
  };
  return { regions, modules, inRegion, moduleOf };
}

export interface SymbolizedAddress {
  address: string;
  module: string | null;
  moduleOffset: string | null;
  symbol: string | null;
  symbolExact: boolean;
}

/** Symbolize many addresses with ONE maps snapshot and one dump per module. */
export async function symbolizeAddresses(session: string, addrs: bigint[], table?: ModuleTable): Promise<Map<string, SymbolizedAddress>> {
  const t = table ?? await loadModuleTable(session);
  const out = new Map<string, SymbolizedAddress>();
  const cache = new Map<string, DynSymbol[]>();
  let symbolSource = 'dynsym';
  let dumpFailures = 0;
  for (const addr of addrs) {
    const key = hex(addr);
    if (out.has(key)) continue;
    const mod = t.moduleOf(addr);
    if (!mod) {
      out.set(key, { address: key, module: null, moduleOffset: null, symbol: null, symbolExact: false });
      continue;
    }
    const base = BigInt(`0x${mod.base}`);
    const offset = addr - base;
    let syms: DynSymbol[] = [];
    if (fromArchive(String(mod.path ?? ''))) {
      symbolSource = 'archive-mapped';
    } else {
      const cacheKey = `${session}:${mod.base}`;
      if (!cache.has(cacheKey)) {
        try {
          const buf = await reconstructSo(session, String(mod.base));
          const parsed = parseDynSymbols(buf);
          if (!parsed.length) dumpFailures++;
          cache.set(cacheKey, parsed);
        } catch { dumpFailures++; cache.set(cacheKey, []); }
      }
      syms = cache.get(cacheKey)!;
    }
    const hit = symbolize(offset, syms);
    out.set(key, {
      address: key, module: mod.name, moduleOffset: hex(offset),
      symbol: hit.symbol, symbolExact: hit.exact,
    });
  }
  // Say when some modules could not be symbolized instead of claiming a clean dynsym run.
  if (dumpFailures) symbolSource = symbolSource === 'dynsym' ? 'partial' : symbolSource;
  (out as any).symbolSource = symbolSource;
  return out;
}
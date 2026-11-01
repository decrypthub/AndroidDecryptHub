// Shared "address -> module + symbol" resolution for the host-side analysis tools.
//
// Extracted from backtrace.ts when the trace digest needed the same answers: which module contains
// this address, what is its file offset, and which dynamic symbol covers it. Everything works on
// memory reconstructions (PT_DYNAMIC only - the section header table is gone after a dump), and a
// library mapped straight out of an APK is reported as archive-mapped instead of being guessed at.
//
// It also owns the other direction - module -> its whole dynamic symbol table - because that is the
// same dump, the same parser and the same honesty rule (`native_symbols`, see moduleSymbols below).
import { modulesFromMaps, reconstructSo, sendCmd } from './service.ts';
import { parseDynSymbols, symbolize, type DynSymbol } from './backtrace.ts';
import { finiteNumber } from './num.ts';

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

// ---- module -> its dynamic symbol table (the `native_symbols` tool) ------------------------------
//
// `symbolizeAddresses` answers "what symbol is at this address"; this answers "list what this library
// exports". Same three inputs (maps, module dump, PT_DYNAMIC walk) and the same refusal to invent a
// name, but the reply is a PAGE: a stripped 2 MB library still has hundreds of dynsym entries and
// handing the whole table to an AI costs more context than the answer is worth. A library mapped
// straight out of an APK has no standalone ELF image to reconstruct, so it reports
// symbolSource='archive-mapped' with zero symbols rather than guessing from the archive bytes.

/** `kind` filter values. `any` is the default; `object` is data (STT_OBJECT). */
export const SYMBOL_KINDS = ['any', 'func', 'object'] as const;
export type SymbolKindFilter = typeof SYMBOL_KINDS[number];

export interface ModuleSymbolsOptions {
  /** Module to read: a name (`libfoo.so`), a full path, or any unambiguous substring of either. */
  module: string;
  /** Only symbols of this kind. Default `any` (both func and object). */
  kind?: string;
  /** Only symbols whose NAME contains this substring (case-sensitive, matching `selectExportSymbols`). */
  contains?: string;
  /** Page size, 1..5000. Default 200. */
  limit?: number;
  /** Index of the first symbol of the page (feed back nextOffset). Default 0. */
  offset?: number;
}

export interface ModuleSymbolRow {
  /** Symbol name as it appears in .dynstr. */
  name: string;
  /** Module-relative offset (`st_value`, hex). Runtime address = module base + this. */
  offset: string;
  /** Declared `st_size` (hex) or null when the table gives 0. */
  size: string | null;
  sizeBytes: number;
  kind: 'func' | 'object';
}

export interface ModuleSymbolsResult {
  module: string;
  path: string;
  base: string;
  /** `dynsym` when the table was read from a memory reconstruction; `archive-mapped` when not. */
  symbolSource: 'dynsym' | 'archive-mapped';
  /** Symbols matching the filters (NOT the module's total, and not the page size). */
  total: number;
  /** Rows in this page. */
  returned: number;
  /** Offset to pass back to get the next page, or null at the end. */
  nextOffset: number | null;
  offset: number;
  limit: number;
  /** Every symbol in the module before the filters, and the func/object split of that set. */
  symbolsInModule: number;
  counts: { func: number; object: number };
  kind: SymbolKindFilter;
  contains: string | null;
  symbols: ModuleSymbolRow[];
  notes: string[];
}

/** Pure filter + page over an already-parsed dynamic symbol table. No I/O, no state. */
export function pageModuleSymbols(
  symbols: DynSymbol[],
  opts: { kind?: string; contains?: string; limit?: number; offset?: number } = {},
): { symbols: ModuleSymbolRow[]; total: number; returned: number; nextOffset: number | null; offset: number; limit: number; kind: SymbolKindFilter; contains: string | null; symbolsInModule: number; counts: { func: number; object: number } } {
  const kind = (SYMBOL_KINDS as readonly string[]).includes(String(opts.kind)) ? String(opts.kind) as SymbolKindFilter : 'any';
  const contains = typeof opts.contains === 'string' && opts.contains.length ? opts.contains : null;
  // Page bounds are clamped rather than trusted: the MCP layer does not schema-validate, and an
  // unclamped limit of 10^9 is the unpaged dump this tool exists to avoid.
  const limit = Math.max(1, Math.min(5000, Math.floor(finiteNumber(opts.limit, 200, 1, 5000))));
  const offset = Math.max(0, Math.floor(finiteNumber(opts.offset, 0, 0, Number.MAX_SAFE_INTEGER)));
  const list = Array.isArray(symbols) ? symbols.filter((s) => s && s.name) : [];
  const counts = {
    func: list.filter((s) => s.kind === 'func').length,
    object: list.filter((s) => s.kind === 'object').length,
  };
  const matches = list.filter((s) => (kind === 'any' || s.kind === kind) && (!contains || s.name.includes(contains)));
  // Address order is the order parseDynSymbols already sorted by; keep it so two runs page identically.
  const page = matches.slice(offset, offset + limit).map((s) => ({
    name: s.name,
    offset: hex(s.addr),
    size: s.size > 0n ? hex(s.size) : null,
    sizeBytes: Number(s.size),
    kind: s.kind,
  }));
  const nextOffset = offset + page.length < matches.length ? offset + page.length : null;
  return { symbols: page, total: matches.length, returned: page.length, nextOffset, offset, limit, kind, contains, symbolsInModule: list.length, counts };
}

/**
 * Read one loaded module's dynamic symbol table from the target process.
 *
 * The module is resolved against the live maps, dumped through `reconstructSo` and parsed with
 * `parseDynSymbols` - the same path `native_hook_all` uses to resolve exports, so a symbol this tool
 * lists is a symbol that tool can hook. An archive-mapped library short-circuits BEFORE the dump:
 * the mapping is a slice of a zip, `reconstructSo` would read garbage, and reporting no symbols with
 * the reason is the only honest answer.
 *
 * `deps` is injectable for the same reason `installSymbolHooks` takes a sender: the interesting
 * branches (the archive short-circuit, an empty dynsym, an ambiguous selector) are decided by inputs a
 * live device cannot be made to produce on demand, so a unit test that could only grep this function
 * would leave them unverified. Production passes nothing.
 */
export async function moduleSymbols(
  session: string,
  opts: ModuleSymbolsOptions,
  deps: { loadModuleTable: typeof loadModuleTable; reconstructSo: typeof reconstructSo; parseDynSymbols: typeof parseDynSymbols } = { loadModuleTable, reconstructSo, parseDynSymbols },
): Promise<ModuleSymbolsResult> {
  const wanted = String(opts.module ?? '').trim();
  if (!wanted) throw new Error('need module (a name like libfoo.so, a path, or an unambiguous substring)');
  const table = await deps.loadModuleTable(session);
  const mod = resolveModule(table.modules, wanted);
  if (!mod) throw new Error(`module not found in this process: ${wanted} (use memory_maps or maps to list loaded libraries)`);
  const notes: string[] = [];
  const archived = fromArchive(String(mod.path ?? ''));
  // An archive-mapped library short-circuits BEFORE the dump: reconstructSo would read a slice of a
  // zip as if it were ELF program headers.
  const symbols = archived ? [] : deps.parseDynSymbols(await deps.reconstructSo(session, String(mod.base)));
  const symbolSource: ModuleSymbolsResult['symbolSource'] = archived ? 'archive-mapped' : 'dynsym';
  if (symbolSource === 'archive-mapped') {
    notes.push(`${mod.name} is mapped directly out of an archive (${String(mod.path).replace(/^.*\//, '')}), so it has no standalone ELF image in memory: no symbol table is claimed. Unpack the archive first, or hook the module and read native_backtrace frames instead.`);
  } else if (!symbols.length) {
    notes.push(`the dynamic symbol table of ${mod.name} parsed as empty: the library is stripped, or the memory dump lost PT_DYNAMIC (retry once before concluding).`);
  }
  const page = pageModuleSymbols(symbols, opts);
  if (page.nextOffset != null) {
    notes.push(`${page.returned} of ${page.total} matching symbols - pass offset:${page.nextOffset} for the next page.`);
  }
  if (page.total === 0 && symbolSource === 'dynsym' && symbols.length) {
    notes.push(`0 of ${symbols.length} symbols matched kind=${page.kind}${page.contains ? ` contains="${page.contains}"` : ''}; drop a filter to see the table.`);
  }
  return {
    module: mod.name,
    path: String(mod.path ?? ''),
    base: `0x${String(mod.base).replace(/^0x/, '')}`,
    symbolSource,
    total: page.total,
    returned: page.returned,
    nextOffset: page.nextOffset,
    offset: page.offset,
    limit: page.limit,
    symbolsInModule: page.symbolsInModule,
    counts: page.counts,
    kind: page.kind,
    contains: page.contains,
    symbols: page.symbols,
    notes,
  };
}

/**
 * Resolve a caller-supplied module selector against the live module table.
 *
 * Order matters: exact name, exact path, `libfoo.so` for any path ending in it, then a substring of
 * name or path. The first two are unambiguous by construction; the last two are how an operator names
 * a library it only half-remembers. An ambiguous substring is NOT silently resolved to the first hit -
 * the error lists the candidates, because hooking/parsing the wrong library is a wrong answer that
 * looks like a right one.
 */
export function resolveModule<T extends { name: string; path: string }>(modules: T[], selector: string): T | null {
  const want = String(selector ?? '').trim();
  if (!want || !Array.isArray(modules) || !modules.length) return null;
  const exactName = modules.filter((m) => m.name === want);
  if (exactName.length === 1) return exactName[0];
  const exactPath = modules.filter((m) => String(m.path ?? '') === want);
  if (exactPath.length === 1) return exactPath[0];
  const tail = modules.filter((m) => String(m.path ?? '').endsWith(`/${want}`));
  if (tail.length === 1) return tail[0];
  const loose = modules.filter((m) => m.name.includes(want) || String(m.path ?? '').includes(want));
  if (loose.length === 1) return loose[0];
  if (loose.length > 1) {
    const names = loose.slice(0, 6).map((m) => m.name).join(', ');
    throw new Error(`module selector "${want}" is ambiguous (${loose.length} matches: ${names}${loose.length > 6 ? ', ...' : ''}) - pass the full path`);
  }
  return null;
}
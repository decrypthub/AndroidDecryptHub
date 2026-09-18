// Batch native hooking by exported-symbol pattern: "hook every EVP_* in libcrypto" without typing
// addresses by hand. Host-side orchestration only - the agent still just executes native_hook.
//
// The symbol list comes from the module dump (module_symbols keeps working on memory
// reconstructions), the runtime address is base + st_value, and the install loop is bounded by the
// agent's 16 concurrent native slots, reporting matched vs installed so truncation is visible.
import { sendCmd } from './service.ts';
import { nativeHookInstallPayload, normalizeThrottleMs } from './native_hook_args.ts';
import { loadModuleTable, parseHex, hex } from './module_symbols.ts';
import { parseDynSymbols, type DynSymbol } from './backtrace.ts';
import { reconstructSo } from './service.ts';

export interface SymbolChoice { name: string; address: string; offset: string; size: number }

/**
 * How many hooks the agent can ACTUALLY take right now: min(requested, free slots it reports).
 * Without this the 17th install just fails symbol by symbol; with it the batch is truncated to what
 * fits and says why. freeSlots=null means an older payload that does not report a budget.
 */
export function effectiveBatchLimit(requested: number, freeSlots: number | null): { limit: number; reason: string; blocked: boolean } {
  const want = Math.max(1, Math.min(16, Math.trunc(Number(requested) || 8)));
  if (freeSlots == null || !Number.isFinite(Number(freeSlots))) {
    return { limit: want, reason: `the agent did not report a slot budget (older payload): assuming the requested ${want}`, blocked: false };
  }
  const raw = Math.trunc(Number(freeSlots));
  if (raw < 0) {
    // A negative budget is a corrupt/overflowed report: saying "0 free" would put words in the
    // agent mouth, so refuse and say what was actually received.
    return { limit: 0, reason: `the agent reported a corrupt slot budget (free=${raw})`, blocked: true };
  }
  const free = raw;
  if (free === 0) return { limit: 0, reason: 'the agent reports 0 free hook slots: unhook something first', blocked: true };
  if (free < want) return { limit: free, reason: `only ${free} of the requested ${want} hooks fit (agent reports ${free} free slot(s))`, blocked: false };
  return { limit: want, reason: `${free} slot(s) free, installing up to ${want}`, blocked: false };
}

export interface InstalledHook { hookId: number; symbol: string; address: string }
export interface HookFailure { symbol: string; error: string }

/**
 * Install one inline hook per selected symbol, in address order, reporting per-symbol progress (one
 * failure never aborts the batch). The sender is injectable so the payload that actually reaches the
 * agent - throttleMs, backtrace and the rest - is covered by a unit test instead of by grepping for
 * the call: dropping a field here is exactly the bug a pure-function test cannot see.
 */
export async function installSymbolHooks(
  session: string,
  base: bigint,
  selected: SymbolChoice[],
  opts: { throttleMs?: number; backtrace?: boolean; skipOriginal?: boolean; returnValue?: string; argIndex?: number; argValue?: string },
  send: typeof sendCmd = sendCmd,
): Promise<{ hooks: InstalledHook[]; failures: HookFailure[] }> {
  const hooks: InstalledHook[] = [];
  const failures: HookFailure[] = [];
  for (const sym of selected) {
    const off = parseHex(sym.address);
    if (off == null) { failures.push({ symbol: sym.name, error: 'bad offset' }); continue; }
    const runtime = base + off;
    const r = await send(session, 'native_hook', nativeHookInstallPayload({
      addr: hex(runtime), throttleMs: opts.throttleMs, backtrace: opts.backtrace,
      skipOriginal: opts.skipOriginal, returnValue: opts.returnValue,
      argIndex: opts.argIndex, argValue: opts.argValue,
    }), 20_000).catch((e) => ({ ok: false, error: (e as Error).message }));
    if (r?.ok && Number(r.hookId) > 0) hooks.push({ hookId: Number(r.hookId), symbol: sym.name, address: hex(runtime) });
    else failures.push({ symbol: sym.name, error: String(r?.error ?? 'install failed') });
  }
  return { hooks, failures };
}

export interface SelectOptions {
  prefix?: string;
  contains?: string;
  exact?: string;
  limit?: number;
  /** Symbols whose name contains any of these are skipped (e.g. "_init", "deregister"). */
  exclude?: string[];
}

/** Pure selection over an already-parsed export table. */
export function selectExportSymbols(symbols: DynSymbol[], opts: SelectOptions): { selected: SymbolChoice[]; matched: number } {
  const limit = Math.max(1, Math.min(16, Math.trunc(Number(opts.limit ?? 8))));
  const exclude = (opts.exclude ?? []).filter((e) => e && e.length);
  const matches = symbols.filter((s) => {
    if (s.kind !== 'func' || !s.name) return false;
    if (opts.exact && s.name !== opts.exact) return false;
    if (opts.prefix && !s.name.startsWith(opts.prefix)) return false;
    if (opts.contains && !s.name.includes(opts.contains)) return false;
    if (!opts.exact && !opts.prefix && !opts.contains) return true;   // no filter = every exported function
    for (const e of exclude) if (s.name.includes(e)) return false;
    return true;
  });
  // Deterministic order: address ascending, so two runs pick the same subset.
  matches.sort((a, b) => (a.addr < b.addr ? -1 : a.addr > b.addr ? 1 : 0));
  const selected = matches.slice(0, limit).map((s) => ({
    name: s.name,
    address: hex(s.addr),          // module-relative; the caller adds the load base
    offset: hex(s.addr),
    size: Number(s.size),
  }));
  return { selected, matched: matches.length };
}

export interface NativeHookAllResult {
  module: string;
  base: string;
  symbolsInModule: number;
  matched: number;
  installedCount: number;
  /** Effective per-hook event throttle (0 = every hit emits). */
  throttleMs: number;
  /**
   * Slot budget the agent reported before the batch (null = older payload that does not report it).
   * used = CONSUMED slots (a soft-unhooked inline hook keeps its slot until a hard unhook), active =
   * hooks currently installed.
   */
  slots: { max: number; used: number; active?: number; free: number; byMode?: Record<string, number> } | null;
  /** Why the batch was (or was not) truncated - the agent slot budget, not a guess. */
  limitReason: string;
  /** The limit that was actually used, next to what the caller asked for. */
  effectiveLimit: number;
  requestedLimit: number;
  slotLimited: boolean;
  hooks: { hookId: number; symbol: string; address: string }[];
  failures: { symbol: string; error: string }[];
  note: string;
}

export async function nativeHookAll(session: string, opts: {
  module: string;
  prefix?: string;
  contains?: string;
  exact?: string;
  limit?: number;
  exclude?: string[];
  backtrace?: boolean;
  /** 0 = every hit emits; >0 = at most one event per hook per window (hot symbols). */
  throttleMs?: number;
  skipOriginal?: boolean;
  returnValue?: string;
  argIndex?: number;
  argValue?: string;
}): Promise<NativeHookAllResult> {
  if (!opts.module) throw new Error('need module');
  const table = await loadModuleTable(session);
  const mod = table.modules.find((m) => m.name === opts.module || m.path === opts.module)
    ?? table.modules.find((m) => String(m.path ?? '').endsWith(`/${opts.module}`))
    ?? table.modules.find((m) => String(m.path ?? '').includes(opts.module));
  if (!mod) throw new Error(`module not found: ${opts.module}`);
  const buf = await reconstructSo(session, String(mod.base));
  const symbols = parseDynSymbols(buf);
  if (!symbols.length) throw new Error(`no dynamic symbols could be read from ${mod.name} (dump failed or the module is stripped)`);
  // Ask the agent for its slot budget first: a batch that does not fit should be truncated with a
  // reason, not rejected symbol by symbol.
  const status = await sendCmd(session, 'native_hook', { action: 'status' }, 15_000).catch(() => null);
  const slotsRaw = status?.status?.slots ?? null;
  const freeSlots = slotsRaw && Number.isFinite(Number(slotsRaw.free)) ? Number(slotsRaw.free) : null;
  const budget = effectiveBatchLimit(opts.limit ?? 8, freeSlots);
  if (budget.blocked) throw new Error(`native_hook_all: ${budget.reason}`);
  const { selected, matched } = selectExportSymbols(symbols, { ...opts, limit: budget.limit });
  if (!matched) throw new Error(`no exported function in ${mod.name} matched the filter (prefix/contains/exact)`);

  const base = parseHex(mod.base);
  if (base == null) throw new Error('module base is not a valid address');
  const { hooks, failures } = await installSymbolHooks(session, base, selected, opts);
  const throttleMs = normalizeThrottleMs(opts.throttleMs);
  return {
    module: mod.name,
    base: mod.base,
    symbolsInModule: symbols.filter((s) => s.kind === 'func').length,
    matched,
    installedCount: hooks.length,
    throttleMs,
    slots: slotsRaw && Number.isFinite(Number(slotsRaw.max))
      ? {
          max: Number(slotsRaw.max), used: Number(slotsRaw.used), free: Number(slotsRaw.free),
          ...(Number.isFinite(Number(slotsRaw.active)) ? { active: Number(slotsRaw.active) } : {}),
          ...(slotsRaw.byMode ? { byMode: slotsRaw.byMode } : {}),
        }
      : null,
    limitReason: budget.reason,
    effectiveLimit: budget.limit,
    requestedLimit: Math.max(1, Math.min(16, Math.trunc(Number(opts.limit ?? 8) || 8))),
    slotLimited: matched > selected.length,
    hooks,
    failures,
    note: `filter=${opts.exact ? `exact:${opts.exact}` : opts.prefix ? `prefix:${opts.prefix}` : opts.contains ? `contains:${opts.contains}` : 'any'} limit=${selected.length === matched ? 'not reached' : `truncated to ${selected.length}`}; unhook with native_hook unhook per hookId`
      + (throttleMs ? `; each hook emits at most one event per ${throttleMs} ms (status reports hits vs throttled)` : '')
      + `; ${budget.reason}`,
  };
}

export async function nativeUnhookAll(session: string, hookIds: number[]): Promise<{ unhooked: number[]; failures: { hookId: number; error: string }[] }> {
  const ids = (hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n));
  if (!ids.length) throw new Error('need hookIds');
  const unhooked: number[] = [];
  const failures: { hookId: number; error: string }[] = [];
  for (const id of ids) {
    try {
      const r = await sendCmd(session, 'native_hook', { action: 'unhook', hookId: id }, 20_000);
      if (r?.ok) unhooked.push(id); else failures.push({ hookId: id, error: String(r?.error ?? 'unhook failed') });
    } catch (e) { failures.push({ hookId: id, error: (e as Error).message }); }
  }
  return { unhooked, failures };
}
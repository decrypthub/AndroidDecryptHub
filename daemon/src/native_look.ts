// One native observation, as a single answer.
//
// native_hook, NATIVE_HOOK and NATIVE_HOOK_MEM stay the parts. This module is the front door:
// stand at a function, then read back one result a person can read. The join is pure so a test
// can prove "two records become one line" without a device.
import { captures as stateCaptures } from './state.ts';
import { agentCmd, pickSid } from './service.ts';
import { drainSession as serviceDrainSession } from './service.ts';
import { memCapturePreview, nativeTracePayload, parseMemWindows } from './native_hook_args.ts';

export interface LookRecord {
  func: string;
  hex: string;
  ts?: number;
  id?: number;
}

export interface NativeLookWindow {
  reg: string;
  offset: number;
  got: number;
  text: string;
  hex: string;
  error: string;
}

export interface NativeLookTrace {
  /** The instruction budget that was asked for. */
  insns: number;
  /** Instructions actually executed under QBDI. */
  seen: number;
  stopReason: string;
  start: string;
  stopPc: string;
  capped: boolean;
  error?: string;
  mnemonics: Array<{ mnemonic: string; count: number }>;
  first: string[];
}

export interface NativeLook {
  hit: boolean;
  hookId: number;
  seq: number | null;
  /** The line to show. Empty windows and a quiet hook are sentences, not a blank. */
  text: string;
  windows: NativeLookWindow[];
  regs: Record<string, string>;
  note: string;
  /** In-hook trace of this hit, when the hook was installed with traceInsns. Null otherwise. */
  trace: NativeLookTrace | null;
}

interface MemEvent {
  seq: number;
  auto: boolean;
  mem: Array<{ reg?: string; offset?: number; got?: number; hex?: string; error?: string }>;
  order: number;
}

interface HookEvent {
  seq: number | null;
  regs: Record<string, string>;
  trace: NativeLookTrace | null;
  order: number;
}

/** One readable line for an in-hook trace: how much ran, why it stopped, and what dominated. */
export function traceLine(t: NativeLookTrace): string {
  const top = (t.mnemonics ?? []).slice(0, 3).map((m) => `${m.mnemonic}×${m.count}`).join(' ');
  const why = t.error ? ` · ${t.error}` : '';
  return `就地 trace ${t.seen}/${t.insns} 条 · ${t.stopReason}${top ? ` · 主要指令 ${top}` : ''}${why}`;
}

export function decodeCaptureJson(hex: string): Record<string, unknown> | null {
  let text = '';
  try { text = Buffer.from(String(hex ?? ''), 'hex').toString('utf8'); } catch { return null; }
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function windowOf(raw: { reg?: string; offset?: number; got?: number; hex?: string; error?: string }): NativeLookWindow {
  const reg = String(raw.reg ?? '?');
  const offset = Number(raw.offset ?? 0);
  const hex = typeof raw.hex === 'string' ? raw.hex : '';
  const got = Number(raw.got ?? (hex ? hex.length / 2 : 0));
  const error = typeof raw.error === 'string' ? raw.error : '';
  const text = memCapturePreview(JSON.stringify({ mem: [{ reg, offset, got, hex, error }] }));
  return { reg, offset, got, text, hex, error };
}

function regsOf(event: Record<string, unknown>): Record<string, string> {
  const regs: Record<string, string> = {};
  for (let i = 0; i <= 8; i++) {
    const key = `x${i}`;
    if (typeof event[key] === 'string') regs[key] = event[key] as string;
  }
  return regs;
}

/** The optional in-hook trace sub-object of a NATIVE_HOOK event (absent unless the hook asked). */
function traceOf(event: Record<string, unknown>): NativeLookTrace | null {
  const raw = event.trace;
  if (!raw || typeof raw !== 'object') return null;
  const t = raw as Record<string, unknown>;
  return {
    insns: Number(t.insns ?? 0),
    seen: Number(t.seen ?? 0),
    stopReason: String(t.stopReason ?? ''),
    start: String(t.start ?? ''),
    stopPc: String(t.stopPc ?? ''),
    capped: t.capped === true,
    ...(typeof t.error === 'string' && t.error ? { error: t.error } : {}),
    mnemonics: Array.isArray(t.mnemonics)
      ? (t.mnemonics as Array<{ mnemonic?: unknown; count?: unknown }>)
        .map((m) => ({ mnemonic: String(m?.mnemonic ?? '?'), count: Number(m?.count ?? 0) }))
      : [],
    first: Array.isArray(t.first) ? (t.first as unknown[]).map((s) => String(s)) : [],
  };
}

/** Latest hit for one hook. Memory and registers that share a seq are one result. */
export function joinNativeLook(records: LookRecord[], hookId: number): NativeLook {
  const empty: NativeLook = {
    hit: false, hookId, seq: null, text: '还没有命中。在手机上做那一步之后再读一次。', windows: [], regs: {}, note: '', trace: null,
  };
  const mems: MemEvent[] = [];
  const hooks: HookEvent[] = [];
  records.forEach((record, index) => {
    const event = decodeCaptureJson(record.hex);
    if (!event || Number(event.hookId) !== hookId) return;
    const order = Number(record.id ?? index);
    if (record.func === 'NATIVE_HOOK_MEM') {
      mems.push({
        seq: Number(event.seq ?? 0),
        auto: event.auto === true,
        mem: Array.isArray(event.mem) ? event.mem as MemEvent['mem'] : [],
        order,
      });
    } else if (record.func === 'NATIVE_HOOK') {
      hooks.push({ seq: event.seq === undefined ? null : Number(event.seq), regs: regsOf(event), trace: traceOf(event), order });
    }
  });
  if (!mems.length && !hooks.length) return empty;

  mems.sort((a, b) => (a.seq - b.seq) || (a.order - b.order));
  hooks.sort((a, b) => ((a.seq ?? -1) - (b.seq ?? -1)) || (a.order - b.order));
  const mem = mems.length ? mems[mems.length - 1] : null;
  const hook = mem
    ? hooks.filter((h) => h.seq === mem.seq).pop() ?? hooks[hooks.length - 1]
    : hooks[hooks.length - 1];
  const windows = (mem?.mem ?? []).map(windowOf);
  const base = mem
    ? (memCapturePreview(JSON.stringify({ auto: mem.auto, mem: mem.mem })) || '这次命中没有抄到可读的内存。')
    : '命中了，这次没有抄到内存。';
  const trace = hook?.trace ?? null;
  const text = trace ? `${base} | ${traceLine(trace)}` : base;
  const note = mem?.auto && windows.length > 1 ? '多出来的窗口是当时别的参数寄存器也指向一块能读的内存。' : '';
  return {
    hit: true,
    hookId,
    seq: mem ? mem.seq : hook?.seq ?? null,
    text,
    windows,
    regs: hook?.regs ?? {},
    note,
    trace,
  };
}

export interface NativeLookDeps {
  sendCmd: (session: string, op: string, args: Record<string, unknown>, timeout?: number) => Promise<any>;
  captures: Array<{ id?: number; sessionId?: string; func: string; hex: string; ts?: number }>;
  drainSession: (session: string) => Promise<unknown>;
}

const defaultDeps: NativeLookDeps = {
  sendCmd: (session, op, args, timeout) => agentCmd(session, op, args, timeout),
  captures: stateCaptures,
  drainSession: (session) => serviceDrainSession(session),
};

export async function nativeLookArm(
  session: string,
  opts: { mode?: string; module?: string; symbol?: string; addr?: string; mem?: string; backtrace?: boolean; traceInsns?: number; traceFrom?: string },
  deps: NativeLookDeps = defaultDeps,
): Promise<{ action: 'arm'; ok: true; hookId: number; mem: string; target: string; text: string }> {
  const sid = pickSid(session) ?? session;
  const mem = parseMemWindows(opts.mem === undefined || opts.mem === '' ? 'auto' : opts.mem).spec || 'auto';
  const mode = opts.mode || 'inline';
  const installed = await deps.sendCmd(sid, 'native_hook', {
    action: 'hook',
    hookId: 0,
    mode,
    module: opts.module ?? '',
    symbol: opts.symbol ?? '',
    addr: opts.addr ?? '',
    skipOriginal: 'false',
    returnValue: '',
    argIndex: -1,
    argValue: '',
    hard: 'false',
    sites: 0,
    scope: '',
    slotsWritable: 'false',
    backtrace: opts.backtrace === false ? 'false' : 'true',
    throttleMs: 0,
    mem,
    ...nativeTracePayload(opts.traceInsns, opts.traceFrom),
  }, 20_000);
  if (!installed?.ok) throw new Error(installed?.error ?? 'native hook install failed');
  const hookId = Number(installed.hookId);
  if (!Number.isFinite(hookId) || hookId <= 0) throw new Error('native hook install did not return a hookId');
  const target = opts.symbol || opts.addr || opts.module || '这个函数';
  return {
    action: 'arm',
    ok: true,
    hookId,
    mem,
    target,
    text: `已在 ${target} 门口等着。到手机上做那一步，然后读这次结果。`,
  };
}

export async function nativeLookRead(session: string, hookId: number, deps: NativeLookDeps = defaultDeps): Promise<NativeLook & { action: 'read' }> {
  if (!Number.isFinite(hookId) || hookId <= 0) throw new Error('need the hookId that arm returned');
  const sid = pickSid(session) ?? session;
  try { await deps.drainSession(sid); } catch { /* the store may already hold the hit */ }
  const records = deps.captures.filter((c) => c.sessionId === sid);
  return { action: 'read', ...joinNativeLook(records, hookId) };
}

export async function nativeLookStop(session: string, hookId: number, hard = false, deps: NativeLookDeps = defaultDeps): Promise<{ action: 'stop'; ok: true; hookId: number; text: string }> {
  if (!Number.isFinite(hookId) || hookId <= 0) throw new Error('need the hookId that arm returned');
  const sid = pickSid(session) ?? session;
  const removed = await deps.sendCmd(sid, 'native_hook', { action: 'unhook', hookId, hard: hard ? 'true' : 'false' }, 20_000);
  if (!removed?.ok) throw new Error(removed?.error ?? 'unhook failed');
  return {
    action: 'stop',
    ok: true,
    hookId,
    text: hard ? '已卸下。这个入口要等进程重新打开才能再挂。' : '已卸下。这个函数还可以再挂。',
  };
}

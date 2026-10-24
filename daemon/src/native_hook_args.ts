// Shared shaping for native-hook installs (host side).
//
// Two host tools resolve addresses themselves and then install inline hooks on each one
// (native_hook_all for exported-symbol batches, syscall_watch for svc #0 sites). Both need the same
// payload rules - in particular the per-hook event throttle, which is what keeps a hot site
// (read/write/futex) from overflowing the capture ring and making the digest look quiet. Keeping the
// shaping in one pure place is also what makes "throttleMs really reaches the agent" a host-testable
// fact instead of a hand-checked one.
export const NATIVE_THROTTLE_MAX_MS = 60_000;

/**
 * 0 (or missing) = no throttling; out-of-range windows clamp to 0..60000 ms and the effective value
 * comes back in the response/status. Non-numeric input is refused: silently treating a typo as "off"
 * would look exactly like a quiet target.
 */
export function normalizeThrottleMs(value: unknown): number {
  if (value === undefined || value === null || value === '') return 0;
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error(`throttleMs must be a number of milliseconds, got ${JSON.stringify(value)}`);
  const ms = Math.trunc(n);
  if (ms <= 0) return 0;
  return ms > NATIVE_THROTTLE_MAX_MS ? NATIVE_THROTTLE_MAX_MS : ms;
}

// Hit-time memory windows. The agent copies these bytes on the hitting thread, before the
// original function runs, and emits them as a separate NATIVE_HOOK_MEM record. "auto" lets
// the agent keep the argument registers that are readable pointers (64 bytes, up to 4) so a
// caller does not have to name x0 first. The numbers are the same constants as ADH_MEM_WIN_*
// in agent/src/hook/native_hooks.h.
export const NATIVE_MEM_WIN_MAX = 6;
export const NATIVE_MEM_WIN_LEN = 1024;
export const NATIVE_MEM_WIN_TOTAL = 4096;
export const NATIVE_MEM_WIN_OFF_MAX = 65535;

export interface MemWindow {
  /** -1 for an absolute window (see addr). */
  reg: number;
  offset: number;
  len: number;
  /** `@x2+32:512`: read the u64 at (reg+offset) and copy the window from THAT address. */
  deref?: boolean;
  /** `@#2+8:256`: read the u64 at +8 inside window 2's copy and copy from THAT address. */
  fromWindow?: number;
  /** `0x7443113690:32`: the window names memory, not a register ("what does this hold NOW"). */
  addr?: string;
}

/**
 * Parse a memory-window spec. Empty means "do not copy". "auto" copies pointer-like
 * argument registers at the hit. Anything else must be `x0:64`, `x2+16:32` or `@x2+32:512`,
 * comma-separated, registers x0-x8 only. The returned `spec` is the canonical string
 * the agent stores and echoes. A typo throws: installing the hook without the window
 * would look like a quiet read.
 */
export function parseMemWindows(value: unknown): { windows: MemWindow[]; spec: string } {
  if (value === undefined || value === null || value === '') return { windows: [], spec: '' };
  if (typeof value !== 'string') {
    throw new Error(`mem must be a string like "auto" or "x0:64", got ${JSON.stringify(value)}`);
  }
  const text = value.trim();
  if (!text) return { windows: [], spec: '' };
  if (text.toLowerCase() === 'auto') return { windows: [], spec: 'auto' };
  const parts = text.split(',');
  if (parts.length > NATIVE_MEM_WIN_MAX) {
    throw new Error(`mem allows at most ${NATIVE_MEM_WIN_MAX} windows, got ${parts.length}`);
  }
  const windows: MemWindow[] = [];
  let total = 0;
  for (const raw of parts) {
    const part = raw.trim();
    // Absolute form first: "0x7443113690:32". A value learned from an earlier hit IS an address, and at
    // the next hit no register necessarily still points at it - that is the whole use case.
    const abs = /^(?:0x)?([0-9a-f]+):([0-9]+)$/i.exec(part);
    if (abs) {
      const address = BigInt(`0x${abs[1]}`);
      const absLen = Number(abs[2]);
      if (address === 0n) throw new Error('mem absolute address must not be 0');
      if (!Number.isSafeInteger(absLen) || absLen < 1 || absLen > NATIVE_MEM_WIN_LEN) {
        throw new Error(`mem length ${absLen} must be 1..${NATIVE_MEM_WIN_LEN}`);
      }
      total += absLen;
      if (total > NATIVE_MEM_WIN_TOTAL) throw new Error(`mem total ${total} exceeds ${NATIVE_MEM_WIN_TOTAL}`);
      windows.push({ reg: -1, offset: 0, len: absLen, addr: `0x${address.toString(16)}` });
      continue;
    }
    // Two shapes. "@#<n>[+<off>]:<len>" follows a pointer that an EARLIER window already copied - the
    // second hop of a pointer chain, which is the shape of a formatter's argument vector (descriptor ->
    // vector -> value). "<@>x<reg>[+<off>]:<len>" reads from a register, optionally following one
    // pointer first.
    const wm = /^@#([1-9][0-9]*)(?:\+([0-9]+))?:([0-9]+)$/.exec(part);
    if (wm) {
      const fromWindow = Number(wm[1]);
      const offset = wm[2] === undefined ? 0 : Number(wm[2]);
      const len = Number(wm[3]);
      if (fromWindow > windows.length) {
        throw new Error(`mem window @#${fromWindow} must reference an earlier window (1..${windows.length})`);
      }
      const prev = windows[fromWindow - 1];
      if (!Number.isSafeInteger(offset) || offset < 0 || offset + 8 > prev.len) {
        throw new Error(`mem window @#${fromWindow}+${offset} needs 8 bytes inside window ${fromWindow} (length ${prev.len})`);
      }
      if (!Number.isSafeInteger(len) || len < 1 || len > NATIVE_MEM_WIN_LEN) {
        throw new Error(`mem length ${len} must be 1..${NATIVE_MEM_WIN_LEN}`);
      }
      total += len;
      if (total > NATIVE_MEM_WIN_TOTAL) throw new Error(`mem total ${total} exceeds ${NATIVE_MEM_WIN_TOTAL}`);
      windows.push({ reg: -1, offset, len, deref: true, fromWindow });
      continue;
    }
    // "<@>x<reg>[+-<off>]:<len>" reads from a register, optionally following one pointer first. A
    // NEGATIVE offset reads BEFORE the register: a template interpreter keeps its instruction records in
    // one contiguous array, so the record that produced a value sits at `pc - 10`, i.e. before the pointer
    // the handler was handed. Without it a hit-time window can only look forward.
    const m = /^(@?)x([0-8])(?:([+-])([0-9]+))?:([0-9]+)$/.exec(part);
    if (!m) throw new Error(`mem window must look like x0:64, x2+16:32, x2-8:8, @x2+32:512 or @#2+8:256, got ${JSON.stringify(part)}`);
    const deref = m[1] === '@';
    const reg = Number(m[2]);
    const offset = m[4] === undefined ? 0 : (m[3] === '-' ? -1 : 1) * Number(m[4]);
    const len = Number(m[5]);
    if (!Number.isSafeInteger(offset) || Math.abs(offset) > NATIVE_MEM_WIN_OFF_MAX) {
      throw new Error(`mem offset ${offset} exceeds ±${NATIVE_MEM_WIN_OFF_MAX}`);
    }
    if (!Number.isSafeInteger(len) || len < 1 || len > NATIVE_MEM_WIN_LEN) {
      throw new Error(`mem length ${len} must be 1..${NATIVE_MEM_WIN_LEN}`);
    }
    total += len;
    if (total > NATIVE_MEM_WIN_TOTAL) throw new Error(`mem total ${total} exceeds ${NATIVE_MEM_WIN_TOTAL}`);
    windows.push(deref ? { reg, offset, len, deref } : { reg, offset, len });
  }
  const spec = windows
    .map((w) => (w.addr
      ? `${w.addr}:${w.len}`
      : w.fromWindow
        ? `@#${w.fromWindow}${w.offset ? `+${w.offset}` : ''}:${w.len}`
        : `${w.deref ? '@' : ''}x${w.reg}${w.offset > 0 ? `+${w.offset}` : w.offset < 0 ? `-${-w.offset}` : ''}:${w.len}`))
    .join(',');
  return { windows, spec };
}

/** One line a person can read from a NATIVE_HOOK_MEM payload (the JSON text, not hex). */
export function memCapturePreview(jsonText: string): string {
  let obj: { auto?: boolean; mem?: Array<{ reg?: string; offset?: number; got?: number; hex?: string; error?: string }> };
  try { obj = JSON.parse(jsonText); } catch { return ''; }
  const wins = Array.isArray(obj.mem) ? obj.mem : [];
  if (wins.length === 0) return obj.auto ? '没有读到像指针的参数' : '';
  return wins.map((w) => {
    const where = `${w.reg ?? '?'}${w.offset ? '+' + w.offset : ''}`;
    if (w.error) return `${where} ${w.error}`;
    const hex = typeof w.hex === 'string' ? w.hex : '';
    const bytes = Buffer.from(hex, 'hex');
    let text = '';
    const shown = bytes.subarray(0, 48);
    for (const b of shown) text += b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
    return `${where} ${w.got ?? bytes.length}字节 ${text}`;
  }).join(' | ');
}

export interface NativeObservationOptions {
  maxEvents?: number;
  sampleEvery?: number;
  tid?: number;
  returnAddress?: string;
}

export const NATIVE_EVENT_LIMIT_MAX = 1_000_000;

function boundedWhole(value: unknown, name: string, fallback: number, min: number, max: number): number {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (typeof value === 'boolean' || !Number.isSafeInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be a whole number in ${min}..${max}`);
  }
  return n;
}

/** Shared wire fields. Defaults are explicit so all install paths agree with the agent. */
export function nativeObservationPayload(opts: NativeObservationOptions): Record<string, string | number> {
  const maxEvents = boundedWhole(opts.maxEvents, 'maxEvents', 0, 0, NATIVE_EVENT_LIMIT_MAX);
  const sampleEvery = boundedWhole(opts.sampleEvery, 'sampleEvery', 1, 1, NATIVE_EVENT_LIMIT_MAX);
  const tid = boundedWhole(opts.tid, 'tid', 0, 0, 2_147_483_647);
  let returnAddress = String(opts.returnAddress ?? '').trim();
  if (returnAddress) {
    if (!/^(?:0x)?[0-9a-f]+$/i.test(returnAddress)) throw new Error('returnAddress must be a nonzero hexadecimal entry x30 address');
    const addr = BigInt(`0x${returnAddress.replace(/^0x/i, '')}`);
    if (addr <= 0n || addr > 0xffff_ffff_ffff_ffffn) throw new Error('returnAddress must be a nonzero 64-bit hexadecimal entry x30 address');
    returnAddress = `0x${addr.toString(16)}`;
  }
  return { maxEvents, sampleEvery, tid, returnAddress };
}

type NativeObservationSender = (session: string, op: string, args: Record<string, unknown>, timeout?: number) => Promise<any>;

/** Old agents silently ignore unknown fields. Require an explicit capability before a new
 * non-default control can install anything; default calls retain the old zero-RPC behavior. */
export async function ensureNativeObservationSupport(
  session: string, opts: NativeObservationOptions, send: NativeObservationSender,
): Promise<Record<string, string | number>> {
  const payload = nativeObservationPayload(opts);
  if (payload.maxEvents === 0 && payload.sampleEvery === 1 && payload.tid === 0 && payload.returnAddress === '') return payload;
  let reply;
  try { reply = await send(session, 'native_hook', { action: 'status' }, 10_000); }
  catch (e) { throw new Error(`cannot verify native observation controls: ${(e as Error).message}; no hook installed`); }
  const version = reply?.status?.observationControlsVersion;
  if (reply?.ok !== true || typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) {
    throw new Error(`target agent does not support native observation controls version 1; deploy current agent before installing${reply?.error ? ` (${reply.error})` : ''}`);
  }
  return payload;
}

export interface NativeHookInstallOptions extends NativeObservationOptions {
  addr: string;
  throttleMs?: number;
  backtrace?: boolean;
  skipOriginal?: boolean;
  returnValue?: string;
  argIndex?: number;
  argValue?: string;
  mem?: string;
  /** In-hook QBDI trace: instructions to run at the hit (0 = off, the default). */
  traceInsns?: number;
  /** Register holding the code address to start the run from ("" = the hooked entry). */
  traceFrom?: string;
  /** One `mem`-style window to watch for WRITES during the run ("" = no watch). */
  traceWatch?: string;
}

// In-hook instruction trace. The ceiling mirrors ADH_QTRACE_INHOOK_MAX in
// agent/src/trace/qbdi_trace.h: the run happens on the TARGET THREAD inside the hook callback, so the
// request is bounded before it can become a second way to hang a target. The agent validates again.
// 4096 was too small to get past a parser into the code that follows it; the wall clock (300 ms) is what
// actually protects the target, so the budget can be generous.
export const NATIVE_TRACE_MAX_INSNS = 65536;

/**
 * 0/missing = off. Anything else is a whole number of instructions, clamped to the agent's ceiling.
 * A non-numeric value throws: silently treating a typo as "off" would look exactly like a hook that
 * was never traced.
 */
export function normalizeTraceInsns(value: unknown): number {
  if (value === undefined || value === null || value === '') return 0;
  const n = Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new Error(`traceInsns must be a whole number of instructions, got ${JSON.stringify(value)}`);
  }
  if (n < 0) throw new Error(`traceInsns must be 0 (off) or positive, got ${n}`);
  return n > NATIVE_TRACE_MAX_INSNS ? NATIVE_TRACE_MAX_INSNS : n;
}

/**
 * "" = start at the hooked function's entry. Otherwise a register that holds a code address.
 * Only registers the hook stub actually saves are usable: x0-x9, x29 (frame pointer), x30 (return
 * address). Anything else would be read from a slot the stub never wrote.
 */
export function normalizeTraceFrom(value: unknown): string {
  if (value === undefined || value === null || value === '') return '';
  const text = String(value).trim().toLowerCase();
  if (!/^x(?:[0-9]|29|30)$/.test(text)) {
    throw new Error(`traceFrom must be x0..x9, x29 or x30 (a register holding a code address), got ${JSON.stringify(value)}`);
  }
  return text;
}

/**
 * The write watch for an in-hook trace: ONE window naming the memory to observe for writes while the
 * traced run executes. Two forms, both needed:
 *   - `x0:32` / `x2-8:8` / `@x1:64` - the same grammar as `mem`, for a buffer the hit's registers point at;
 *   - `0x7443113690:32` - an ABSOLUTE address, which is the common case when the buffer was learned from a
 *     previous hit (an address, not a register).
 * Empty = off. Needs traceInsns: the watch lives only for that run.
 *
 * This is the software stand-in for a hardware watchpoint (perf_event_open is denied to app domains on
 * the devices we use), and it is what turns "which code ran" into "which store landed where": the event
 * comes back with the writing instruction, the address and the value.
 */
export function normalizeTraceWatch(value: unknown): string {
  if (value === undefined || value === null || String(value).trim() === '') return '';
  const text = String(value).trim();
  const abs = /^(?:0x)?([0-9a-f]+):([0-9]+)$/i.exec(text);
  if (abs) {
    const addr = BigInt(`0x${abs[1]}`);
    const len = Number(abs[2]);
    if (addr === 0n) throw new Error('traceWatch address must not be 0');
    if (!Number.isSafeInteger(len) || len < 1 || len > 4096) throw new Error(`traceWatch length ${len} must be 1..4096`);
    return `0x${addr.toString(16)}:${len}`;
  }
  const { windows, spec } = parseMemWindows(text);
  if (windows.length !== 1) {
    throw new Error(`traceWatch must be exactly one window, e.g. x0:32 or 0x7443113690:32 (got ${windows.length})`);
  }
  return spec;
}

/**
 * The trace fields an install may carry. ABSENT when the trace is off - a payload that names
 * traceInsns:0 would still say "this hook was asked to trace", and the default install has to stay
 * byte-identical to what it was before the feature existed.
 */
export function nativeTracePayload(insns: unknown, from: unknown, watch?: unknown): Record<string, string | number> {
  const n = normalizeTraceInsns(insns);
  const reg = normalizeTraceFrom(from);
  const watchSpec = normalizeTraceWatch(watch);
  if (n <= 0) {
    if (reg) throw new Error('traceFrom needs traceInsns (nothing would read that register)');
    if (watchSpec) throw new Error('traceWatch needs traceInsns (the watch lives for the run only)');
    return {};
  }
  const out: Record<string, string | number> = { traceInsns: n };
  if (reg) out.traceFrom = reg;
  if (watchSpec) out.traceWatch = watchSpec;
  return out;
}

/** The exact agent command payload for one address-mode inline hook. */
export function nativeHookInstallPayload(opts: NativeHookInstallOptions): Record<string, string | number> {
  return {
    action: 'hook',
    mode: 'inline',
    module: '',
    symbol: '',
    addr: String(opts.addr),
    throttleMs: normalizeThrottleMs(opts.throttleMs),
    backtrace: opts.backtrace ? 'true' : 'false',
    skipOriginal: opts.skipOriginal ? 'true' : 'false',
    returnValue: opts.returnValue ?? '',
    argIndex: Number(opts.argIndex ?? -1),
    argValue: opts.argValue ?? '',
    mem: parseMemWindows(opts.mem).spec,
    ...nativeObservationPayload(opts),
    ...nativeTracePayload(opts.traceInsns, opts.traceFrom, opts.traceWatch),
  };
}

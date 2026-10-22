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
export const NATIVE_MEM_WIN_MAX = 4;
export const NATIVE_MEM_WIN_LEN = 1024;
export const NATIVE_MEM_WIN_TOTAL = 4096;
export const NATIVE_MEM_WIN_OFF_MAX = 65535;

export interface MemWindow {
  reg: number;
  offset: number;
  len: number;
  /** `@x2+32:512`: read the u64 at (reg+offset) and copy the window from THAT address. */
  deref?: boolean;
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
    const m = /^(@?)x([0-8])(?:\+([0-9]+))?:([0-9]+)$/.exec(part);
    if (!m) throw new Error(`mem window must look like x0:64, x2+16:32 or @x2+32:512, got ${JSON.stringify(part)}`);
    const deref = m[1] === '@';
    const reg = Number(m[2]);
    const offset = m[3] === undefined ? 0 : Number(m[3]);
    const len = Number(m[4]);
    if (!Number.isSafeInteger(offset) || offset > NATIVE_MEM_WIN_OFF_MAX) {
      throw new Error(`mem offset ${offset} exceeds ${NATIVE_MEM_WIN_OFF_MAX}`);
    }
    if (!Number.isSafeInteger(len) || len < 1 || len > NATIVE_MEM_WIN_LEN) {
      throw new Error(`mem length ${len} must be 1..${NATIVE_MEM_WIN_LEN}`);
    }
    total += len;
    if (total > NATIVE_MEM_WIN_TOTAL) throw new Error(`mem total ${total} exceeds ${NATIVE_MEM_WIN_TOTAL}`);
    windows.push(deref ? { reg, offset, len, deref } : { reg, offset, len });
  }
  const spec = windows.map((w) => `${w.deref ? '@' : ''}${w.offset ? `x${w.reg}+${w.offset}` : `x${w.reg}`}:${w.len}`).join(',');
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

export interface NativeHookInstallOptions {
  addr: string;
  throttleMs?: number;
  backtrace?: boolean;
  skipOriginal?: boolean;
  returnValue?: string;
  argIndex?: number;
  argValue?: string;
  mem?: string;
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
  };
}

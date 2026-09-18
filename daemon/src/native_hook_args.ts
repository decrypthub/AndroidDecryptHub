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

export interface NativeHookInstallOptions {
  addr: string;
  throttleMs?: number;
  backtrace?: boolean;
  skipOriginal?: boolean;
  returnValue?: string;
  argIndex?: number;
  argValue?: string;
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
  };
}

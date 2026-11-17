// error_codes.ts — machine-readable failure classes for every MCP tool.
//
// Why: before this, every failure was `{ ok:false, error:"<prose>" }`. A client could not tell
// "you passed a bad argument" (retry differently) from "the session is gone" (restart the target)
// from "the capture ring dropped events" (do NOT conclude anything). That distinction is the
// difference between one retry and a wasted analysis round, and the field reports from real targets
// name exactly this as a top pain.
//
// The classifier is pattern-based on purpose: the daemon already produces honest prose, and this
// module adds a stable enum on top without pretending to be a typed error hierarchy. A client that
// gets UNKNOWN still has the message; a client that gets a code can branch.

export type ErrorCode =
  | 'BAD_ARG'
  | 'NO_SESSION'
  | 'SESSION_OFFLINE'
  | 'AGENT_TIMEOUT'
  | 'UNSUPPORTED_OP'
  | 'TARGET_CRASHED'
  | 'CAPTURE_LOSS'
  | 'HELPER_MISSING'
  | 'DEVICE_UNAVAILABLE'
  | 'UNKNOWN';

interface Rule { code: ErrorCode; re: RegExp }

// Order matters: the first match wins. Loss/incompleteness is checked first because those messages
// often also contain a timeout or a bad-arg word, and misrouting them to BAD_ARG is exactly the
// failure mode this module exists to prevent. BAD_ARG is last so it cannot shadow the others.
const RULES: Rule[] = [
  { code: 'CAPTURE_LOSS', re: /dropped|evicted|complete:\s*false|ring .*full|storeLoss|incomplete/i },
  { code: 'HELPER_MISSING', re: /build_root_watch|helper|not built|prepare failed|missing helper/i },
  { code: 'UNSUPPORTED_OP', re: /unsupported|unknown (op|operation)|not available|old agent|does not support|not implemented|no such op/i },
  { code: 'NO_SESSION', re: /no session|no online agent|session .*not found|session required|需要.*session|没有在线/i },
  { code: 'SESSION_OFFLINE', re: /offline|disconnected|socket hang up|ECONNRESET|connection closed|not connected/i },
  { code: 'AGENT_TIMEOUT', re: /timed out|timeout|still running after|超时/i },
  { code: 'TARGET_CRASHED', re: /crashed|killed by signal|SIGSEGV|SIGBUS|died|target exited/i },
  { code: 'DEVICE_UNAVAILABLE', re: /no device|device offline|unauthorized|adb .*not found|没有在线设备/i },
  { code: 'BAD_ARG', re: /must be|needs |requires |missing |invalid |expected |did not parse|cannot be|cannot parse|unknown argument|不支持.*参数|参数/i },
];

export function classifyError(input: unknown): ErrorCode {
  const text = input instanceof Error ? input.message : String(input ?? '');
  for (const rule of RULES) if (rule.re.test(text)) return rule.code;
  return 'UNKNOWN';
}

/** The payload every MCP tool failure is rendered as. Keeps `ok:false` for older clients. */
export function errorPayload(e: unknown): { ok: false; code: ErrorCode; error: string } {
  const message = (e instanceof Error ? e.message : String(e ?? 'error')) || 'error';
  return { ok: false, code: classifyError(message), error: message };
}

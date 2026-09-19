// NaN-safe numeric parsing shared by the MCP tool surface and the phone text renderer
// (v4.96/v4.99). Number('abc') is NaN and every Math.max/min clamp propagates it: a NaN timeout
// never fires, so a wait primitive polls forever; NaN retries make `attempt >= retries` false
// forever; a NaN maxNodes silently renders an empty screen. The MCP layer does not schema-validate,
// so the numbers have to be sanitized where they are read.
export function finiteNumber(value: unknown, fallback: number, min: number, max: number): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

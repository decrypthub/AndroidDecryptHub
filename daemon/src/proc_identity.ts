// Pure procfs identity parsing shared by diagnostics and the independent root
// collector. Never parse stat by splitting the comm field on spaces.
export function normalizeStarttimeTicks(value: unknown): string | undefined {
  return typeof value === 'string' && value.length >= 1 && value.length <= 20 && !/[^0-9]/.test(value) ? value : undefined;
}
export function parseProcStat(text?: string) {
  const match = /^(\d+) \(([^]*)\) ([A-Za-z]) (.*)$/.exec((text ?? '').trim());
  if (!match) return null;
  const fields = match[4].trim().split(/\s+/), starttime = normalizeStarttimeTicks(fields[18]);
  if (starttime === undefined) return null;
  return { pid: Number(match[1]), state: match[3], starttime };
}
export function assertProcessGeneration(stat: string, pid: number, expected?: string) {
  const observed = parseProcStat(stat);
  if (!observed || observed.pid !== pid) throw new Error('Cannot establish exact device PID starttime');
  if (expected !== undefined && (normalizeStarttimeTicks(expected) === undefined || observed.starttime !== expected))
    throw new Error('Device PID generation does not match the selected agent session');
  return { starttimeTicks: observed.starttime, sessionGenerationVerified: expected !== undefined };
}

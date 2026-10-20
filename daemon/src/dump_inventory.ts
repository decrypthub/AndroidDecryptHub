// Pure decisions for the Dump page. No process state and no filesystem.
//
// A dex is unpackable only when the bytes ART declared are one contiguous readable
// mapping. An app's package directories come from the .so paths already mapped, plus
// the private files dir where packers drop libraries that are not under lib/arm64.

export interface MapSpan {
  start: string;
  end: string;
  perms: string;
}

export function contiguousReadable(regions: readonly MapSpan[], beginHex: string, declared: number): number {
  if (!Number.isSafeInteger(declared) || declared <= 0) return 0;
  const begin = parseHex(beginHex);
  if (begin === null) return 0;
  const want = begin + BigInt(declared);
  const spans = regions
    .map((region) => ({ start: parseHex(region.start), end: parseHex(region.end), read: region.perms[0] === 'r' }))
    .filter((span): span is { start: bigint; end: bigint; read: boolean } =>
      span.start !== null && span.end !== null && span.end > span.start)
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  let cursor = begin;
  for (const span of spans) {
    if (span.end <= cursor) continue;
    if (span.start > cursor) break;
    if (!span.read) break;
    if (span.end > cursor) cursor = span.end;
    if (cursor >= want) return declared;
  }
  const got = cursor - begin;
  if (got <= 0n) return 0;
  return Number(got > BigInt(declared) ? BigInt(declared) : got);
}

/**
 * Directories that commonly hold an app's own .so files.
 * - Mapped path parents (already-loaded libs, often under /data/app/.../lib/arm64)
 * - Private lib/ and files/ (legacy + packer-dropped libs)
 */
export function packageSoDirs(mappedPaths: readonly string[], packageName: string): string[] {
  const pkg = packageName.trim();
  const dirs = new Set<string>();
  for (const path of mappedPaths) {
    const slash = path.lastIndexOf('/');
    if (slash > 0) dirs.add(path.slice(0, slash));
  }
  if (pkg && pkg !== '?') {
    dirs.add(`/data/data/${pkg}/lib`);
    dirs.add(`/data/user/0/${pkg}/lib`);
    dirs.add(`/data/data/${pkg}/files`);
    dirs.add(`/data/user/0/${pkg}/files`);
  }
  return [...dirs];
}

export function preferMainProcess<T extends { process: string; package: string; online: boolean }>(rows: readonly T[]): T | null {
  const online = rows.filter((row) => row.online);
  return online.find((row) => !row.process.includes(':')) ?? online[0] ?? null;
}

/** Safe zip subfolder for a process: main / pushservice / … (no path separators). */
export function processFolderLabel(processName: string, packageName: string): string {
  const proc = String(processName || '').trim();
  const pkg = String(packageName || '').trim();
  if (!proc || proc === pkg || !proc.includes(':')) return 'main';
  const suffix = proc.slice(proc.indexOf(':') + 1).replace(/[^a-zA-Z0-9._-]+/g, '_') || 'proc';
  return suffix.slice(0, 64);
}

function parseHex(hex: string): bigint | null {
  const text = String(hex ?? '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]+$/.test(text)) return null;
  return BigInt('0x' + text);
}

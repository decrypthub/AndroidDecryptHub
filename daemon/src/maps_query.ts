// maps_query.ts — the "which segment is this address in / where is the decrypted copy" primitive.
//
// A full /proc/<pid>/maps is 2000-5000 lines; dumping it into a model's context is useless, and the
// field report from a real VMP target says exactly what that costs: the decrypted copy lived in an
// anonymous segment, the first dump took an executable segment and returned garbage, and the only
// reason it was caught was a hand-computed entropy difference. This module turns the raw maps reply
// into a filterable, address-resolving view, with "belongs to whom" as a tool fact.

export interface RawRegion {
  start?: string | number;
  end?: string | number;
  perms?: string;
  offset?: string;
  dev?: string;
  inode?: number;
  path?: string;
}

export interface MapsQuery {
  /** Substring match on the path (module name, [anon:...], /dev/...). */
  path?: string;
  /** Only regions whose perms start with this (e.g. "r-x" or "rw"). */
  perm?: string;
  /** true = executable; false = not executable. */
  exec?: boolean;
  /** true = no file-backed path (anonymous); false = file-backed. */
  anon?: boolean;
  minSize?: number;
  maxSize?: number;
  /** 0 or omitted = no limit; the reply always reports matched/truncated. */
  limit?: number;
  /** Resolve this address: returns the containing region + module-relative offset. */
  addr?: string;
}

export interface MapsRow {
  start: string;
  end: string;
  size: number;
  perms: string;
  offset: string;
  path: string;
}

export interface MapsResolved {
  addr: string;
  region: MapsRow;
  /** File offset of the address inside its backing file, when the region is file-backed. */
  fileOffset: string | null;
  /** Address minus region start, in hex. */
  regionOffset: string;
}

export interface MapsResult {
  ok: true;
  total: number;
  matched: number;
  returned: number;
  truncated: boolean;
  regions: MapsRow[];
  resolved?: MapsResolved;
}

function toBig(value: string | number | undefined): bigint | null {
  if (value === undefined || value === null) return null;
  try {
    const text = String(value).trim();
    return text.startsWith('0x') ? BigInt(text) : BigInt(`0x${text}`);
  } catch {
    return null;
  }
}

function hex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

export function normalizeRegion(r: RawRegion): MapsRow | null {
  const start = toBig(r.start);
  const end = toBig(r.end);
  if (start === null || end === null || end <= start) return null;
  const size = Number(end - start);
  const offset = String(r.offset ?? '0').trim();
  return {
    start: hex(start),
    end: hex(end),
    size,
    perms: String(r.perms ?? ''),
    offset: offset.startsWith('0x') ? offset : `0x${offset}`,
    path: String(r.path ?? '').trim(),
  };
}

/** Rewrite the resolved address with a module-relative offset, when the region is file-backed. */
export function resolveAddress(rows: MapsRow[], addr: string): MapsResolved | null {
  const target = toBig(addr);
  if (target === null) return null;
  for (const row of rows) {
    const start = toBig(row.start)!;
    const end = toBig(row.end)!;
    if (target < start || target >= end) continue;
    const base = toBig(row.offset);
    const fileOffset = row.path && base !== null ? hex(base + (target - start)) : null;
    return {
      addr: hex(target),
      region: row,
      fileOffset,
      regionOffset: hex(target - start),
    };
  }
  return null;
}

export function queryMaps(raw: RawRegion[], q: MapsQuery = {}): MapsResult {
  const rows: MapsRow[] = [];
  for (const r of Array.isArray(raw) ? raw : []) {
    const row = normalizeRegion(r);
    if (row) rows.push(row);
  }
  const total = rows.length;
  const perm = q.perm ? String(q.perm) : '';
  const pathNeedle = q.path ? String(q.path).toLowerCase() : '';
  const matches = rows.filter((row) => {
    if (pathNeedle && !row.path.toLowerCase().includes(pathNeedle)) return false;
    if (perm && !row.perms.startsWith(perm)) return false;
    if (q.exec === true && !row.perms.includes('x')) return false;
    if (q.exec === false && row.perms.includes('x')) return false;
    if (q.anon === true && row.path && !row.path.startsWith('[')) return false;
    if (q.anon === false && (!row.path || row.path.startsWith('['))) return false;
    if (q.minSize !== undefined && row.size < Number(q.minSize)) return false;
    if (q.maxSize !== undefined && row.size > Number(q.maxSize)) return false;
    return true;
  });
  const limit = Number(q.limit) > 0 ? Math.min(Number(q.limit), 500) : matches.length;
  const returned = matches.slice(0, limit);
  const result: MapsResult = {
    ok: true,
    total,
    matched: matches.length,
    returned: returned.length,
    truncated: matches.length > returned.length,
    regions: returned,
  };
  if (q.addr) {
    const resolved = resolveAddress(rows, String(q.addr));
    if (resolved) result.resolved = resolved;
  }
  return result;
}

// maps_view.ts — the whole address space, normalized, plus the counters that answer "what does this
// process look like" without making the browser re-derive them from 3000 raw lines.
//
// The model-facing surface is maps_query: filtered and paged because a full reply floods context.
// The panel is the opposite case — it needs every row ONCE so filtering, sorting and paging stay
// local and instant, and it needs the aggregates that are easy to get subtly wrong in the client
// (anonymous = "[anon:...]" AND an empty path; a device path like /dev/ashmem is neither anonymous
// nor a module). Both read the same rows through normalizeRegion, so they cannot disagree about
// start/end/size.
import { normalizeRegion, type MapsRow, type RawRegion } from './maps_query.ts';

export interface MapsStats {
  /** Regions kept from the raw reply (unparseable lines dropped). */
  total: number;
  readable: number;
  writable: number;
  executable: number;
  /** Writable AND executable: self-modifying code / freshly decrypted payload territory. */
  writableExecutable: number;
  /** No file backing: [anon:*], [stack], [heap], [vdso], and rows with an empty path. */
  anonymous: number;
  /** Anonymous AND executable — where an unpacked payload or a VMP interpreter usually lives. */
  anonymousExecutable: number;
  fileBacked: number;
  /** Sum of the virtual sizes. Virtual, not resident: a 2 GB dalvik space counts in full. */
  mappedBytes: number;
  executableBytes: number;
  anonymousExecutableBytes: number;
}

export interface MapsView {
  ok: true;
  total: number;
  regions: MapsRow[];
  stats: MapsStats;
}

/** A [label] path or no path at all means the mapping has no file behind it. */
export function isAnonymousPath(path: string): boolean {
  const p = path ?? '';
  return !p || p.startsWith('[');
}

export function summarizeMaps(rows: readonly MapsRow[]): MapsStats {
  const stats: MapsStats = {
    total: 0, readable: 0, writable: 0, executable: 0, writableExecutable: 0,
    anonymous: 0, anonymousExecutable: 0, fileBacked: 0,
    mappedBytes: 0, executableBytes: 0, anonymousExecutableBytes: 0,
  };
  for (const row of rows) {
    const perms = String(row.perms ?? '');
    const readable = perms.startsWith('r');
    const writable = perms.length > 1 && perms[1] === 'w';
    const executable = perms.length > 2 && perms[2] === 'x';
    const anonymous = isAnonymousPath(row.path);
    const size = Number.isFinite(row.size) ? row.size : 0;
    stats.total++;
    if (readable) stats.readable++;
    if (writable) stats.writable++;
    if (executable) stats.executable++;
    if (writable && executable) stats.writableExecutable++;
    if (anonymous) stats.anonymous++;
    else stats.fileBacked++;
    stats.mappedBytes += size;
    if (executable) {
      stats.executableBytes += size;
      if (anonymous) {
        stats.anonymousExecutable++;
        stats.anonymousExecutableBytes += size;
      }
    }
  }
  return stats;
}

/** Normalize a raw agent `maps` reply. Rows that cannot be parsed are dropped, not guessed. */
export function mapsView(raw: readonly RawRegion[] | null | undefined): MapsView {
  const regions: MapsRow[] = [];
  for (const r of Array.isArray(raw) ? raw : []) {
    const row = normalizeRegion(r);
    if (row) regions.push(row);
  }
  return { ok: true, total: regions.length, regions, stats: summarizeMaps(regions) };
}

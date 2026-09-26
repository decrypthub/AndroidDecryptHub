// artifacts.ts — pure policy for the on-disk artifact store (captures/).
//
// Kept free of filesystem and daemon-state imports so the retention policy can be unit-tested
// directly: state.ts owns the store, this owns the decisions.
//
// Naming on disk: `<sha16>.<kind>.bin` (persistArtifact / dumpRegion), `<sha16>.so` (module
// reassembly), `<sha16>.dex` (dex rebuild/recover). Only 16 hex chars of the sha are in the name,
// so a reload has to re-hash the bytes — which is also what keeps it self-healing rather than
// dependent on a side index that can drift.

export interface ArtifactEntry { sha256: string; path: string; size: number; mtime: number }

/** Map an artifact filename to its kind, or null when the name is not an artifact we wrote. */
export function artifactKindOf(name: string): string | null {
  const m = /^([0-9a-f]{16})(?:\.([a-z0-9]+))?\.(bin|so|dex)$/.exec(name);
  if (!m) return null;
  return m[3] === 'bin' ? (m[2] ?? 'region') : m[3];
}

/**
 * Decide which artifacts to reclaim.
 *
 * Over-age entries go first, then oldest-first until the byte budget is met. `protectSha` (the
 * artifact just written) is never evicted by the size rule: pruning runs right after a write, and
 * evicting the file the caller just asked for is within policy but useless to them.
 *
 * `overAge` / `overSize` are reported separately so a caller can tell the two rules apart.
 */
export function planArtifactEviction(
  entries: ArtifactEntry[],
  policy: { maxBytes: number; maxAgeDays: number },
  now: number,
  protectSha?: string,
): { evict: ArtifactEntry[]; overAge: number; overSize: number; remainingBytes: number } {
  const maxAgeMs = policy.maxAgeDays > 0 ? policy.maxAgeDays * 86_400_000 : 0;
  const evict: ArtifactEntry[] = [];
  const evicted = new Set<string>();
  let overAge = 0;
  if (maxAgeMs) {
    for (const e of entries) {
      if (e.mtime && now - e.mtime > maxAgeMs) { evict.push(e); evicted.add(e.sha256); overAge++; }
    }
  }
  const alive = entries.filter((e) => !evicted.has(e.sha256));
  let total = alive.reduce((a, e) => a + (Number(e.size) || 0), 0);
  let overSize = 0;
  if (total > policy.maxBytes) {
    for (const e of [...alive].sort((a, b) => a.mtime - b.mtime)) {
      if (total <= policy.maxBytes) break;
      if (protectSha && e.sha256 === protectSha) continue;
      evict.push(e); evicted.add(e.sha256);
      total -= Number(e.size) || 0;
      overSize++;
    }
  }
  return { evict, overAge, overSize, remainingBytes: Math.max(0, total) };
}

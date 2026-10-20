// Package-scoped capture log on disk. Agent still only rings+drains; Host owns the durable store.
// Layout: {dataDir}/packages/<package>/captures.jsonl — one JSON object per line.
import {
  appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync,
  unlinkSync, writeFileSync, rmSync, statSync,
} from 'node:fs';
import { join } from 'node:path';

// Subset of Host Capture needed for disk — kept local so this module never imports state.ts.
export interface PersistedCapture {
  id: number;
  sessionId: string;
  source: string;
  func: string;
  algo: string;
  op: string;
  category: string;
  inl: number;
  tid: number;
  tsNs: number;
  ts: number;
  hex: string;
  preview: string;
  package?: string;
  conn?: string;
  keyHex?: string;
  ivHex?: string;
  outHex?: string;
}

const PKG_RE = /^[a-zA-Z0-9._-]+$/;

// Reject path traversal and junk so a package name never escapes packages/.
export function safePackageDirName(pkg: string): string | null {
  if (!pkg || pkg === '?' || !PKG_RE.test(pkg)) return null;
  return pkg;
}

export function packageCapturesPath(dataDir: string, pkg: string): string | null {
  const safe = safePackageDirName(pkg);
  if (!safe) return null;
  return join(dataDir, 'packages', safe, 'captures.jsonl');
}

export function appendCaptureLine(dataDir: string, entry: PersistedCapture): void {
  const pkg = entry.package && entry.package !== '?' ? entry.package : '';
  const path = packageCapturesPath(dataDir, pkg);
  if (!path) return;
  mkdirSync(join(dataDir, 'packages', safePackageDirName(pkg)!), { recursive: true });
  appendFileSync(path, JSON.stringify(entry) + '\n');
}

// Keep the newest retain lines for one package file (rewrite). No-op if under budget.
export function trimPackageCapturesFile(dataDir: string, pkg: string, retain: number): void {
  const path = packageCapturesPath(dataDir, pkg);
  if (!path || !existsSync(path) || retain < 1) return;
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  if (lines.length <= retain) return;
  const kept = lines.slice(-retain);
  const tmp = path + '.tmp';
  writeFileSync(tmp, kept.join('\n') + '\n');
  renameSync(tmp, path);
}

// Load durable captures from every packages/<pkg>/captures.jsonl (newest retain lines each).
export function loadCapturesFromDisk(dataDir: string, retain: number): PersistedCapture[] {
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return [];
  const out: PersistedCapture[] = [];
  for (const name of readdirSync(root)) {
    if (!safePackageDirName(name)) continue;
    const path = join(root, name, 'captures.jsonl');
    if (!existsSync(path)) continue;
    let lines: string[];
    try { lines = readFileSync(path, 'utf8').split('\n').filter(Boolean); }
    catch { continue; }
    if (retain > 0 && lines.length > retain) lines = lines.slice(-retain);
    for (const line of lines) {
      try {
        const c = JSON.parse(line) as PersistedCapture;
        if (!c || typeof c.id !== 'number') continue;
        if (!c.package) c.package = name;
        out.push(c);
      } catch {
        // skip corrupt line
      }
    }
  }
  out.sort((a, b) => a.id - b.id || a.ts - b.ts);
  return out;
}

export interface PackageCaptureStat {
  package: string;
  lines: number;
  bytes: number;
  oldestTs: number;
  newestTs: number;
}

/** Per-package disk stats for the packages/<pkg>/captures.jsonl logs. */
export function listPackageCaptureStats(dataDir: string): PackageCaptureStat[] {
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return [];
  const out: PackageCaptureStat[] = [];
  for (const name of readdirSync(root)) {
    if (!safePackageDirName(name)) continue;
    const path = join(root, name, 'captures.jsonl');
    if (!existsSync(path)) continue;
    let bytes = 0, lines = 0, oldestTs = 0, newestTs = 0;
    try {
      bytes = statSync(path).size;
      const raw = readFileSync(path, 'utf8').split('\n').filter(Boolean);
      lines = raw.length;
      for (const line of raw) {
        try {
          const ts = Number((JSON.parse(line) as { ts?: number }).ts) || 0;
          if (!oldestTs || (ts && ts < oldestTs)) oldestTs = ts;
          if (ts > newestTs) newestTs = ts;
        } catch { /* skip */ }
      }
    } catch { continue; }
    out.push({ package: name, lines, bytes, oldestTs, newestTs });
  }
  return out.sort((a, b) => a.package.localeCompare(b.package));
}

/** Delete one package's captures.jsonl (and its directory if empty). */
export function clearPackagePersistedCaptures(dataDir: string, pkg: string): string[] {
  const errors: string[] = [];
  const safe = safePackageDirName(pkg);
  if (!safe) return [`包名不正确: ${pkg}`];
  const dir = join(dataDir, 'packages', safe);
  const path = join(dir, 'captures.jsonl');
  try { if (existsSync(path)) unlinkSync(path); } catch (e) { errors.push(`${path}: ${(e as Error).message}`); }
  try {
    if (existsSync(dir) && readdirSync(dir).length === 0) rmSync(dir, { recursive: true, force: true });
  } catch (e) { errors.push(`${dir}: ${(e as Error).message}`); }
  return errors;
}

/** Drop records older than maxAgeDays from each package file. maxAgeDays<=0 means no age prune. */
export function pruneCapturesOlderThan(dataDir: string, maxAgeDays: number, now = Date.now()): number {
  if (maxAgeDays <= 0) return 0;
  const cutoff = now - maxAgeDays * 86400000;
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return 0;
  let dropped = 0;
  for (const name of readdirSync(root)) {
    if (!safePackageDirName(name)) continue;
    const path = join(root, name, 'captures.jsonl');
    if (!existsSync(path)) continue;
    let lines: string[];
    try { lines = readFileSync(path, 'utf8').split('\n').filter(Boolean); }
    catch { continue; }
    const kept: string[] = [];
    for (const line of lines) {
      try {
        const ts = Number((JSON.parse(line) as { ts?: number }).ts) || 0;
        if (ts && ts < cutoff) { dropped++; continue; }
      } catch { /* keep corrupt lines */ }
      kept.push(line);
    }
    if (kept.length === lines.length) continue;
    if (!kept.length) {
      try { unlinkSync(path); } catch { /* ignore */ }
      continue;
    }
    const tmp = path + '.tmp';
    writeFileSync(tmp, kept.join('\n') + '\n');
    renameSync(tmp, path);
  }
  return dropped;
}

/** Read the raw jsonl text for export (empty string if missing). */
export function readPackageCapturesJsonl(dataDir: string, pkg: string): string | null {
  const path = packageCapturesPath(dataDir, pkg);
  if (!path || !existsSync(path)) return null;
  return readFileSync(path, 'utf8');
}

// Drop the entire packages/ tree under dataDir.
export function clearAllPersistedCaptures(dataDir: string): string[] {
  const errors: string[] = [];
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return errors;
  try {
    rmSync(root, { recursive: true, force: true });
  } catch (e) {
    errors.push(`${root}: ${(e as Error).message}`);
    // Best-effort per file if the tree delete failed mid-way.
    try {
      for (const name of readdirSync(root)) {
        const path = join(root, name, 'captures.jsonl');
        try { if (existsSync(path)) unlinkSync(path); } catch (err) { errors.push(`${path}: ${(err as Error).message}`); }
      }
    } catch {
      // ignore
    }
  }
  return errors;
}

// Evict oldest records of pkg from the in-memory list until that package has at most retain.
// Returns how many were removed (oldest first).
export function evictPackageFromMemory<T extends { package?: string }>(list: T[], pkg: string, retain: number): T[] {
  if (retain < 1) return [];
  const idxs: number[] = [];
  for (let i = 0; i < list.length; i++) {
    const p = list[i].package && list[i].package !== '?' ? list[i].package! : '';
    if (p === pkg) idxs.push(i);
  }
  const drop = idxs.length - retain;
  if (drop <= 0) return [];
  const removeAt = new Set(idxs.slice(0, drop));
  const evicted: T[] = [];
  for (let i = list.length - 1; i >= 0; i--) {
    if (!removeAt.has(i)) continue;
    evicted.push(list[i]);
    list.splice(i, 1);
  }
  return evicted.reverse();
}

// Re-apply per-package retain across the whole in-memory list (e.g. after settings change).
export function enforcePerPackageRetain<T extends { package?: string }>(list: T[], retain: number): T[] {
  const pkgs = new Set<string>();
  for (const c of list) pkgs.add(c.package && c.package !== '?' ? c.package : '');
  const all: T[] = [];
  for (const pkg of pkgs) all.push(...evictPackageFromMemory(list, pkg, retain));
  return all;
}

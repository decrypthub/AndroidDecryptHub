import {captureMatchesScope,deviceRequestScope,type AgentDeviceBinding} from './agent_scope.ts';
import { atomicWriteText } from './storage.ts';
// Package-scoped capture log on disk. Agent still only rings+drains; Host owns the durable store.
// Layout: {dataDir}/packages/<package>/captures.jsonl — one JSON object per line.
import {
  appendFileSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync,
  readdirSync, renameSync, unlinkSync, writeFileSync, rmSync, statSync,
} from 'node:fs';
import { join } from 'node:path';

// Subset of Host Capture needed for disk — kept local so this module never imports state.ts.
export interface PersistedCapture {
  id: number;
  sessionId: string;
  deviceBinding?:Readonly<AgentDeviceBinding>;
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
  path?: string;
  callStack?: string;
}

function retentionKey(c:{deviceBinding?:Readonly<AgentDeviceBinding>}){return c.deviceBinding?.serial??'legacy-unverified';}
function retainedLines(lines:string[],retain:number):string[]{
  if(retain<1)return lines;const counts=new Map<string,number>();
  return lines.filter(()=>true).reverse().filter(line=>{try{const c=JSON.parse(line);const k=retentionKey(c);const n=(counts.get(k)??0)+1;counts.set(k,n);return n<=retain;}catch{return true;}}).reverse();
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

export function appendCaptureLines(dataDir: string, pkg: string, entries: PersistedCapture[]): void {
  const path = packageCapturesPath(dataDir, pkg);
  if (!path || entries.length === 0) return;
  mkdirSync(join(dataDir, 'packages', safePackageDirName(pkg)!), { recursive: true });
  appendFileSync(path, entries.map((entry) => JSON.stringify(entry)).join('\n') + '\n');
}

// 单条删除不重写主文件（可能几百 MB）：packages/<pkg>/captures.deleted.jsonl 追加墓碑，
// 恢复、分页、详情、导出所有读取路径统一过滤。
const deletedIdsCache = new Map<string, Set<number>>();

export function deletedCaptureIds(dataDir: string, pkg: string): Set<number> {
  const safe = safePackageDirName(pkg);
  const empty = new Set<number>();
  if (!safe) return empty;
  const path = join(dataDir, 'packages', safe, 'captures.deleted.jsonl');
  const cached = deletedIdsCache.get(path);
  if (cached) return cached;
  if (existsSync(path)) {
    try {
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        if (!line) continue;
        try {
          const id = Number((JSON.parse(line) as { id?: number }).id);
          if (Number.isFinite(id)) empty.add(id);
        } catch { /* skip corrupt line */ }
      }
    } catch { /* unreadable → treat as none */ }
  }
  deletedIdsCache.set(path, empty);
  return empty;
}

export function markCaptureDeleted(dataDir: string, pkg: string, id: number): void {
  const safe = safePackageDirName(pkg);
  if (!safe || !Number.isFinite(id) || id <= 0) return;
  mkdirSync(join(dataDir, 'packages', safe), { recursive: true });
  appendFileSync(join(dataDir, 'packages', safe, 'captures.deleted.jsonl'), JSON.stringify({ id }) + '\n');
  deletedCaptureIds(dataDir, safe).add(id);
}

// Keep the newest retain lines for one package file (rewrite). No-op if under budget.
export function trimPackageCapturesFile(dataDir: string, pkg: string, retain: number): void {
  const path = packageCapturesPath(dataDir, pkg);
  if (!path || !existsSync(path) || retain < 1) return;
  const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
  if (lines.length <= retain) return;
  const kept = retainedLines(lines,retain);
  const tmp = path + '.tmp';
  writeFileSync(tmp, kept.join('\n') + '\n');
  renameSync(tmp, path);
}

/** Preview or explicitly enforce both disk rules. Read failures are reported, never success. */
export function retainCaptureFiles(dataDir: string, policy: { retain: number; maxAgeDays: number }, dryRun = true, now = Date.now()) {
  const packages: { package: string; before: number; remaining: number; removed: number }[] = [];
  const errors: string[] = [];
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return { packages, removed: 0, errors };
  for (const name of readdirSync(root)) {
    if (!safePackageDirName(name)) continue;
    const path = join(root, name, 'captures.jsonl');
    if (!existsSync(path)) continue;
    try {
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
      const cutoff = policy.maxAgeDays > 0 ? now - policy.maxAgeDays * 86400000 : 0;
      let kept = lines.filter(line => {
        try { const ts = Number(JSON.parse(line).ts) || 0; return !cutoff || !ts || ts >= cutoff; }
        catch { return true; }
      });
      if (policy.retain > 0) kept = retainedLines(kept,policy.retain);
      const removed = lines.length - kept.length;
      if (!dryRun && removed) {
        if (kept.length) atomicWriteText(path, kept.join('\n') + '\n');
        else unlinkSync(path);
      }
      packages.push({ package: name, before: lines.length, remaining: kept.length, removed });
    } catch (error) { errors.push(`${name}: ${(error as Error).message}`); }
  }
  return { packages, removed: packages.reduce((n, p) => n + p.removed, 0), errors };
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
    const deleted = deletedCaptureIds(dataDir, name);
    let lines: string[];
    try { lines = readFileSync(path, 'utf8').split('\n').filter(Boolean); }
    catch { continue; }
    if (retain > 0) lines = retainedLines(lines,retain);
    for (const line of lines) {
      try {
        const c = JSON.parse(line) as PersistedCapture;
        if (!c || typeof c.id !== 'number') continue;
        if (deleted.size && deleted.has(c.id)) continue;
        if (!c.package) c.package = name;
        if (captureMatchesScope(c)) out.push(c);
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
  if(deviceRequestScope()?.serial){
    // Tombstones preserve other phones, unknown history and malformed rows byte-for-byte.
    if(existsSync(path))try{for(const line of readFileSync(path,'utf8').split('\n')){try{const c=JSON.parse(line);if(captureMatchesScope({...c,package:c.package||pkg}))markCaptureDeleted(dataDir,pkg,c.id);}catch{}}}catch(e){errors.push((e as Error).message);}
    return errors;
  }
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
  const text=readFileSync(path,'utf8');
  if(!deviceRequestScope()?.serial&&!deviceRequestScope()?.package)return text;
  return text.split('\n').filter(line=>{try{const c=JSON.parse(line);return captureMatchesScope({...c,package:c.package||pkg});}catch{return false;}}).join('\n');
}

// Drop the entire packages/ tree under dataDir.
export function clearAllPersistedCaptures(dataDir: string): string[] {
  const errors: string[] = [];
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return errors;
  if(deviceRequestScope()?.serial){for(const name of readdirSync(root))if(safePackageDirName(name))errors.push(...clearPackagePersistedCaptures(dataDir,name));return errors;}
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
export function evictPackageFromMemory<T extends { package?: string;deviceBinding?:Readonly<AgentDeviceBinding> }>(list: T[], pkg: string, retain: number): T[] {
  if (retain < 1) return [];
  const buckets=new Map<string,number[]>();
  for(let i=0;i<list.length;i++)if((list[i].package&&list[i].package!=='?'?list[i].package:'')===pkg){const k=retentionKey(list[i]);if(!buckets.has(k))buckets.set(k,[]);buckets.get(k)!.push(i);}
  const removeAt=new Set<number>();
  for(const bucket of buckets.values())for(const i of bucket.slice(0,Math.max(0,bucket.length-retain)))removeAt.add(i);
  const evicted: T[] = [];
  for (let i = list.length - 1; i >= 0; i--) {
    if (!removeAt.has(i)) continue;
    evicted.push(list[i]);
    list.splice(i, 1);
  }
  return evicted.reverse();
}

// Re-apply per-package retain across the whole in-memory list (e.g. after settings change).
export function enforcePerPackageRetain<T extends { package?: string;deviceBinding?:Readonly<AgentDeviceBinding> }>(list: T[], retain: number): T[] {
  const pkgs = new Set<string>();
  for (const c of list) pkgs.add(c.package && c.package !== '?' ? c.package : '');
  const all: T[] = [];
  for (const pkg of pkgs) all.push(...evictPackageFromMemory(list, pkg, retain));
  return all;
}

export interface CapturePageQuery {
  package?: string | null;
  session?: string | null;
  categories?: string[] | null;
  since?: number;
  beforeId?: number | null;
  fromTs?: number | null;
  toTs?: number | null;
  q?: string | null;
  limit: number;
}

const REV_CHUNK = 128 * 1024;

function narrowUpperOffset(fd: number, size: number, beforeId: number | null, toTs: number | null): number {
  if (size <= 512 * 1024 || (beforeId == null && toTs == null)) return size;
  let lo = 0, hi = size;
  const probe = Buffer.allocUnsafe(REV_CHUNK);
  for (let step = 0; step < 22 && hi - lo > 256 * 1024; step++) {
    const mid = Math.floor((lo + hi) / 2);
    const n = readSync(fd, probe, 0, Math.min(REV_CHUNK, hi - mid), mid);
    if (n <= 0) break;
    const nl1 = probe.subarray(0, n).indexOf(10);
    if (nl1 < 0 || nl1 + 1 >= n) break;
    const nl2 = probe.subarray(nl1 + 1, n).indexOf(10);
    if (nl2 < 0) break;
    const line = probe.subarray(nl1 + 1, nl1 + 1 + nl2).toString('utf8');
    let rec: { id?: number; ts?: number } | null = null;
    try { rec = JSON.parse(line); } catch { break; }
    if (!rec || typeof rec.id !== 'number') break;
    const tooNew = (beforeId != null && rec.id >= beforeId) || (toTs != null && (rec.ts ?? 0) > toTs);
    if (tooNew) hi = mid + nl1 + 1;
    else lo = mid + nl1 + 1 + nl2 + 1;
  }
  return hi;
}

function scanOneFilePage(
  filePath: string,
  pkgName: string,
  q: CapturePageQuery,
  catSet: Set<string> | null,
  needle: string,
  deleted: Set<number>,
): { items: PersistedCapture[]; hasMore: boolean } {
  const fd = openSync(filePath, 'r');
  try {
    const size = fstatSync(fd).size;
    if (size <= 0) return { items: [], hasMore: false };
    const beforeId = q.beforeId != null && Number.isFinite(q.beforeId) ? q.beforeId : null;
    const fromTs = q.fromTs != null && Number.isFinite(q.fromTs) ? q.fromTs : null;
    const toTs = q.toTs != null && Number.isFinite(q.toTs) ? q.toTs : null;
    const since = q.since && q.since > 0 ? q.since : 0;
    const want = Math.max(1, q.limit) + 1;

    let pos = narrowUpperOffset(fd, size, beforeId, toTs);
    let carry: Buffer = Buffer.alloc(0);
    const buf = Buffer.allocUnsafe(REV_CHUNK);
    const rev: PersistedCapture[] = [];
    let stopEarly = false;

    while (pos > 0 && !stopEarly) {
      const readLen = Math.min(REV_CHUNK, pos);
      pos -= readLen;
      const got = readSync(fd, buf, 0, readLen, pos);
      if (got <= 0) break;
      const slice = buf.subarray(0, got);
      const combined = carry.length ? Buffer.concat([slice, carry]) : slice;
      let body: Buffer;
      if (pos > 0) {
        const firstNl = combined.indexOf(10);
        if (firstNl < 0) { carry = Buffer.from(combined); continue; }
        carry = Buffer.from(combined.subarray(0, firstNl));
        body = combined.subarray(firstNl + 1);
      } else {
        body = combined;
        carry = Buffer.alloc(0);
      }
      const lines = body.toString('utf8').split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i];
        if (!line) continue;
        let c: PersistedCapture;
        try { c = JSON.parse(line) as PersistedCapture; } catch { continue; }
        if (!c || typeof c.id !== 'number') continue;
        if (deleted.size && deleted.has(c.id)) continue;
        if (beforeId != null && c.id >= beforeId) continue;
        if (toTs != null && c.ts > toTs) continue;
        if (since > 0 && c.id <= since) { stopEarly = true; break; }
        if (fromTs != null && c.ts < fromTs) { stopEarly = true; break; }
        if (q.session && c.sessionId !== q.session) continue;
        if (catSet && !catSet.has(c.category)) continue;
        if (needle) {
          const hay = `${c.algo || ''} ${c.op || ''} ${c.func || ''} ${c.path || ''} ${c.preview || ''}`.toLowerCase();
          if (!hay.includes(needle)) continue;
        }
        if (!c.package) c.package = pkgName;
        if (!captureMatchesScope(c)) continue;
        rev.push(c);
        if (rev.length >= want) { stopEarly = true; break; }
      }
    }
    const hasMore = rev.length > q.limit;
    if (hasMore) rev.length = q.limit;
    rev.reverse();
    return { items: rev, hasMore };
  } finally {
    closeSync(fd);
  }
}

/** Reverse-paged query over persisted captures.jsonl files (bounded I/O via binary-offset narrow + reverse chunks). */
export function queryPersistedCapturesPage(
  dataDir: string,
  q: CapturePageQuery,
): { items: PersistedCapture[]; hasMore: boolean } | null {
  const catSet = q.categories && q.categories.length ? new Set(q.categories) : null;
  const needle = (q.q ?? '').trim().toLowerCase();
  if (q.package) {
    const path = packageCapturesPath(dataDir, q.package);
    if (!path || !existsSync(path)) return null;
    return scanOneFilePage(path, q.package, q, catSet, needle, deletedCaptureIds(dataDir, q.package));
  }
  const root = join(dataDir, 'packages');
  if (!existsSync(root)) return null;
  const merged: PersistedCapture[] = [];
  let anyMore = false;
  for (const name of readdirSync(root)) {
    if (!safePackageDirName(name)) continue;
    const path = join(root, name, 'captures.jsonl');
    if (!existsSync(path)) continue;
    const sub = scanOneFilePage(path, name, q, catSet, needle, deletedCaptureIds(dataDir, name));
    if (sub.hasMore) anyMore = true;
    merged.push(...sub.items);
  }
  if (!merged.length && !anyMore) return null;
  merged.sort((a, b) => a.id - b.id || a.ts - b.ts);
  const hasMore = anyMore || merged.length > q.limit;
  return { items: merged.slice(-q.limit), hasMore };
}

/** Lookup a single capture record by id on disk when it has been evicted from the bounded in-memory window. */
export function findPersistedCaptureById(dataDir: string, id: number, pkg?: string): PersistedCapture | null {
  if (!Number.isFinite(id) || id <= 0) return null;
  const candidates: { name: string; path: string }[] = [];
  if (pkg) {
    const p = packageCapturesPath(dataDir, pkg);
    if (p && existsSync(p)) candidates.push({ name: pkg, path: p });
  }
  const root = join(dataDir, 'packages');
  if (existsSync(root)) {
    for (const name of readdirSync(root)) {
      if (name === pkg || !safePackageDirName(name)) continue;
      const p = join(root, name, 'captures.jsonl');
      if (existsSync(p)) candidates.push({ name, path: p });
    }
  }
  for (const { name, path } of candidates) {
    const deleted = deletedCaptureIds(dataDir, name);
    if (deleted.size && deleted.has(id)) continue;
    const page = scanOneFilePage(path, name, { beforeId: id + 1, since: id - 1, limit: 1 }, null, '', deleted);
    if (page.items.length && page.items[0].id === id) return page.items[0];
  }
  return null;
}

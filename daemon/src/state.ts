// state.ts — ADH Daemon shared state + leaf mutators.
// Pure state holder: imports NOTHING from service.ts/mcp.ts/index.ts (no circular refs).
// Imported by everyone. Everything that holds runtime state or is a leaf helper lives here;
// functions that issue agent commands (sendCmd/capture loop/unpack/dump) live in service.ts.
import net from 'node:net';
import type { IncomingMessage } from 'node:http';
import { mkdirSync, writeFileSync, existsSync, appendFileSync, readFileSync, readdirSync, statSync, unlinkSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import { artifactKindOf, planArtifactEviction } from './artifacts.ts';
import type { ArtifactEntry } from './artifacts.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const CAPTURES = join(__dirname, '..', '..', 'captures');
mkdirSync(CAPTURES, { recursive: true });

// ---- wire framing (v2.0, WS-D): [u32 len BE][u8 type][payload] -------------
// Control/cmd/cmdResult ride as FRAME_JSON; binary/bulk types reserved for later
// (capture batch, chunked dump). Fail-loud on oversized/unknown. Shared by sendCmd
// (encode, service.ts) and the agent TCP server (decode, index.ts).
export const FRAME_JSON = 0x01;
export const FRAME_MAX = 64 * 1024 * 1024;   // inbound payload cap; beyond → close (corrupt stream)
export function frameJson(obj: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const hdr = Buffer.allocUnsafe(5);
  hdr.writeUInt32BE(payload.length, 0);
  hdr.writeUInt8(FRAME_JSON, 4);
  return Buffer.concat([hdr, payload]);
}

// ---- types (erased at runtime) -------------------------------------------
export interface MapsRegion {
  start: string; end: string; perms: string; offset: string;
  dev: string; inode: number; path: string;
}
export interface AgentSession {
  sessionId: string;
  pid: number;
  uid: number;
  package: string;
  process: string;
  abi: string;
  android: string;
  sdk: number;
  entry: string;
  agentVer: string;
  // Own-image identity reported by the agent itself (dladdr): with the Zygisk memfd loader the
  // module has no path on disk, so this is the only per-session proof of HOW the agent is mapped
  // ("/memfd:jit-cache (deleted)" vs "/data/adb/modules/adh/libadh_agent.so").
  selfModule?: string;
  selfBase?: string;
  connectedAt: number;
  lastSeen: number;
  online: boolean;
  mapsCount: number;
  regionsSample: MapsRegion[];
  // Last capture_start/capture_stop reply from the agent (per-hook install counters:
  // evp/digest/hmac/pkey/aead/file/sys). Without it "capture_start returned ok" is the
  // only visible signal for whether the persistent hooks actually installed.
  captureHooks?: Record<string, any>;
}
export type AgentMsg =
  | ({ t: 'hello' } & Partial<AgentSession>)
  | { t: 'maps'; count: number; regions?: MapsRegion[] }
  | { t: 'ping'; ts?: number }
  | { t: 'cmdResult'; id: string; op: string; ok: boolean; [k: string]: unknown };

export interface DumpMeta {
  sha256: string; size: number; source: string; addr: string;
  tag: string; sessionId: string; package: string; capturedAt: number;
  path: string; kind: string;   // dex|so|region|... inferred from magic
  // Completeness (v4.91). `size` is what actually landed on disk; `requestedSize` is what the
  // caller asked for and `complete` says whether they match. A short dump is still an artifact
  // worth keeping - it just must not look like the whole region.
  requestedSize?: number;
  complete?: boolean;
  /** Free-form caveat, e.g. that a reassembled .so is not byte-exact. */
  note?: string;
}

// ---- registry ------------------------------------------------------------
export const sessions = new Map<string, AgentSession>();

// Session hygiene. Every app restart dials in as a NEW session and the map was never pruned —
// one afternoon of testing left 20 dead entries in the Web UI picker. Keep the recent past only:
// per package at most OFFLINE_KEEP_PER_PACKAGE offline sessions, never anything older than
// OFFLINE_RETENTION_MS. Online sessions are never touched here.
export const OFFLINE_RETENTION_MS = 10 * 60_000;
export const OFFLINE_KEEP_PER_PACKAGE = 2;

/** Drops stale offline sessions; returns the sessionIds it removed (for logging/tests). */
export function pruneSessions(now = Date.now()): string[] {
  const byPackage = new Map<string, AgentSession[]>();
  for (const s of sessions.values()) {
    if (s.online) continue;
    const list = byPackage.get(s.package) ?? [];
    list.push(s);
    byPackage.set(s.package, list);
  }
  const dropped: string[] = [];
  for (const list of byPackage.values()) {
    list.sort((a, b) => b.connectedAt - a.connectedAt);   // newest first
    list.forEach((s, index) => {
      const age = now - Math.max(s.lastSeen, s.connectedAt);
      if (index >= OFFLINE_KEEP_PER_PACKAGE || age > OFFLINE_RETENTION_MS) dropped.push(s.sessionId);
    });
  }
  for (const id of dropped) {
    sessions.delete(id);
    // The per-session capture accounting dies with the session. Without this the map grows for
    // every app restart (measured 2026-10-01: 91 entries in one gate run) - and while the health
    // aggregate only counts LIVE sessions, keeping thousands of dead ones around is pure leak.
    // Sessions kept as history (OFFLINE_KEEP_PER_PACKAGE / OFFLINE_RETENTION_MS) keep theirs too,
    // so the "what did that session leave behind" question is still answerable for a while.
    capStats.delete(id);
    captureSessionCounters.delete(id);
  }
  return dropped;
}
export const dumps = new Map<string, DumpMeta>();                        // sha256 -> meta (dedup)
export const agentSockets = new Map<string, net.Socket>();               // sessionId -> live socket
export const pending = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
export let seq = 0;
export let cmdSeq = 0;
export const nextId = () => `s_${(++seq).toString(36)}${Date.now().toString(36).slice(-3)}`;
export const nextCmdId = () => `c${(++cmdSeq).toString(36)}`;

// ---- event store (session record/replay) ---------------------------------
const _dataRoot = join(__dirname, '..', '..');
// Where artifacts, the event log, settings and the dex index live. Overridable because this tree is
// worked from a SHARED SMB folder, and that is a bad home for a SQLite database: measured
// 2026-09-30, `adhd-data/dex-index.sqlite` came back SQLITE_CORRUPT while the same tree was open on
// two machines, and on SMB the corrupt file could not even be renamed away from Linux (`mv` →
// "device or resource busy") because the other host still held it. Point ADH_DATA_DIR at local disk
// on any machine sharing this checkout. Default is unchanged for single-machine use.
export const DATA_DIR = process.env.ADH_DATA_DIR ?? join(_dataRoot, 'adhd-data');
mkdirSync(DATA_DIR, { recursive: true });
export const EVENTS_FILE = join(DATA_DIR, 'events.jsonl');
interface Ev { seq: number; ts: number; type: string; data: any }
export const events: Ev[] = [];
export let evSeq = 0;
try {   // replay: load persisted events on startup so a session survives restarts
  if (existsSync(EVENTS_FILE)) {
    const lines = readFileSync(EVENTS_FILE, 'utf8').split('\n').filter(Boolean).slice(-5000);
    let corrupt = 0;
    for (const l of lines) { try { const e = JSON.parse(l); events.push(e); if (e.seq > evSeq) evSeq = e.seq; } catch { corrupt++; } }
    if (corrupt) log(`[events] replay: ${corrupt}/${lines.length} 行损坏已跳过 (${EVENTS_FILE})`);
  }
} catch (e) { log(`[events] replay 失败 (${EVENTS_FILE}) — 从空事件起步:`, (e as Error).message); }
export function recordEvent(type: string, data: any) {
  const e: Ev = { seq: ++evSeq, ts: Date.now(), type, data };
  events.push(e); if (events.length > 5000) events.shift();
  try { appendFileSync(EVENTS_FILE, JSON.stringify(e) + '\n'); }
  catch (err) { log(`[events] 持久化失败 (${EVENTS_FILE}):`, (err as Error).message); }
}

// ---- user settings (persisted; tunable from the web 设置 panel; ADH-style) --------
// Only touches the ADH Daemon / web layer — the agent .so is never reconfigured from here.
export const SETTINGS_FILE = join(DATA_DIR, 'settings.json');
export interface Settings {
  capture: { enabled: boolean; autoDumpDex: boolean; retain: number; families: Record<string, boolean>; cryptoModule: string; fileModule: string; sysModule: string };
  ui: { displayCap: number };
  // On-disk artifact retention (captures/). `capture.retain` above only bounds the in-memory
  // capture list; the files themselves used to grow without limit (one packed-app run left ~1.1 GB).
  // maxAgeDays = 0 disables the age rule; the size budget still applies.
  artifacts: { maxBytes: number; maxAgeDays: number };
}
export const DEFAULT_SETTINGS: Settings = {
  // cryptoModule: which module's GOT holds the EVP/SSL calls the agent hooks. The agent bakes
  // in NO module name (target-agnostic); this value drives it. Default 'libjavacrypto.so' =
  // Conscrypt, the app-level JCE/TLS path present in every app — safe and isolated from
  // framework internals. Set '' to scan ALL file-backed modules (advanced: catches cronet's
  // bundled BoringSSL / renamed libs, but also hooks framework crypto on the main thread during
  // init and can destabilize startup — opt in per target, don't use as the default).
  // fileModule/sysModule: which loaded module's GOT the persistent file(open/read/…) and
  // system(ptrace/access/getprop) hooks patch. Defaults are the sandbox-backing modules for
  // self-test; override per real target (empty string = don't install that category's hooks).
  capture: { enabled: true, autoDumpDex: true, retain: 1000, families: { digest: true, hmac: true, symmetric: true, asymmetric: true, tls: true, aead: true }, cryptoModule: 'libjavacrypto.so', fileModule: 'libjavacore.so', sysModule: 'libadhdetect.so' },
  ui: { displayCap: 300 },
  artifacts: { maxBytes: 8 * 1024 ** 3, maxAgeDays: 14 },
};
export let settings: Settings = JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
// section-merge (like IDH /api/settings/import): only the segments present in `patch` apply.
export function mergeSettings(patch: any): string[] {
  const applied: string[] = [];
  if (!patch || typeof patch !== 'object') return applied;
  if (patch.capture && typeof patch.capture === 'object') {
    const c = patch.capture;
    if (typeof c.enabled === 'boolean') settings.capture.enabled = c.enabled;
    if (typeof c.autoDumpDex === 'boolean') settings.capture.autoDumpDex = c.autoDumpDex;
    if (Number.isFinite(c.retain)) settings.capture.retain = Math.max(50, Math.min(100000, Math.floor(c.retain)));
    if (typeof c.cryptoModule === 'string') settings.capture.cryptoModule = c.cryptoModule.trim();
    if (typeof c.fileModule === 'string') settings.capture.fileModule = c.fileModule.trim();
    if (typeof c.sysModule === 'string') settings.capture.sysModule = c.sysModule.trim();
    if (c.families && typeof c.families === 'object')
      for (const k of Object.keys(settings.capture.families))
        if (typeof c.families[k] === 'boolean') settings.capture.families[k] = c.families[k];
    applied.push('capture');
  }
  if (patch.ui && typeof patch.ui === 'object') {
    if (Number.isFinite(patch.ui.displayCap)) settings.ui.displayCap = Math.max(50, Math.min(5000, Math.floor(patch.ui.displayCap)));
    applied.push('ui');
  }
  if (patch.artifacts && typeof patch.artifacts === 'object') {
    const a = patch.artifacts;
    if (Number.isFinite(a.maxBytes)) settings.artifacts.maxBytes = Math.max(256 * 1024 ** 2, Math.min(512 * 1024 ** 3, Math.floor(a.maxBytes)));
    if (Number.isFinite(a.maxAgeDays)) settings.artifacts.maxAgeDays = Math.max(0, Math.min(365, Math.floor(a.maxAgeDays)));
    applied.push('artifacts');
  }
  return applied;
}
// Load persisted settings. Fail LOUD: if the file is present but corrupt/unreadable we must not
// silently run on defaults (that masks lost config as "working"). Absent file is normal (defaults).
try {
  if (existsSync(SETTINGS_FILE)) mergeSettings(JSON.parse(readFileSync(SETTINGS_FILE, 'utf8')));
} catch (e) {
  log(`[settings] ${SETTINGS_FILE} 载入失败，已回退默认值 — 磁盘上的配置未生效:`, (e as Error).message);
}
// Persist. Throws on failure — callers MUST surface it so the UI never claims "已保存" on a failed write.
export function saveSettings() { writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2)); }

// ---- on-disk artifact store --------------------------------------------------------------
// Adopt artifacts that are already on disk into the runtime map.
//
// Without this the map is empty after a restart: `dumps_list` / `/api/dumps` / download-by-sha /
// `dex_index` all report "nothing here" while the bytes sit in captures/ — the artifacts survive,
// only the daemon forgot them. The session, address and tag that produced a file are NOT on disk;
// they are labelled 'disk-reload' rather than guessed, so nothing downstream reads a fabricated
// provenance.
export function loadArtifactsFromDisk(): { loaded: number; skipped: number; bytes: number; ms: number } {
  const t0 = Date.now();
  let loaded = 0, skipped = 0, bytes = 0;
  let names: string[];
  try { names = readdirSync(CAPTURES); }
  catch (e) {
    log(`[artifacts] 扫描 ${CAPTURES} 失败 — 磁盘上的工件本次不可见:`, (e as Error).message);
    return { loaded: 0, skipped: 0, bytes: 0, ms: Date.now() - t0 };
  }
  const chunk = Buffer.allocUnsafe(1 << 20);       // hashing streams: a dump can be 100 MB+
  for (const name of names) {
    const kind = artifactKindOf(name);
    if (!kind) { skipped++; continue; }
    const path = join(CAPTURES, name);
    try {
      const st = statSync(path);
      if (!st.isFile()) { skipped++; continue; }
      const h = createHash('sha256');
      const fd = openSync(path, 'r');
      try { let n: number; while ((n = readSync(fd, chunk, 0, chunk.length, null)) > 0) h.update(chunk.subarray(0, n)); }
      finally { closeSync(fd); }
      const sha = h.digest('hex');
      if (dumps.has(sha)) { skipped++; continue; }   // already adopted (or produced this session)
      dumps.set(sha, {
        sha256: sha, size: st.size, source: 'disk-reload', addr: '', tag: 'disk-reload',
        sessionId: '', package: '', capturedAt: Math.round(st.mtimeMs), path, kind,
        requestedSize: st.size, complete: true,
      });
      loaded++; bytes += st.size;
    } catch (e) { skipped++; log(`[artifacts] 跳过 ${name}:`, (e as Error).message); }
  }
  return { loaded, skipped, bytes, ms: Date.now() - t0 };
}

// Enforce `settings.artifacts` against the real store (policy: planArtifactEviction).
// A file that cannot be unlinked stays in the map — the map has to keep describing what is actually
// on disk, so a failed delete is reported rather than quietly forgotten.
// `onDelete` lets a caller drop related state it owns (the dex index row) without state.ts having to
// import the indexer, which would be a cycle (dex_index.ts imports this file).
export function pruneArtifacts(onDelete?: (sha: string) => void, protectSha?: string): { removed: number; bytesFreed: number; remainingBytes: number; kept: number; failed: number } {
  const mtimeOf = (p: string) => { try { return Math.round(statSync(p).mtimeMs); } catch { return 0; } };
  const entries: ArtifactEntry[] = [...dumps.values()].map((m) => ({
    sha256: m.sha256, path: m.path, size: Number(m.size) || 0,
    mtime: mtimeOf(m.path) || Number(m.capturedAt) || 0,
  }));
  const plan = planArtifactEviction(entries, settings.artifacts, Date.now(), protectSha);
  let removed = 0, bytesFreed = 0, failed = 0;
  for (const e of plan.evict) {
    try { unlinkSync(e.path); }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        failed++; log(`[artifacts] 删除失败，保留记账 ${e.path}:`, (err as Error).message); continue;
      }
    }
    dumps.delete(e.sha256); onDelete?.(e.sha256);
    removed++; bytesFreed += e.size;
  }
  return { removed, bytesFreed, remainingBytes: plan.remainingBytes, kept: dumps.size, failed };
}

{ // re-adopt what is already on disk (see loadArtifactsFromDisk)
  const a = loadArtifactsFromDisk();
  if (a.loaded || a.skipped) log(`[artifacts] 从磁盘恢复 ${a.loaded} 个工件（跳过 ${a.skipped}，${(a.bytes / 1048576).toFixed(1)} MiB，${a.ms}ms）`);
}
/** Retention accounting for the in-memory capture list. Pass a session for that session's view. */
export function captureStoreStats(session?: string) {
  if (session) {
    const c = captureSessionCounters.get(session) ?? { pushed: 0, evicted: 0 };
    const mine = captures.filter((x) => x.sessionId === session);
    return { pushed: c.pushed, evicted: c.evicted, retained: mine.length,
      retain: settings.capture.retain, oldestTs: mine.length ? Number(mine[0].ts ?? 0) : 0,
      oldestId: mine.length ? Number(mine[0].id ?? 0) : 0 };
  }
  return { pushed: capturePushed, evicted: captureEvicted, retained: captures.length,
    retain: settings.capture.retain, oldestTs: captures.length ? Number(captures[0].ts ?? 0) : 0,
    oldestId: captures.length ? Number(captures[0].id ?? 0) : 0 };
}

/**
 * A note for any digest that filters the store by session and window: when that session had
 * records evicted and the requested window reaches back past the oldest retained record, the
 * window may be missing events. Returns null when nothing was lost or the window is intact.
 */
export function storeLossNote(session: string, window: { sinceMs?: number | null; sinceCaptureId?: number | null } = {}): string | null {
  const s = captureStoreStats(session);
  if (s.evicted <= 0) return null;
  // The window is intact when the oldest retained record still precedes what was asked for.
  if (window.sinceMs != null && s.oldestTs > 0 && s.oldestTs <= window.sinceMs) return null;
  if (window.sinceCaptureId != null && s.oldestId > 0 && s.oldestId <= window.sinceCaptureId) return null;
  return `capture store: ${s.evicted} record(s) of this session were evicted (retain ${s.retain}) - the requested window may be missing events`;
}

/** On-disk artifact accounting, so retention is observable instead of a silent background rule. */
export function artifactStats() {
  let bytes = 0;
  for (const m of dumps.values()) bytes += Number(m.size) || 0;
  return { count: dumps.size, bytes, maxBytes: settings.artifacts.maxBytes, maxAgeDays: settings.artifacts.maxAgeDays };
}
export function configStats() { return { captures: captures.length, dumps: dumps.size, events: events.length, on: captureTimers.size > 0, agents: sessions.size, capture: captureHealth(), artifacts: artifactStats() }; }
// Which crypto family a capture belongs to (mirrors cryptoIdentify's buckets) — used by the
// Daemon-side family filter (panel-level; the agent still hooks everything).
export function familyOf(algo: string): 'tls' | 'asymmetric' | 'hmac' | 'digest' | 'symmetric' | 'aead' {
  if (/TLS/.test(algo)) return 'tls';
  if (/AEAD/i.test(algo)) return 'aead';
  if (/RSA|(^|[^m])EC[^B]|ECDSA|DSA/i.test(algo)) return 'asymmetric';
  if (/Hmac|HMAC/i.test(algo)) return 'hmac';
  if (/MD5|SHA|摘要|Digest/i.test(algo)) return 'digest';
  return 'symmetric';
}
// Store a capture honoring the family filter + retention cap. Returns false if filtered out.
// The family filter is a crypto-panel control only — net/file/system captures bypass it
// (their algo doesn't map to a crypto family, so familyOf would misclassify them).
export function pushCapture(entry: Capture): boolean {
  if (entry.category === 'crypto' && settings.capture.families[familyOf(entry.algo)] === false) return false;
  captures.push(entry);
  capturePushed++;
  bumpSession(entry.sessionId, 'pushed');
  while (captures.length > settings.capture.retain) {
    const dropped = captures.shift();
    captureEvicted++;
    if (dropped) bumpSession(dropped.sessionId, 'evicted');
  }
  return true;
}
// The persistent-hook target modules the agent should use. Sent with every capture_start so
// the agent stays target-agnostic (no hardcoded modules). The Java rich-capture reporter class
// is published by the TARGET via the "adh.reporter.class" system property (bound at JNI_OnLoad),
// not passed here — it must be bound before the target's JCE provider fires, i.e. before connect.
export function captureModules() { return { cryptoModule: settings.capture.cryptoModule, fileModule: settings.capture.fileModule, sysModule: settings.capture.sysModule }; }

// ---- live capture store: what the agent's persistent hooks stream in (the panel's
//      加解密 list reads this; it auto-populates without any button click) -------------
export type CapCategory = 'crypto' | 'net' | 'file' | 'system';
export interface Capture {
  id: number; sessionId: string; source: 'java' | 'native'; func: string; algo: string; op: string;
  category: CapCategory;
  inl: number; tid: number; tsNs: number; ts: number; hex: string; preview: string;
  keyHex?: string; ivHex?: string; outHex?: string;
}
export const captures: Capture[] = [];
// Store accounting (v4.93): the in-memory list is capped by settings.capture.retain, and an
// evicted record is gone for every digest that runs later. Counting pushes and evictions lets
// a digest admit that its window may be missing events instead of looking complete.
let capturePushed = 0;
let captureEvicted = 0;
// Per session as well: the store is one FIFO across sessions, so a digest that filters by
// session cannot read the global eviction counter and expect it to describe its own window.
const captureSessionCounters = new Map<string, { pushed: number; evicted: number }>();
function bumpSession(sessionId: string | undefined, field: 'pushed' | 'evicted'): void {
  if (!sessionId) return;
  const cur = captureSessionCounters.get(sessionId) ?? { pushed: 0, evicted: 0 };
  cur[field]++;
  captureSessionCounters.set(sessionId, cur);
}
// capSeq lives in service.ts — it's ++'d inside startCaptureLoop there, and ESM imported
// bindings are read-only for the importer (can't reassign from another module). It's only
// used by the capture loop, so it's a service-local counter, not shared state.
export const recentJavaIn = new Map<string, number>();   // input-hex -> ts, to dedup native echoes
export const captureTimers = new Map<string, ReturnType<typeof setInterval>>();
// WS-C: per-session honest capture accounting from the agent ring's capture_drain stats.
// seq/dropped/jdropped are CUMULATIVE IN THE AGENT PROCESS, while emitted counts only what THIS
// daemon session ingested — so the raw numbers cannot be compared directly after a daemon restart
// or an agent reconnect (the gap is permanent and reads as silent loss; measured 3455 records on
// 2026-10-01). base* is the snapshot taken with the session's FIRST drain response, and HEALTH IS
// REPORTED RELATIVE TO IT: the window is "since this daemon started watching", where the identity
// below is true. The raw agent counters are kept in `baseline` so nothing is hidden.
export interface CapStat {
  seq: number; emitted: number; dropped: number; jdropped: number; backlog: number;
  /** Cumulative records the AGENT has popped out of its ring (its own counter). */
  drained: number;
  /** The AGENT's own identity residual (seq - drained - backlog - dropped) as it reported it in
   *  the last drain reply. Compared against agentLost below: if the agent says 0 while the daemon
   *  computes non-zero, the divergence is in the daemon's accounting, not in the ring. */
  agentResidual?: number | null;
  firstDropNs: number; lastDropNs: number; complete: boolean; ring: number; ts: number; announcedDrop?: boolean;
  base?: { seq: number; dropped: number; jdropped: number; drained: number; emitted: number };
}
export const capStats = new Map<string, CapStat>();
// Aggregate drop accounting across sessions — complete:false the moment anything dropped.
// The invariant emitted + backlog + dropped === seq holds per session, for the session window.
export function captureHealth() {
  // AGGREGATE OVER LIVE SESSIONS ONLY, and say so. A session that ends while its last drain
  // snapshot happened to catch a producer between "counted the attempt" and "the outcome"
  // (insert / drop) freezes with a residual of a few records, and no later drain can resolve it -
  // the agent's counters are cumulative and the sample was taken mid-flight. Summing those
  // forever-stale residues over a long run (the gate restarts the app per script) turned a
  // handful of in-flight records into thousands and made verify_v22 read as a silent loss.
  // The health object answers "how is the ring doing RIGHT NOW"; the stale side is reported
  // separately instead of being folded in or hidden.
  const liveIds = new Set([...sessions.values()].filter((s) => s.online).map((s) => s.sessionId));
  let seq = 0, emitted = 0, dropped = 0, jdropped = 0, backlog = 0; let complete = true;
  let baseSeq = 0, baseDropped = 0, agentResidual = 0, staleResidual = 0, staleSessions = 0;
  for (const [sid, s] of capStats.entries()) {
    const b = s.base ?? { seq: s.seq, dropped: s.dropped, jdropped: s.jdropped, drained: s.drained, emitted: s.emitted };
    if (!liveIds.has(sid)) {
      staleSessions++;
      staleResidual += Math.max(0, (s.seq - b.seq) - (s.drained - b.drained) - s.backlog - (s.dropped - b.dropped));
      continue;
    }
    seq += Math.max(0, s.seq - b.seq);
    dropped += Math.max(0, s.dropped - b.dropped);
    jdropped += Math.max(0, s.jdropped - b.jdropped);
    emitted += Math.max(0, s.emitted - b.emitted);
    backlog += s.backlog;
    baseSeq += b.seq; baseDropped += b.dropped;
    agentResidual += Number(s.agentResidual ?? 0);
    if (!s.complete) complete = false;
  }
  // Two DIFFERENT residuals, deliberately separated (a single "unaccounted" hid which side lost what):
  //   agentLost  - the agent's own identity (seq == drained + backlog + dropped) failed for a LIVE
  //                session: records left its ring without being popped, counted as dropped, or
  //                still in the ring.
  //   daemonLost - the agent popped them (it says so via `drained`) but this daemon never ingested
  //                them: a drain response that never reached processDrain (timeout/socket error).
  let agentLost = 0, daemonLost = 0;
  for (const [sid, s] of capStats.entries()) {
    if (!liveIds.has(sid)) continue;
    const b = s.base ?? { seq: s.seq, dropped: s.dropped, jdropped: s.jdropped, drained: s.drained, emitted: s.emitted };
    const dSeq = Math.max(0, s.seq - b.seq), dDropped = Math.max(0, s.dropped - b.dropped);
    const dDrained = Math.max(0, s.drained - b.drained), dEmitted = Math.max(0, s.emitted - b.emitted);
    agentLost += Math.max(0, dSeq - dDrained - s.backlog - dDropped);
    daemonLost += Math.max(0, dDrained - dEmitted);
  }
  const accountedFor = emitted + backlog + dropped;
  return { seq, emitted, dropped, jdropped, backlog, complete, accountedFor,
    unaccounted: Math.max(0, seq - accountedFor), agentLost, daemonLost,
    agentResidual, staleSessions, staleResidual, sessions: capStats.size, liveSessions: capStats.size - staleSessions,
    baseline: { seq: baseSeq, dropped: baseDropped },
    window: 'live sessions only, since each session began being watched (agent counters are cumulative over its whole process)' };
}

export function hexToPreview(hex: string, max = 80): string {
  let s = '';
  for (let i = 0; i + 1 < hex.length && s.length < max; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16);
    s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
  }
  return s;
}
// Which UI axis a capture belongs to. Derived from the agent's func tag so the web can
// split the single stream into 加解密 / 网络 / 文件 / 系统 master-detail panels. The agent
// stamps func: EVP_*/HMAC_* (crypto), SSL_read/write (net), open*/read/write/close (file),
// ptrace/access/sysprop (system) — see cmd_capture_start.
export function categoryOf(func: string): CapCategory {
  if (func === 'JAVA_HOOK' || func === 'NATIVE_HOOK' || func === 'JNI_NATIVE' || func === 'JNI_ONLOAD' || func === 'JNI_ENV') return 'system';
  if (func === 'SSL_write' || func === 'SSL_read') return 'net';
  if (/^(open|openat|read|write|close)$/.test(func)) return 'file';
  if (/^(ptrace|access|sysprop|__system_property_get|getprop)$/.test(func)) return 'system';
  return 'crypto';
}
export function classify(func: string): { algo: string; op: string } {
  if (func === 'JAVA_HOOK') return { algo: 'Java Hook', op: '方法调用' };
  if (func === 'NATIVE_HOOK') return { algo: 'Native Hook', op: '函数调用' };
  if (func === 'JNI_NATIVE') return { algo: 'JNI Hook', op: 'RegisterNatives' };
  if (func === 'JNI_ONLOAD') return { algo: 'JNI Hook', op: 'JNI_OnLoad' };
  if (func === 'JNI_ENV') return { algo: 'JNI Hook', op: 'JNIEnv' };
  if (func.startsWith('EVP_Cipher') || func.startsWith('EVP_Encrypt') || func.startsWith('EVP_Decrypt'))
    return { algo: '对称加解密', op: '明文' };
  if (func === 'HMAC_Update' || func === 'EVP_DigestSignUpdate' || func === 'EVP_DigestVerifyUpdate') return { algo: 'HMAC', op: '消息' };
  // EVP_DigestSign/VerifyUpdate+Final also serve JCA Signature (RSA/EC) on this BoringSSL build —
  // the agent disambiguates via EVP_PKEY_id() at Init time and tags the asymmetric case distinctly
  // (see agent_main.c dsign_ctx_* — real call path for Conscrypt's SHA256withECDSA, not ECDSA_sign).
  if (func === 'EVP_DSignUpdate_asym')   return { algo: 'RSA/EC 签名', op: '待签名数据' };
  if (func === 'EVP_DSignFinal_sig')     return { algo: 'RSA/EC 签名', op: '签名结果' };
  if (func === 'EVP_DVerifyUpdate_asym') return { algo: 'RSA/EC 验签', op: '待验签数据' };
  if (func === 'EVP_DVerifyFinal_sig')   return { algo: 'RSA/EC 验签', op: '签名值' };
  if (func.startsWith('EVP_Digest')) return { algo: '摘要 Digest', op: '输入' };
  if (func === 'SSL_write') return { algo: 'TLS', op: '发送明文' };
  if (func === 'SSL_read') return { algo: 'TLS', op: '接收明文' };
  if (func === 'openat' || func === 'open') return { algo: '文件', op: '打开' };
  if (func === 'read') return { algo: '文件', op: '读取' };
  if (func === 'write') return { algo: '文件', op: '写入' };
  if (func === 'close') return { algo: '文件', op: '关闭' };
  if (func === 'ptrace') return { algo: 'ptrace', op: '反调试检测' };
  if (func === 'access') return { algo: 'access', op: '路径探测' };
  if (func === 'sysprop' || func === '__system_property_get') return { algo: '系统属性', op: '读取手机信息' };
  if (func === 'ECDSA_sign_digest')    return { algo: 'RSA/EC 签名', op: '待签名数据' };
  if (func === 'ECDSA_sign_sig')       return { algo: 'RSA/EC 签名', op: '签名结果' };
  if (func === 'ECDSA_verify_digest')  return { algo: 'RSA/EC 验签', op: '待验签数据' };
  if (func === 'ECDSA_verify_sig')     return { algo: 'RSA/EC 验签', op: '签名值' };
  if (func === 'EVP_PKEY_encrypt_in')  return { algo: 'RSA 非对称加密', op: '明文输入' };
  if (func === 'EVP_PKEY_encrypt_out') return { algo: 'RSA 非对称加密', op: '密文输出' };
  if (func === 'EVP_PKEY_decrypt_in')  return { algo: 'RSA 非对称解密', op: '密文输入' };
  if (func === 'EVP_PKEY_decrypt_out') return { algo: 'RSA 非对称解密', op: '明文输出' };
  if (func === 'EVP_AEAD_seal_pt' || func === 'EVP_AEAD_seal_ct')
    return { algo: 'AEAD 加密(GCM/ChaCha20-Poly1305)', op: func === 'EVP_AEAD_seal_pt' ? '明文' : '密文+Tag' };
  if (func === 'EVP_AEAD_open_ct' || func === 'EVP_AEAD_open_pt')
    return { algo: 'AEAD 解密(GCM/ChaCha20-Poly1305)', op: func === 'EVP_AEAD_open_ct' ? '密文+Tag' : '明文' };
  return { algo: func, op: '捕获' };
}

// Plain-language crypto identification — turns raw captures into "this app uses X" so a
// colleague who can't reverse can read off the algorithms/keys/IVs at a glance (axis 1).
export function cryptoIdentify() {
  const byAlgo = new Map<string, { algo: string; op: string; count: number; source: string; keyHex?: string; ivHex?: string; sampleId?: number; samplePlain?: string }>();
  for (const c of captures) {
    const key = c.algo + '|' + c.op;
    const e = byAlgo.get(key) ?? { algo: c.algo, op: c.op, count: 0, source: c.source };
    e.count++;
    if (c.keyHex && !e.keyHex) e.keyHex = c.keyHex;
    if (c.ivHex && !e.ivHex) e.ivHex = c.ivHex;
    if (!e.sampleId) { e.sampleId = c.id; e.samplePlain = hexToPreview(c.hex, 48); }
    byAlgo.set(key, e);
  }
  const algorithms = [...byAlgo.values()].sort((a, b) => b.count - a.count);
  const families = { symmetric: 0, asymmetric: 0, digest: 0, hmac: 0, tls: 0, aead: 0 };
  for (const a of algorithms) {
    if (/TLS/.test(a.algo)) families.tls += a.count;
    else if (/AEAD/i.test(a.algo)) families.aead += a.count;
    else if (/RSA|(^|[^m])EC[^B]|ECDSA|DSA/i.test(a.algo)) families.asymmetric += a.count;
    else if (/Hmac|HMAC/i.test(a.algo)) families.hmac += a.count;
    else if (/MD5|SHA|摘要|Digest/i.test(a.algo)) families.digest += a.count;
    else families.symmetric += a.count;
  }
  const withKey = algorithms.filter(a => a.keyHex).length;
  const summary = `捕获 ${captures.length} 次加密操作，涉及 ${algorithms.length} 种算法/用途；` +
    `其中 ${withKey} 种拿到了密钥。对称 ${families.symmetric} · 非对称 ${families.asymmetric} · 摘要 ${families.digest} · HMAC ${families.hmac} · TLS ${families.tls} · AEAD ${families.aead}。`;
  return { total: captures.length, families, algorithms, summary };
}

// ---- infra ---------------------------------------------------------------
export const wss = new WebSocketServer({ noServer: true });
export function broadcast(event: string, data: unknown) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  for (const c of wss.clients) if (c.readyState === WebSocket.OPEN) c.send(msg);
  if (event !== 'snapshot') recordEvent(event, data);   // persist for record/replay
}
export function log(...a: unknown[]) {
  console.log(`[adhd ${new Date().toISOString()}]`, ...a);
}
export function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c: Buffer) => (b += c));
    req.on('end', () => resolve(b));
  });
}

// state.ts — ADH Daemon shared state + leaf mutators.
// Pure state holder: imports NOTHING from service.ts/mcp.ts/index.ts (no circular refs).
// Imported by everyone. Everything that holds runtime state or is a leaf helper lives here;
// functions that issue agent commands (sendCmd/capture loop/unpack/dump) live in service.ts.
import net from 'node:net';
import type { IncomingMessage } from 'node:http';
import { mkdirSync, writeFileSync, existsSync, appendFileSync, readFileSync, readdirSync, statSync, unlinkSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';
import { artifactKindOf, artifactSidecarPath, parseArtifactProvenance, planArtifactEviction } from './artifacts.ts';
import type { ArtifactProvenance } from './artifacts.ts';
import type { ArtifactEntry } from './artifacts.ts';
import {
  appendCaptureLine, clearAllPersistedCaptures, clearPackagePersistedCaptures,
  enforcePerPackageRetain, evictPackageFromMemory, listPackageCaptureStats,
  loadCapturesFromDisk, pruneCapturesOlderThan, readPackageCapturesJsonl,
  trimPackageCapturesFile,
} from './capture_persist.ts';
import { memCapturePreview } from './native_hook_args.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
// The test runner gives every test FILE its own process (test/run.mjs sets ADH_SKIP_ARTIFACT_LOAD).
// Without a private root they all write the same captures/ and adhd-data/ files; on Windows a second
// writer makes the first fail with a sharing violation, which surfaced as a random test file failing
// at ~2.7s with fewer tests counted. Under the flag everything goes to OS temp instead of the checkout.
const _testRoot = process.env.ADH_SKIP_ARTIFACT_LOAD === '1' ? join(tmpdir(), `adh-test-${process.pid}`) : '';
export const CAPTURES = _testRoot ? join(_testRoot, 'captures') : join(__dirname, '..', '..', 'captures');
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
  // Per-package hook policy the agent holds for this process ("d=1,h=0,…", or "default" when the
  // scope file carried none). It is applied by the NEXT install, so the verdict that proves it —
  // `skipped` plus the per-family counters — arrives in the capture_start reply, i.e. in
  // captureHooks below (`captureHooks.skipped`). The agent cannot pre-empt it: it carries no module
  // name to arm with (see the note above adh_cmd_capture_start in agent/src/capture/capture.c).
  policy?: string;
  // What THIS build says it can do (hello + the `caps` frame right after it): every op it
  // dispatches plus the limits that decide whether a plan is feasible. Served verbatim by the
  // `capabilities` tool so a client plans from the running agent, not from a document.
  caps?: { ops?: string[]; limits?: Record<string, number>; error?: string };
  // Startup policy that actually ran for this session (see settings.startup). Present only when
  // the policy was enabled AND applied; the hookIds are what `recipe anti_debug undoHookIds`
  // needs, so a caller never has to guess which hooks the daemon installed by itself.
  startupHooks?: { appliedAt: number; module: string; hookIds: number[]; failed: { symbol: string; error: string }[]; widenedAt?: number };
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
  | { t: 'caps'; ops?: string[]; limits?: Record<string, number>; error?: string }
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

// Remember which app a dump belongs to. The file name only has 16 hex chars of the sha, so a
// restart used to adopt the bytes with an empty package and the Dump page then hid them behind
// the selected app. The sidecar is the recorded provenance, not a guess.
export function rememberDump(meta: DumpMeta): void {
  dumps.set(meta.sha256, meta);
  const prov: ArtifactProvenance = {
    sha256: meta.sha256, source: meta.source, addr: meta.addr, tag: meta.tag,
    sessionId: meta.sessionId, package: meta.package === '?' ? '' : (meta.package || ''),
    capturedAt: meta.capturedAt,
    ...(typeof meta.requestedSize === 'number' ? { requestedSize: meta.requestedSize } : {}),
    ...(typeof meta.complete === 'boolean' ? { complete: meta.complete } : {}),
    ...(meta.note ? { note: meta.note } : {}),
  };
  try { writeFileSync(artifactSidecarPath(meta.path), JSON.stringify(prov)); }
  catch (e) { log(`[artifacts] 来源未写入 ${meta.path}:`, (e as Error).message); }
}

function readDumpProvenance(path: string, sha: string): ArtifactProvenance | null {
  const side = artifactSidecarPath(path);
  try {
    if (!existsSync(side)) return null;
    return parseArtifactProvenance(JSON.parse(readFileSync(side, 'utf8')), sha);
  } catch (e) {
    log(`[artifacts] 来源读不了 ${side}:`, (e as Error).message);
    return null;
  }
}
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
export const DATA_DIR = process.env.ADH_DATA_DIR ?? (_testRoot ? join(_testRoot, 'adhd-data') : join(_dataRoot, 'adhd-data'));
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
  // retain = per-package cap for both the in-memory list and packages/<pkg>/captures.jsonl.
  // maxAgeDays = drop capture log lines older than this (0 = no age prune). enabled = auto-arm
  // when a session comes online; false = force-stop hooks on all online sessions.
  capture: { enabled: boolean; autoDumpDex: boolean; retain: number; maxAgeDays: number; families: Record<string, boolean>; cryptoModule: string; fileModule: string; sysModule: string };
  ui: { displayCap: number };
  // On-disk artifact retention (captures/ dump files). Capture event logs live under adhd-data/packages/.
  // maxAgeDays = 0 disables the age rule; the size budget still applies.
  artifacts: { maxBytes: number; maxAgeDays: number };
  // Startup policy: applied the moment a session's hello arrives, before the agent starts the
  // capture loop and before the host waits for any command round trip. This is the host-side
  // approximation of the Zygisk pre-arm: it loses to a check that runs in .init_array, but wins
  // over "someone types the command 30 seconds later". OFF by default because neutralizing
  // access()/faccessat() makes every path check in the app fail - a deliberate choice per target.
  startup: { antiDebug: boolean; module: string; extraTargets: string[]; packages: string[]; widenAfterMs: number; widenTargets: string[] };
}
export const DEFAULT_SETTINGS: Settings = {
  // cryptoModule: which module's GOT holds the EVP/SSL calls the agent hooks. The agent bakes
  // in NO module name (target-agnostic); this value drives it. Default 'libjavacrypto.so' =
  // Conscrypt, the app-level JCE/TLS path present in every app — safe and isolated from
  // framework internals. Set '' to scan ALL file-backed modules (advanced: catches cronet's
  // bundled BoringSSL / renamed libs, but also hooks framework crypto on the main thread during
  // init and can destabilize startup — opt in per target, don't use as the default).
  // fileModule/sysModule: which loaded module's GOT the persistent file(open/read/…) and
  // system(ptrace/access/getprop) hooks patch. Default '' = install NEITHER category: both are
  // per-target choices (file_probe reports which module actually imports the symbols), and the
  // MCP contract already says empty = don't hook. A module name that is not loaded in the target
  // installs nothing without failing, so a wrong default reads as "6 hooks silently missing" —
  // which is exactly what the sandbox-only defaults below used to do on every real app. The
  // sandbox self-test passes its own module explicitly (verify_v20_file.sh, verify_v05_detect.sh).
  capture: { enabled: true, autoDumpDex: true, retain: 1000, maxAgeDays: 14, families: { digest: true, hmac: true, symmetric: true, asymmetric: true, tls: true, aead: true }, cryptoModule: 'libjavacrypto.so', fileModule: '', sysModule: '' },
  ui: { displayCap: 300 },
  artifacts: { maxBytes: 8 * 1024 ** 3, maxAgeDays: 14 },
  startup: { antiDebug: false, module: 'libc.so', extraTargets: [], packages: [], widenAfterMs: 0, widenTargets: ['access', 'faccessat'] },
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
    if (Number.isFinite(c.maxAgeDays)) settings.capture.maxAgeDays = Math.max(0, Math.min(365, Math.floor(c.maxAgeDays)));
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
  if (patch.startup && typeof patch.startup === 'object') {
    const s = patch.startup;
    if (typeof s.antiDebug === 'boolean') settings.startup.antiDebug = s.antiDebug;
    if (typeof s.module === 'string') settings.startup.module = s.module.trim() || 'libc.so';
    if (Array.isArray(s.extraTargets)) {
      // Only symbol names: the return/errno pair is a policy decision made in service.ts, not
      // something a settings patch can invent.
      settings.startup.extraTargets = s.extraTargets
        .filter((x: unknown) => typeof x === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))
        .slice(0, 16);
    }
    if (Array.isArray(s.packages)) {
      // Empty = every package. A non-empty list is the safe form: pre-arming neutralizes path
      // checks process-wide, so it is a per-target choice, not a daemon-wide default.
      settings.startup.packages = s.packages
        .filter((x: unknown) => typeof x === 'string' && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(x))
        .slice(0, 32);
    }
    // Delayed widening: install the checks that are unsafe during initialization once the app has
    // settled (see service.ts startupWidenPlan). 0 = off, max 10 minutes.
    if (Number.isFinite(s.widenAfterMs)) settings.startup.widenAfterMs = Math.max(0, Math.min(600000, Math.floor(s.widenAfterMs)));
    if (Array.isArray(s.widenTargets)) {
      settings.startup.widenTargets = s.widenTargets
        .filter((x: unknown) => typeof x === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))
        .slice(0, 8);
    }
    applied.push('startup');
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
// Migrate ONE legacy default: before 2026-10-11 the daemon defaulted sysModule to
// 'libadhdetect.so' — the SANDBOX's mock detector lib, built by tools/build_detect.sh. Nothing
// outside the sandbox ships that name, so a persisted value equal to it can only have come from
// that default (a target-specific choice would be a real lib). Keeping it would make every real
// target report six zero-installs for hooks nobody asked for. fileModule's old default
// ('libjavacore.so') is a genuine Android lib, so it is left alone — only the default changes.
if (settings.capture.sysModule === 'libadhdetect.so') settings.capture.sysModule = '';
// Persist. Throws on failure — callers MUST surface it so the UI never claims "已保存" on a failed write.
export function saveSettings() { writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2)); }

// ---- on-disk artifact store --------------------------------------------------------------
// Adopt artifacts that are already on disk into the runtime map.
//
// Without this the map is empty after a restart: `dumps_list` / `/api/dumps` / download-by-sha /
// `dex_index` all report "nothing here" while the bytes sit in captures/ — the artifacts survive,
// only the daemon forgot them. A sidecar written by rememberDump restores the package; a file
// with no sidecar stays unlabeled (`disk-reload`) rather than being assigned to whichever app
// happens to be selected.
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
      const prov = readDumpProvenance(path, sha);
      dumps.set(sha, {
        sha256: sha, size: st.size,
        source: prov?.source || 'disk-reload',
        addr: prov?.addr ?? '',
        tag: prov?.tag || (prov ? '' : 'disk-reload'),
        sessionId: prov?.sessionId ?? '',
        package: prov?.package ?? '',
        capturedAt: prov?.capturedAt || Math.round(st.mtimeMs),
        path, kind,
        requestedSize: prov?.requestedSize ?? st.size,
        complete: prov?.complete ?? true,
        ...(prov?.note ? { note: prov.note } : {}),
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
    try { unlinkSync(artifactSidecarPath(e.path)); }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') log(`[artifacts] 来源未删除 ${e.path}:`, (err as Error).message);
    }
    removed++; bytesFreed += e.size;
  }
  return { removed, bytesFreed, remainingBytes: plan.remainingBytes, kept: dumps.size, failed };
}

// One pass over the event log for artifacts adopted without a package. dump.new already recorded
// the real package; this writes it into the sidecar so the next boot does not scan again.
function backfillUnlabeledDumps(): number {
  const need = new Set<string>();
  for (const d of dumps.values()) if (!d.package) need.add(d.sha256);
  if (!need.size || !existsSync(EVENTS_FILE)) return 0;
  const found = new Map<string, ArtifactProvenance>();
  const fd = openSync(EVENTS_FILE, 'r');
  const buf = Buffer.allocUnsafe(1 << 20);
  let carry = '';
  let done = false;
  const take = (line: string) => {
    if (done || !line.includes('"dump.new"')) return;
    let rec: { type?: string; data?: unknown };
    try { rec = JSON.parse(line); } catch { return; }
    if (rec.type !== 'dump.new' || !rec.data || typeof rec.data !== 'object') return;
    const sha = (rec.data as { sha256?: unknown }).sha256;
    if (typeof sha !== 'string' || !need.has(sha) || found.has(sha)) return;
    const prov = parseArtifactProvenance(rec.data, sha);
    if (!prov?.package) return;
    found.set(sha, prov);
    if (found.size === need.size) done = true;
  };
  try {
    let n: number;
    while (!done && (n = readSync(fd, buf, 0, buf.length, null)) > 0) {
      carry += buf.toString('utf8', 0, n);
      let nl: number;
      while ((nl = carry.indexOf('\n')) >= 0) {
        const line = carry.slice(0, nl);
        carry = carry.slice(nl + 1);
        take(line);
        if (done) break;
      }
    }
    if (!done && carry) take(carry);
  } finally { closeSync(fd); }
  let labeled = 0;
  for (const [sha, prov] of found) {
    const meta = dumps.get(sha);
    if (!meta || meta.package) continue;
    meta.source = prov.source;
    meta.addr = prov.addr;
    meta.tag = prov.tag;
    meta.sessionId = prov.sessionId;
    meta.package = prov.package;
    if (prov.capturedAt) meta.capturedAt = prov.capturedAt;
    if (typeof prov.requestedSize === 'number') meta.requestedSize = prov.requestedSize;
    if (typeof prov.complete === 'boolean') meta.complete = prov.complete;
    if (prov.note) meta.note = prov.note;
    rememberDump(meta);
    labeled++;
  }
  return labeled;
}

{ // re-adopt what is already on disk (see loadArtifactsFromDisk)
  // Tests (and CI) must not depend on whatever sits in the developer's captures/ directory: every
  // test process would scan ~1.2 GiB at import, which made the parallel suite flaky under I/O
  // contention (a file would occasionally fail with no useful output). `npm test` runs through
  // test/run.mjs, which sets this before the runner spawns the per-file processes.
  if (process.env.ADH_SKIP_ARTIFACT_LOAD === '1') {
    log('[artifacts] ADH_SKIP_ARTIFACT_LOAD=1 - starting with an empty artifact store');
  } else {
    const a = loadArtifactsFromDisk();
    const labeled = backfillUnlabeledDumps();
    if (a.loaded || a.skipped) log(`[artifacts] 从磁盘恢复 ${a.loaded} 个工件（跳过 ${a.skipped}，${(a.bytes / 1048576).toFixed(1)} MiB，${a.ms}ms）`);
    if (labeled) log(`[artifacts] 从事件日志补上 ${labeled} 个工件的包名`);
  }
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
// Store a capture honoring the family filter + per-package retention. Returns false if filtered out.
// The family filter is a crypto-panel control only — net/file/system captures bypass it
// (their algo doesn't map to a crypto family, so familyOf would misclassify them).
// Durable truth: when the entry has a package, append the full record under
// adhd-data/packages/<pkg>/captures.jsonl so a daemon restart can replay it.
export function pushCapture(entry: Capture): boolean {
  if (entry.category === 'crypto' && settings.capture.families[familyOf(entry.algo)] === false) return false;
  captures.push(entry);
  capturePushed++;
  bumpSession(entry.sessionId, 'pushed');
  const pkg = entry.package && entry.package !== '?' ? entry.package : '';
  if (pkg) {
    try { appendCaptureLine(DATA_DIR, entry); }
    catch (err) { log(`[captures] 持久化失败 (${pkg}):`, (err as Error).message); }
  }
  const retain = settings.capture.retain;
  const evicted = evictPackageFromMemory(captures, pkg, retain);
  for (const dropped of evicted) {
    captureEvicted++;
    bumpSession(dropped.sessionId, 'evicted');
  }
  if (pkg && evicted.length) {
    try { trimPackageCapturesFile(DATA_DIR, pkg, retain); }
    catch (err) { log(`[captures] 裁剪失败 (${pkg}):`, (err as Error).message); }
  }
  return true;
}

/** Drop in-memory captures and the on-disk packages/ tree. Returns disk errors (if any). */
export function clearCaptureStore(): string[] {
  captures.length = 0;
  recentJavaIn.clear();
  return clearAllPersistedCaptures(DATA_DIR);
}

/** Drop one package from memory and disk. */
export function clearPackageCaptureStore(pkg: string): string[] {
  for (let i = captures.length - 1; i >= 0; i--) {
    if (capturePackage(captures[i]) === pkg) captures.splice(i, 1);
  }
  return clearPackagePersistedCaptures(DATA_DIR, pkg);
}

export function packageCaptureDiskStats() {
  return listPackageCaptureStats(DATA_DIR);
}

export function exportPackageCapturesJsonl(pkg: string): string | null {
  return readPackageCapturesJsonl(DATA_DIR, pkg);
}

/** After settings.retain / maxAgeDays change: enforce caps in memory and on disk. */
export function applyCaptureRetainCap(): void {
  try { pruneCapturesOlderThan(DATA_DIR, settings.capture.maxAgeDays); }
  catch (err) { log(`[captures] 天龄裁剪失败:`, (err as Error).message); }
  const retain = settings.capture.retain;
  const pkgs = new Set<string>();
  for (const c of captures) pkgs.add(c.package && c.package !== '?' ? c.package : '');
  // Drop from memory anything older than maxAgeDays.
  if (settings.capture.maxAgeDays > 0) {
    const cutoff = Date.now() - settings.capture.maxAgeDays * 86400000;
    for (let i = captures.length - 1; i >= 0; i--) {
      if (Number(captures[i].ts) && Number(captures[i].ts) < cutoff) captures.splice(i, 1);
    }
  }
  enforcePerPackageRetain(captures, retain);
  for (const pkg of pkgs) {
    if (!pkg) continue;
    try { trimPackageCapturesFile(DATA_DIR, pkg, retain); }
    catch (err) { log(`[captures] 裁剪失败 (${pkg}):`, (err as Error).message); }
  }
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
  /** SSL* for a TLS record (`0x…`). The host pairs HTTP/1.1 on this, per session. */
  conn?: string;
  /** Target package. Stamped at ingest so the record stays with the app after the process exits and its session is pruned. */
  package?: string;
  keyHex?: string; ivHex?: string; outHex?: string;
}
/** Package a capture belongs to. Prefer the stamp; fall back to a session that is still in the registry. */
export function capturePackage(c: { package?: string; sessionId?: string }): string {
  if (c.package && c.package !== '?') return c.package;
  if (c.sessionId) {
    const pkg = sessions.get(c.sessionId)?.package;
    if (pkg && pkg !== '?') return pkg;
  }
  return '';
}
/**
 * Narrow the live capture store the way `http_exchanges` already does. Kept pure and exported
 * because "the sandbox self-check records and the target's records are one undifferentiated
 * stream" was a real defect: a caller could only tell them apart by reading every record.
 * `package` is resolved per record (its own stamp first), so a target's records stay attributable
 * after its process exits and the session is pruned.
 */
export function filterLiveCaptures<T extends { category: string; package?: string; sessionId: string }>(
  list: readonly T[], opts: { category?: string; session?: string; package?: string },
): T[] {
  let out = list as readonly T[];
  if (opts.category) out = out.filter((c) => c.category === opts.category);
  if (opts.session) out = out.filter((c) => c.sessionId === opts.session);
  if (opts.package) out = out.filter((c) => capturePackage(c) === opts.package);
  return out as T[];
}
export interface KnownApp {
  package: string; online: boolean; pids: number[]; sessions: number; lastSeen: number;
}
/** Apps the viewer can switch to: every package that has a session or a retained capture. */
export function knownApps(): KnownApp[] {
  const by = new Map<string, KnownApp>();
  const touch = (pkg: string): KnownApp | null => {
    if (!pkg || pkg === '?') return null;
    let cur = by.get(pkg);
    if (!cur) {
      cur = { package: pkg, online: false, pids: [], sessions: 0, lastSeen: 0 };
      by.set(pkg, cur);
    }
    return cur;
  };
  for (const s of sessions.values()) {
    const cur = touch(s.package);
    if (!cur) continue;
    cur.sessions++;
    cur.lastSeen = Math.max(cur.lastSeen, s.lastSeen || s.connectedAt || 0);
    if (s.online && !cur.pids.includes(s.pid)) cur.pids.push(s.pid);
    if (s.online) cur.online = true;
  }
  for (const c of captures) {
    const cur = touch(capturePackage(c));
    if (!cur) continue;
    cur.lastSeen = Math.max(cur.lastSeen, c.ts || 0);
  }
  for (const e of events) {
    const cur = touch(eventPackage(e.data));
    if (!cur) continue;
    cur.lastSeen = Math.max(cur.lastSeen, e.ts || 0);
  }
  return [...by.values()].sort((a, b) => b.lastSeen - a.lastSeen || a.package.localeCompare(b.package));
}
export const captures: Capture[] = [];
// Replay durable captures so a daemon restart keeps hook history (per package).
{
  try {
    const aged = pruneCapturesOlderThan(DATA_DIR, settings.capture.maxAgeDays);
    if (aged) log(`[captures] 按天龄裁掉 ${aged} 条（>${settings.capture.maxAgeDays} 天）`);
  } catch (e) { log(`[captures] 天龄裁剪失败:`, (e as Error).message); }
  const loaded = loadCapturesFromDisk(DATA_DIR, settings.capture.retain);
  for (const c of loaded) captures.push(c as Capture);
  if (loaded.length) log(`[captures] 从磁盘恢复 ${loaded.length} 条（按包保留上限 ${settings.capture.retain}）`);
}
// Store accounting (v4.93): the in-memory list is capped by settings.capture.retain (per package
// since 2026-10-20), and an evicted record is gone for every digest that runs later. Counting
// pushes and evictions lets a digest admit that its window may be missing events.
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

function hexHead(hex: string, maxBytes: number): string {
  let s = '';
  const n = Math.min(hex.length, maxBytes * 2);
  for (let i = 0; i + 1 < n; i += 2) s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
  return s;
}

/**
 * Network-list label for one TLS plaintext.
 * A request becomes `METHOD https://host/path` (path alone when the Host header is absent).
 * A response becomes its status line. Anything else returns '' so the caller keeps the raw preview.
 * `text` may be the real header block, or the dotted preview (`\\r\\n` already collapsed to `.`).
 */
export function httpCapturePreview(text: string): string {
  if (!text) return '';
  const lines = /[\r\n]/.test(text)
    ? text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')
    : text.split('..');
  const line = (lines[0] ?? '').trim();
  const req = line.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  if (req) {
    const method = req[1].toUpperCase();
    const target = req[2];
    if (/^https?:\/\//i.test(target)) return `${method} ${target}`;
    let host = '';
    for (const header of lines.slice(1)) {
      const found = header.match(/^Host:\s*(\S+)/i);
      if (found) { host = found[1]; break; }
    }
    if (host && target.startsWith('/')) return `${method} https://${host}${target}`;
    return `${method} ${target}`;
  }
  const status = line.match(/^HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s+\S+)*/);
  return status ? status[0] : '';
}

/** Preview stored on a capture. TLS records prefer the URL / status line over a raw header dump. */
export function previewForCapture(func: string, hex: string): string {
  if (func === 'SSL_write' || func === 'SSL_read') {
    const url = httpCapturePreview(hexHead(hex, 4096));
    if (url) return url;
  }
  if (func === 'NATIVE_HOOK_MEM') {
    const line = memCapturePreview(Buffer.from(hex, 'hex').toString('utf8'));
    if (line) return line.slice(0, 180);
  }
  return hexToPreview(hex);
}
// Which UI axis a capture belongs to. Derived from the agent's func tag so the web can
// split the single stream into 加解密 / 网络 / 文件 / 系统 master-detail panels. The agent
// stamps func: EVP_*/HMAC_* (crypto), SSL_read/write (net), open*/read/write/close (file),
// ptrace/access/faccessat/sysprop/propread (system) — see cmd_capture_start.
export function categoryOf(func: string): CapCategory {
  if (func === 'JAVA_HOOK' || func === 'NATIVE_HOOK' || func === 'NATIVE_HOOK_MEM' || func === 'JNI_NATIVE' || func === 'JNI_ONLOAD' || func === 'JNI_ENV') return 'system';
  // A library mapped at runtime belongs with the system/hook observations: it is context for the
  // other records (what appeared, and when), not a payload of its own.
  if (func === 'MODULE_LOAD') return 'system';
  if (func === 'SSL_write' || func === 'SSL_read') return 'net';
  if (/^(open|openat|read|write|close)$/.test(func)) return 'file';
  if (/^(ptrace|access|faccessat|sysprop|propread|__system_property_get|getprop)$/.test(func)) return 'system';
  return 'crypto';
}
export function classify(func: string): { algo: string; op: string } {
  if (func === 'JAVA_HOOK') return { algo: 'Java Hook', op: '方法调用' };
  if (func === 'NATIVE_HOOK') return { algo: 'Native Hook', op: '函数调用' };
  if (func === 'NATIVE_HOOK_MEM') return { algo: '函数参数', op: '入口内容' };
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
  if (func === 'access' || func === 'faccessat') return { algo: 'access', op: '路径探测' };
  if (func === 'sysprop' || func === 'propread' || func === '__system_property_get') return { algo: '系统属性', op: '读取手机信息' };
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
/** Package carried by an event payload, either stamped or still resolvable from a live session. */
export function eventPackage(data: unknown): string {
  if (!data || typeof data !== 'object') return '';
  const d = data as { package?: unknown; sessionId?: unknown };
  if (typeof d.package === 'string' && d.package && d.package !== '?') return d.package;
  if (typeof d.sessionId === 'string') {
    const pkg = sessions.get(d.sessionId)?.package;
    if (pkg && pkg !== '?') return pkg;
  }
  return '';
}
function stampPackage(data: unknown): unknown {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return data;
  const d = data as Record<string, unknown>;
  if (typeof d.package === 'string' && d.package) return data;
  const pkg = eventPackage(d);
  return pkg ? { ...d, package: pkg } : data;
}
export function broadcast(event: string, data: unknown) {
  const stamped = stampPackage(data);
  const msg = JSON.stringify({ event, data: stamped, ts: Date.now() });
  for (const c of wss.clients) if (c.readyState === WebSocket.OPEN) c.send(msg);
  if (event !== 'snapshot') recordEvent(event, stamped);   // persist for record/replay
}
export function log(...a: unknown[]) {
  console.log(`[adhd ${new Date().toISOString()}]`, ...a);
}
// Requests are small: MCP JSON, a package name, a path. The old implementation concatenated an
// unbounded string (and decoded each chunk on its own, so a multi-byte character split across a
// chunk boundary became U+FFFD). With the server on 0.0.0.0 and no auth, any peer that can reach
// the port could grow the heap until the daemon died. Cap it; the top-level error net in
// index.ts maps `status` to the response code, so this answers 413 instead of hanging.
export const MAX_BODY_BYTES = 8 * 1024 * 1024;
export function readBody(req: IncomingMessage, cap = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const parts: Buffer[] = [];
    const fail = (e: Error & { status?: number }) => {
      if (settled) return;
      settled = true;
      // Do NOT destroy the socket here: that turns the answer into a bare TCP reset, so a caller
      // sending an oversized body sees "connection closed" instead of 413. Stop consuming, let the
      // top-level error net write the 413 (it sets Connection: close for this case) and drop the
      // rest of the stream after the response.
      try { req.pause(); } catch { /* already ended */ }
      reject(e);
    };
    req.on('data', (c: Buffer) => {
      if (settled) return;
      size += c.length;
      if (size > cap) {
        const e: Error & { status?: number } = new Error(`request body too large (> ${cap} bytes)`);
        e.status = 413;
        return fail(e);
      }
      parts.push(c);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(parts).toString('utf8'));
    });
    req.on('error', fail);
  });
}

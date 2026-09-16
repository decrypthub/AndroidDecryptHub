// state.ts — ADH Daemon shared state + leaf mutators.
// Pure state holder: imports NOTHING from service.ts/mcp.ts/index.ts (no circular refs).
// Imported by everyone. Everything that holds runtime state or is a leaf helper lives here;
// functions that issue agent commands (sendCmd/capture loop/unpack/dump) live in service.ts.
import net from 'node:net';
import type { IncomingMessage } from 'node:http';
import { mkdirSync, writeFileSync, existsSync, appendFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';

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
  connectedAt: number;
  lastSeen: number;
  online: boolean;
  mapsCount: number;
  regionsSample: MapsRegion[];
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
  for (const id of dropped) sessions.delete(id);
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
export const DATA_DIR = join(_dataRoot, 'adhd-data');
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
// Live agent cursor: the newest event seq + capture id the host has stored so far. An AI takes
// one of these before an action and passes it back to phone_wait, so a signal that lands between
// two MCP calls is still caught (no race against the capture-drain tick).
export function agentCursor() {
  return { eventSeq: evSeq, captureId: captures.length ? captures[captures.length - 1].id : 0 };
}

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
  automation: { enabled: boolean; screenshot: boolean; packages: string[]; maxNodes: number; screenshotMaxDimension: number };
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
  automation: { enabled: false, screenshot: true, packages: [], maxNodes: 300, screenshotMaxDimension: 1280 },
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
  if (patch.automation && typeof patch.automation === 'object') {
    const a = patch.automation;
    if (typeof a.enabled === 'boolean') settings.automation.enabled = a.enabled;
    if (typeof a.screenshot === 'boolean') settings.automation.screenshot = a.screenshot;
    if (Array.isArray(a.packages))
      settings.automation.packages = [...new Set(a.packages.map((v: unknown) => String(v).trim()).filter(Boolean))].sort();
    if (Number.isFinite(a.maxNodes)) settings.automation.maxNodes = Math.max(20, Math.min(2000, Math.floor(a.maxNodes)));
    if (Number.isFinite(a.screenshotMaxDimension)) settings.automation.screenshotMaxDimension = Math.max(480, Math.min(2400, Math.floor(a.screenshotMaxDimension)));
    applied.push('automation');
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
export function configStats() { return { captures: captures.length, dumps: dumps.size, events: events.length, on: captureTimers.size > 0, agents: sessions.size, capture: captureHealth() }; }
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
  while (captures.length > settings.capture.retain) captures.shift();
  return true;
}
// Self-test workload classes the one-shot probe ops drive. The AGENT is target-agnostic —
// it reads className/module/reportClass from each command and knows nothing about the target;
// ADH Daemon supplies these sandbox defaults so its self-test endpoints work out of the box. A real
// investigation overrides via ?class= / className. (This is the daemon side of the red line: the
// grep-com.adh.sandbox-agent/=0 gate is about the .so, which stays clean.)
export const SANDBOX = {
  net: 'com.adh.sandbox.Network', flow: 'com.adh.sandbox.CorrelatedFlow',
  crypto: 'com.adh.sandbox.JavaCrypto', file: 'com.adh.sandbox.FileIO',
  detect: 'com.adh.sandbox.Detection',
  inlineModule: 'libadhdetect.so', inlineSymbol: 'adh_static_EVP_CipherUpdate',
  inlineMethod: 'staticCrypto',
};
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
// capSeq lives in service.ts — it's ++'d inside startCaptureLoop there, and ESM imported
// bindings are read-only for the importer (can't reassign from another module). It's only
// used by the capture loop, so it's a service-local counter, not shared state.
export const recentJavaIn = new Map<string, number>();   // input-hex -> ts, to dedup native echoes
export const captureTimers = new Map<string, ReturnType<typeof setInterval>>();
export const capturePaused = new Set<string>();   // sessions with continuous capture suspended
// WS-C: per-session honest capture accounting from the agent ring's capture_drain stats.
export interface CapStat { seq: number; emitted: number; dropped: number; jdropped: number; backlog: number; firstDropNs: number; lastDropNs: number; complete: boolean; ring: number; ts: number; }
export const capStats = new Map<string, CapStat>();
// Aggregate drop accounting across sessions — complete:false the moment anything dropped.
// The invariant emitted + backlog + dropped === seq holds per session (nothing silent).
export function captureHealth() {
  let seq = 0, emitted = 0, dropped = 0, jdropped = 0, backlog = 0; let complete = true;
  for (const s of capStats.values()) { seq += s.seq; emitted += s.emitted; dropped += s.dropped; jdropped += s.jdropped; backlog += s.backlog; if (!s.complete) complete = false; }
  return { seq, emitted, dropped, jdropped, backlog, complete, accountedFor: emitted + backlog + dropped, sessions: capStats.size };
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
  if (func === 'SSL_write' || func === 'SSL_read') return 'net';
  if (/^(open|openat|read|write|close)$/.test(func)) return 'file';
  if (/^(ptrace|access|sysprop|__system_property_get|getprop)$/.test(func)) return 'system';
  return 'crypto';
}
export function classify(func: string): { algo: string; op: string } {
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

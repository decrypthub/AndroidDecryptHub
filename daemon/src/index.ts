// idhd — ADH (Android DecryptHub) daemon (v0.1)
// Three surfaces:
//   - Agent TCP server (NDJSON)         : device agents connect here (via `adb reverse`)
//   - HTTP server (REST + static)       : /health, /api/agents, dashboard
//   - WebSocket                         : pushes live agent/registry events to the browser
// v0.1 keeps all state in memory. Persistence (SQLite) arrives in v0.2.

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { mkdirSync, writeFileSync, existsSync, createReadStream, unlinkSync, appendFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { homedir, tmpdir, networkInterfaces } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const execFileP = promisify(execFile);
const LLVM_BIN = process.env.IDH_LLVM_BIN ??
  join(homedir(), 'AppData/Local/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/windows-x86_64/bin');
const OBJDUMP = process.env.IDH_OBJDUMP ?? join(LLVM_BIN, 'llvm-objdump.exe');
const READELF = process.env.IDH_READELF ?? join(LLVM_BIN, 'llvm-readelf.exe');

// Static binary analysis of an ELF .so: dynamic symbols (exports/imports),
// NEEDED libs, and printable strings.
async function analyzeSo(path: string): Promise<any> {
  const exports: string[] = [], imports: string[] = [];
  let readelfError = '';   // fail-loud: an absent/failing readelf must not masquerade as "no symbols"
  try {
    const { stdout } = await execFileP(READELF, ['--dyn-syms', path], { maxBuffer: 32 * 1024 * 1024 });
    for (const line of stdout.split('\n')) {
      // Num: Value Size Type Bind Vis Ndx Name
      const m = line.match(/^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(FUNC|OBJECT|NOTYPE)\s+\S+\s+\S+\s+(\S+)\s+(\S+)/i);
      if (!m) continue;
      const [, , , ndx, name] = m;
      if (!name || name === '') continue;
      if (ndx === 'UND') imports.push(name); else exports.push(name);
    }
  } catch (e) { readelfError = `readelf --dyn-syms failed: ${(e as Error).message}`; }
  const needed: string[] = [];
  try {
    const { stdout } = await execFileP(READELF, ['-d', path], { maxBuffer: 8 * 1024 * 1024 });
    for (const line of stdout.split('\n')) { const m = line.match(/\(NEEDED\).*\[(.+?)\]/); if (m) needed.push(m[1]); }
  } catch (e) { if (!readelfError) readelfError = `readelf -d failed: ${(e as Error).message}`; }
  // printable string runs (>=4)
  const buf = await readFile(path);
  const strings: string[] = []; let cur = '';
  for (let i = 0; i < buf.length && strings.length < 5000; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
    else { if (cur.length >= 4) strings.push(cur); cur = ''; }
  }
  return { exports: [...new Set(exports)], imports: [...new Set(imports)], needed, strings: [...new Set(strings)],
    ...(readelfError ? { readelfError } : {}),
    counts: { exports: exports.length, imports: imports.length, needed: needed.length, strings: strings.length } };
}

// Known crypto constant signatures (byte patterns) — locate algorithms in stripped
// native libs where symbols are gone (H.4). Little-endian where applicable.
const CRYPTO_CONSTS: { name: string; hex: string }[] = [
  { name: 'AES-Sbox', hex: '637c777bf26b6fc53001672bfed7ab76' },
  { name: 'AES-InvSbox', hex: '52096ad53036a538bf40a39e81f3d7fb' },
  { name: 'Base64-std', hex: Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/').toString('hex') },
  { name: 'Base64-url', hex: Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_').toString('hex') },
  { name: 'SHA256-init', hex: '67e6096a85ae67bb' },   // H0,H1 LE
  { name: 'SHA256-K', hex: '982f8a4291443771' },       // K0,K1 LE
  { name: 'MD5-init', hex: '0123456789abcdef' },        // A,B LE (0x67452301,0xefcdab89)
  { name: 'SHA1-init', hex: '01234567' + '89abcdef' },  // A,B LE
  { name: 'TEA-delta', hex: 'b979379e' },               // 0x9e3779b9 LE
];
function cryptoConstScan(buf: Buffer): { name: string; offset: string; hexLen: number }[] {
  const hits: { name: string; offset: string; hexLen: number }[] = [];
  for (const c of CRYPTO_CONSTS) {
    const pat = Buffer.from(c.hex, 'hex');
    let idx = buf.indexOf(pat);
    let n = 0;
    while (idx >= 0 && n < 8) { hits.push({ name: c.name, offset: '0x' + idx.toString(16), hexLen: pat.length }); n++; idx = buf.indexOf(pat, idx + 1); }
  }
  return hits;
}

// Scan an ELF .so's executable segments for arm64 `svc #0` (0xd4000001) — direct
// syscalls that bypass libc/PLT (and thus GOT hooks). E.9 L1: locate hotspots.
function svcScan(buf: Buffer): { hits: { fileOff: string; vaddr: string }[]; execSegs: number; scanned: number } {
  const hits: { fileOff: string; vaddr: string }[] = [];
  let execSegs = 0, scanned = 0;
  if (buf.length < 64 || buf.readUInt32LE(0) !== 0x464c457f || buf[4] !== 2) return { hits, execSegs, scanned };
  const phoff = Number(buf.readBigUInt64LE(32));
  const phentsize = buf.readUInt16LE(54), phnum = buf.readUInt16LE(56);
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + 56 > buf.length) break;
    if (buf.readUInt32LE(o) !== 1) continue;                 // PT_LOAD
    if (!(buf.readUInt32LE(o + 4) & 1)) continue;            // PF_X
    execSegs++;
    const off = Number(buf.readBigUInt64LE(o + 8));
    const vaddr = Number(buf.readBigUInt64LE(o + 16));
    const filesz = Number(buf.readBigUInt64LE(o + 32));
    const end = Math.min(off + filesz, buf.length);
    for (let a = off; a + 4 <= end; a += 4) {
      scanned += 4;
      if (buf.readUInt32LE(a) === 0xd4000001) hits.push({ fileOff: '0x' + a.toString(16), vaddr: '0x' + (vaddr + (a - off)).toString(16) });
      if (hits.length >= 4096) return { hits, execSegs, scanned };
    }
  }
  return { hits, execSegs, scanned };
}

interface Insn { addr: string; bytes: string; mnemonic: string; text: string; }
// Disassemble an ELF .so on disk (llvm-objdump). By symbol, or an address range.
async function disasmSo(path: string, opts: { symbol?: string; start?: string; stop?: string }): Promise<Insn[]> {
  const args = ['-d'];
  if (opts.symbol) args.push(`--disassemble-symbols=${opts.symbol}`);
  if (opts.start) args.push(`--start-address=0x${opts.start.replace(/^0x/, '')}`);
  if (opts.stop) args.push(`--stop-address=0x${opts.stop.replace(/^0x/, '')}`);
  args.push(path);
  const { stdout } = await execFileP(OBJDUMP, args, { maxBuffer: 32 * 1024 * 1024 });
  const insns: Insn[] = [];
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?: ?[0-9a-f]{2})*)\s+(.+?)\s*$/i);
    if (m) insns.push({ addr: m[1], bytes: m[2].replace(/\s+/g, ''), mnemonic: m[3].trim().split(/\s+/)[0], text: m[3].trim() });
  }
  return insns;
}
import { WebSocketServer, WebSocket } from 'ws';
import { parseDex, cryptoScan, searchDex, invokeXref, extractMethodCode, analyzeCoverage, rebuildStandardDex, recoverFromSnapshots, stripMethodCode } from './dex.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CAPTURES = join(__dirname, '..', '..', 'captures');
mkdirSync(CAPTURES, { recursive: true });

const HTTP_PORT = Number(process.env.IDH_HTTP_PORT ?? 8760);
const AGENT_PORT = Number(process.env.IDH_AGENT_PORT ?? 8761);

// ---- access URLs (mirrors ios-decrypt-helper: surface the LAN address so the console
//      is reachable from the phone / any device on the network, fail-loud if none) -----
// idhd (the web console) runs on the HOST, so the relevant LAN IP is this machine's,
// not the phone's. The phone reaches it via `adb reverse` (127.0.0.1) OR directly over
// Wi-Fi at the LAN IP. Prefer private ranges (192.168./10./172.16-31.) and stable NICs.
function lanIPv4s(): string[] {
  const nics = networkInterfaces();
  const priv: string[] = [];
  const other: string[] = [];
  for (const [name, addrs] of Object.entries(nics)) {
    for (const a of addrs ?? []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      // skip virtual/container/adb NICs that aren't the real LAN
      if (/^(vEthernet|Loopback|WSL|Hyper-V|docker|veth|utun|tun|tap)/i.test(name)) continue;
      const ip = a.address;
      if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) priv.push(ip);
      else other.push(ip);
    }
  }
  return [...priv, ...other];
}
function webUrls() {
  const port = HTTP_PORT;
  const lan = lanIPv4s().map((ip) => `http://${ip}:${port}`);
  return { port, local: `http://127.0.0.1:${port}`, lan };
}

// ---- types (erased at runtime) -------------------------------------------

interface MapsRegion {
  start: string; end: string; perms: string; offset: string;
  dev: string; inode: number; path: string;
}
interface AgentSession {
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
type AgentMsg =
  | ({ t: 'hello' } & Partial<AgentSession>)
  | { t: 'maps'; count: number; regions?: MapsRegion[] }
  | { t: 'ping'; ts?: number }
  | { t: 'cmdResult'; id: string; op: string; ok: boolean; [k: string]: unknown };

// ---- registry -------------------------------------------------------------

interface DumpMeta {
  sha256: string; size: number; source: string; addr: string;
  tag: string; sessionId: string; package: string; capturedAt: number;
  path: string; kind: string;   // dex|so|region|... inferred from magic
}
const sessions = new Map<string, AgentSession>();
const dumps = new Map<string, DumpMeta>();                        // sha256 -> meta (dedup)
const agentSockets = new Map<string, net.Socket>();               // sessionId -> live socket
const pending = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
let seq = 0;
let cmdSeq = 0;
const nextId = () => `s_${(++seq).toString(36)}${Date.now().toString(36).slice(-3)}`;
const nextCmdId = () => `c${(++cmdSeq).toString(36)}`;

// Issue a command to an agent and await its cmdResult (10s timeout).
// ---- wire framing (v2.0, WS-D): [u32 len BE][u8 type][payload] -------------
// Replaces NDJSON. Control/cmd/cmdResult ride as FRAME_JSON; binary/bulk types
// reserved for later (capture batch, chunked dump). Fail-loud on oversized/unknown.
const FRAME_JSON = 0x01;
const FRAME_MAX = 64 * 1024 * 1024;   // inbound payload cap; beyond → close (corrupt stream)
function frameJson(obj: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  const hdr = Buffer.allocUnsafe(5);
  hdr.writeUInt32BE(payload.length, 0);
  hdr.writeUInt8(FRAME_JSON, 4);
  return Buffer.concat([hdr, payload]);
}

function sendCmd(sessionId: string, op: string, args: Record<string, unknown> = {}, timeoutMs = 10_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = agentSockets.get(sessionId);
    if (!sock || sock.destroyed) return reject(new Error('agent not connected'));
    const id = nextCmdId();
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('command timeout')); }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    sock.write(frameJson({ t: 'cmd', id, op, ...args }));
  });
}

// ---- event store (session record/replay) ---------------------------------
const DATA_DIR = join(__dirname, '..', '..', 'idhd-data');
mkdirSync(DATA_DIR, { recursive: true });
const EVENTS_FILE = join(DATA_DIR, 'events.jsonl');
interface Ev { seq: number; ts: number; type: string; data: any }
const events: Ev[] = [];
let evSeq = 0;
try {   // replay: load persisted events on startup so a session survives restarts
  if (existsSync(EVENTS_FILE)) {
    const lines = readFileSync(EVENTS_FILE, 'utf8').split('\n').filter(Boolean).slice(-5000);
    let corrupt = 0;
    for (const l of lines) { try { const e = JSON.parse(l); events.push(e); if (e.seq > evSeq) evSeq = e.seq; } catch { corrupt++; } }
    if (corrupt) log(`[events] replay: ${corrupt}/${lines.length} 行损坏已跳过 (${EVENTS_FILE})`);
  }
} catch (e) { log(`[events] replay 失败 (${EVENTS_FILE}) — 从空事件起步:`, (e as Error).message); }
function recordEvent(type: string, data: any) {
  const e: Ev = { seq: ++evSeq, ts: Date.now(), type, data };
  events.push(e); if (events.length > 5000) events.shift();
  try { appendFileSync(EVENTS_FILE, JSON.stringify(e) + '\n'); }
  catch (err) { log(`[events] 持久化失败 (${EVENTS_FILE}):`, (err as Error).message); }
}

// ---- user settings (persisted; tunable from the web 设置 panel; IDH-style) --------
// Only touches the idhd/web layer — the agent .so is never reconfigured from here.
const SETTINGS_FILE = join(DATA_DIR, 'settings.json');
interface Settings {
  capture: { enabled: boolean; autoDumpDex: boolean; retain: number; families: Record<string, boolean>; fileModule: string; sysModule: string };
  ui: { displayCap: number };
}
const DEFAULT_SETTINGS: Settings = {
  // fileModule/sysModule: which loaded module's GOT the persistent file(open/read/…) and
  // system(ptrace/access/getprop) hooks patch. Defaults are the sandbox-backing modules for
  // self-test; override per real target (empty string = don't install that category's hooks).
  capture: { enabled: true, autoDumpDex: true, retain: 1000, families: { digest: true, hmac: true, symmetric: true, asymmetric: true, tls: true }, fileModule: 'libjavacore.so', sysModule: 'libidhdetect.so' },
  ui: { displayCap: 300 },
};
let settings: Settings = JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
// section-merge (like IDH /api/settings/import): only the segments present in `patch` apply.
function mergeSettings(patch: any): string[] {
  const applied: string[] = [];
  if (!patch || typeof patch !== 'object') return applied;
  if (patch.capture && typeof patch.capture === 'object') {
    const c = patch.capture;
    if (typeof c.enabled === 'boolean') settings.capture.enabled = c.enabled;
    if (typeof c.autoDumpDex === 'boolean') settings.capture.autoDumpDex = c.autoDumpDex;
    if (Number.isFinite(c.retain)) settings.capture.retain = Math.max(50, Math.min(100000, Math.floor(c.retain)));
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
function saveSettings() { writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2)); }
function configStats() { return { captures: captures.length, dumps: dumps.size, events: events.length, on: captureTimers.size > 0, agents: sessions.size, capture: captureHealth() }; }
// Which crypto family a capture belongs to (mirrors cryptoIdentify's buckets) — used by the
// idhd-side family filter (panel-level; the agent still hooks everything).
function familyOf(algo: string): 'tls' | 'asymmetric' | 'hmac' | 'digest' | 'symmetric' {
  if (/TLS/.test(algo)) return 'tls';
  if (/RSA|(^|[^m])EC[^B]|ECDSA|DSA/i.test(algo)) return 'asymmetric';
  if (/Hmac|HMAC/i.test(algo)) return 'hmac';
  if (/MD5|SHA|摘要|Digest/i.test(algo)) return 'digest';
  return 'symmetric';
}
// Store a capture honoring the family filter + retention cap. Returns false if filtered out.
// The family filter is a crypto-panel control only — net/file/system captures bypass it
// (their algo doesn't map to a crypto family, so familyOf would misclassify them).
function pushCapture(entry: Capture): boolean {
  if (entry.category === 'crypto' && settings.capture.families[familyOf(entry.algo)] === false) return false;
  captures.push(entry);
  while (captures.length > settings.capture.retain) captures.shift();
  return true;
}
// Self-test workload classes the one-shot probe ops drive. The AGENT is target-agnostic —
// it reads className/module/reportClass from each command and knows nothing about the target;
// idhd supplies these sandbox defaults so its self-test endpoints work out of the box. A real
// investigation overrides via ?class= / className. (This is the idhd side of the red line: the
// grep-com.idh.sandbox-agent/=0 gate is about the .so, which stays clean.)
const SANDBOX = {
  net: 'com.idh.sandbox.Network', flow: 'com.idh.sandbox.CorrelatedFlow',
  crypto: 'com.idh.sandbox.JavaCrypto', file: 'com.idh.sandbox.FileIO',
  detect: 'com.idh.sandbox.Detection', javaHook: 'com.idh.sandbox.HookTarget',
};
// The persistent-hook target modules the agent should use. Sent with every capture_start so
// the agent stays target-agnostic (no hardcoded modules). The Java rich-capture reporter class
// is published by the TARGET via the "idh.reporter.class" system property (bound at JNI_OnLoad),
// not passed here — it must be bound before the target's JCE provider fires, i.e. before connect.
function captureModules() { return { fileModule: settings.capture.fileModule, sysModule: settings.capture.sysModule }; }
// Apply the capture.enabled toggle to already-connected sessions (start/stop the hooks).
async function applyCaptureEnabled() {
  for (const s of sessions.values()) {
    if (!s.online) continue;
    const cmd = settings.capture.enabled ? 'capture_start' : 'capture_stop';
    const args = settings.capture.enabled ? captureModules() : {};
    // Fail loud: a live session that rejects the toggle means the panel and the target disagree.
    try { await sendCmd(s.sessionId, cmd, args, 8_000); }
    catch (e) { log(`[settings] ${cmd} 会话 ${s.sessionId} 失败:`, (e as Error).message); }
  }
}

// ---- live capture store: what the agent's persistent hooks stream in (the panel's
//      加解密 list reads this; it auto-populates without any button click) -------------
type CapCategory = 'crypto' | 'net' | 'file' | 'system';
interface Capture {
  id: number; sessionId: string; source: 'java' | 'native'; func: string; algo: string; op: string;
  category: CapCategory;
  inl: number; tid: number; tsNs: number; ts: number; hex: string; preview: string;
  keyHex?: string; ivHex?: string; outHex?: string;
}
const captures: Capture[] = [];
let capSeq = 0;
const recentJavaIn = new Map<string, number>();   // input-hex -> ts, to dedup native echoes
const captureTimers = new Map<string, ReturnType<typeof setInterval>>();
const capturePaused = new Set<string>();   // sessions with continuous capture suspended
// WS-C: per-session honest capture accounting from the agent ring's capture_drain stats.
interface CapStat { seq: number; emitted: number; dropped: number; jdropped: number; backlog: number; firstDropNs: number; lastDropNs: number; complete: boolean; ring: number; ts: number; }
const capStats = new Map<string, CapStat>();
// Aggregate drop accounting across sessions — complete:false the moment anything dropped.
// The invariant emitted + backlog + dropped === seq holds per session (nothing silent).
function captureHealth() {
  let seq = 0, emitted = 0, dropped = 0, jdropped = 0, backlog = 0; let complete = true;
  for (const s of capStats.values()) { seq += s.seq; emitted += s.emitted; dropped += s.dropped; jdropped += s.jdropped; backlog += s.backlog; if (!s.complete) complete = false; }
  return { seq, emitted, dropped, jdropped, backlog, complete, accountedFor: emitted + backlog + dropped, sessions: capStats.size };
}

// The one-shot probe endpoints install-and-restore their OWN hooks on the same GOT slot
// the continuous capture uses. Suspend continuous capture around them (pause the drain +
// uninstall the persistent hooks) so the probe sees a clean slot, then resume.
async function withCaptureSuspended<T>(sid: string, fn: () => Promise<T>): Promise<T> {
  const wasOn = captureTimers.has(sid);
  if (wasOn) {
    capturePaused.add(sid);
    // fail-loud: if stop fails the probe patches a slot the persistent hook still holds — visible, not silent
    try { await sendCmd(sid, 'capture_stop', {}, 8_000); }
    catch (e) { log(`[capture] suspend: capture_stop ${sid} 失败 — 探针将在持久 hook 仍占的槽上安装:`, (e as Error).message); }
  }
  try { return await fn(); }
  finally {
    if (wasOn) {
      // fail-loud: a failed resume leaves continuous capture dead — must not vanish silently
      try { await sendCmd(sid, 'capture_start', captureModules(), 8_000); }
      catch (e) { log(`[capture] resume: capture_start ${sid} 失败 — 持续捕获已停，需手动重启:`, (e as Error).message); }
      capturePaused.delete(sid);
    }
  }
}

function hexToPreview(hex: string, max = 80): string {
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
function categoryOf(func: string): CapCategory {
  if (func === 'SSL_write' || func === 'SSL_read') return 'net';
  if (/^(open|openat|read|write|close)$/.test(func)) return 'file';
  if (/^(ptrace|access|sysprop|__system_property_get|getprop)$/.test(func)) return 'system';
  return 'crypto';
}
function classify(func: string): { algo: string; op: string } {
  if (func.startsWith('EVP_Cipher') || func.startsWith('EVP_Encrypt') || func.startsWith('EVP_Decrypt'))
    return { algo: '对称加解密', op: '明文' };
  if (func === 'HMAC_Update' || func === 'EVP_DigestSignUpdate') return { algo: 'HMAC', op: '消息' };
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
  return { algo: func, op: '捕获' };
}

// Plain-language crypto identification — turns raw captures into "this app uses X" so a
// colleague who can't reverse can read off the algorithms/keys/IVs at a glance (axis 1).
function cryptoIdentify() {
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
  const families = { symmetric: 0, asymmetric: 0, digest: 0, hmac: 0, tls: 0 };
  for (const a of algorithms) {
    if (/TLS/.test(a.algo)) families.tls += a.count;
    else if (/RSA|(^|[^m])EC[^B]|ECDSA|DSA/i.test(a.algo)) families.asymmetric += a.count;
    else if (/Hmac|HMAC/i.test(a.algo)) families.hmac += a.count;
    else if (/MD5|SHA|摘要|Digest/i.test(a.algo)) families.digest += a.count;
    else families.symmetric += a.count;
  }
  const withKey = algorithms.filter(a => a.keyHex).length;
  const summary = `捕获 ${captures.length} 次加密操作，涉及 ${algorithms.length} 种算法/用途；` +
    `其中 ${withKey} 种拿到了密钥。对称 ${families.symmetric} · 非对称 ${families.asymmetric} · 摘要 ${families.digest} · HMAC ${families.hmac} · TLS ${families.tls}。`;
  return { total: captures.length, families, algorithms, summary };
}

// Install persistent hooks on connect, then poll capture_drain and stream each new record
// into the store + over WS. Also auto-dump the app's DEX files so the panel can download
// them. Mirrors the ios-decrypt-helper flow (hooks stay live, events fill the panel).
function startCaptureLoop(sid: string) {
  setTimeout(async () => {
    if (settings.capture.enabled) {
      try { await sendCmd(sid, 'capture_start', captureModules(), 15_000); log(`capture_start ${sid}`); } catch (e) { log('capture_start failed', (e as Error).message); }
    }
    if (settings.capture.autoDumpDex) autoDumpDex(sid).catch((e) => log(`[capture] autoDumpDex ${sid} 失败:`, (e as Error).message));
    if (captureTimers.has(sid)) return;
    let busy = false;
    let drainErrLogged = false;   // fail-loud once per wedged-drain episode, not every 1.5s tick
    const processDrain = (r: any, now: number) => {
      for (const c of (r.jcaptures ?? [])) {
        if (c.in) recentJavaIn.set(c.in, now);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, source: 'java', func: c.op, algo: c.algo, op: c.op,
          category: 'crypto',
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.in, preview: hexToPreview(c.in),
          keyHex: c.key || '', ivHex: c.iv || '', outHex: c.out || '',
        };
        if (pushCapture(entry))
          broadcast('capture.new', { id: entry.id, sessionId: sid, source: 'java', category: entry.category, algo: entry.algo, op: entry.op, preview: entry.preview, inl: entry.inl, ts: entry.ts });
      }
      for (const [k, t] of recentJavaIn) if (now - t > 2000) recentJavaIn.delete(k);
      for (const c of (r.captures ?? [])) {
        if (c.hex && recentJavaIn.has(c.hex)) continue;   // already captured richly at the Java layer
        const { algo, op } = classify(c.func);
        const category = categoryOf(c.func);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, source: 'native', func: c.func, algo, op,
          category,
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.hex, preview: hexToPreview(c.hex),
        };
        if (pushCapture(entry))
          broadcast('capture.new', { id: entry.id, sessionId: sid, source: 'native', category, algo, op, preview: entry.preview, inl: entry.inl, ts: entry.ts });
      }
    };
    const timer = setInterval(async () => {
      if (busy || capturePaused.has(sid) || !sessions.get(sid)?.online) return;
      busy = true;
      try {
        // Drain repeatedly while the agent ring has a backlog, so a burst is pulled out
        // fast (WS-C: keeps drops near zero when the pipeline can keep up). Bounded so one
        // tick can't monopolise the session.
        let r: any, drains = 0, emittedTick = 0;
        do {
          r = await sendCmd(sid, 'capture_drain', {}, 8_000);
          emittedTick += (r?.count ?? 0);
          processDrain(r, Date.now());
          drains++;
        } while (r && r.backlog > 0 && drains < 60);
        drainErrLogged = false;   // a drain succeeded — clear the failure episode
        if (r) {
          const prev = capStats.get(sid);
          capStats.set(sid, { seq: r.seq ?? 0, emitted: (prev?.emitted ?? 0) + emittedTick,
            dropped: r.dropped ?? 0, jdropped: r.jdropped ?? 0,
            backlog: r.backlog ?? 0, firstDropNs: r.firstDropNs ?? 0, lastDropNs: r.lastDropNs ?? 0,
            complete: r.complete === true, ring: r.ring ?? 0, ts: Date.now() });
          // fail-loud: announce the first time this session starts dropping
          if ((r.dropped ?? 0) > 0 && (!prev || prev.dropped === 0))
            log(`[capture] session ${sid} DROPPING — ring full: dropped=${r.dropped} seq=${r.seq} (complete:false)`);
        }
      } catch (e) {
        if (!drainErrLogged) { drainErrLogged = true; log(`[capture] drain ${sid} 失败 (静默重试直至恢复):`, (e as Error).message); }
      } finally { busy = false; }
    }, 1500);
    captureTimers.set(sid, timer);
  }, 1200);
}

// Enumerate the app's DEX files and dump each so it's downloadable from the panel.
// Full unpack session (P3): T0 snapshot → coverage → active trigger → T1 snapshot →
// recover+rebuild per dex. Shared by REST (/api/unpack/run) and MCP (unpack_run).
async function runUnpackSession(sid: string, body: any) {
  const level = Number(body.level ?? 3);
  const snapshot = async (tag: string) => {
    const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
    const out: { begin: string; size: number; format: string; sha: string }[] = [];
    for (const d of (r.dexfiles ?? [])) {
      const begin = String(d.begin ?? ''); const size = Number(d.size ?? 0);
      if (!begin || !size || size > (64 << 20)) continue;
      try { const { meta } = await dumpRegion(sid, begin.replace(/^0x/, ''), size, tag); out.push({ begin, size, format: d.format ?? 'dex', sha: meta.sha256 }); }
      catch (e) { log(`[unpack] ${tag} dump 失败 @0x${begin} (${size}B):`, (e as Error).message); }
    }
    return out;
  };
  const t0 = await snapshot('unpack-t0');
  const targeted = new Set<string>();
  // Default the aggressive-enumeration prefix to the CONNECTED TARGET'S OWN package (from the
  // agent hello) — so "one-click unpack" works on whatever is attached, not a hardcoded
  // sandbox class. Caller may override (custom sub-package) or pass '' to disable enumeration.
  const prefix = body.triggerAllPrefix !== undefined ? String(body.triggerAllPrefix) : (sessions.get(sid)?.package ?? '');
  for (const s of t0) {
    try {
      const buf = await readFile(dumps.get(s.sha)!.path); const pd = parseDex(buf);
      // classes with extracted methods (targeted, highest priority)
      for (const m of analyzeCoverage(buf, pd).missing) {
        const dot = m.method.split('->')[0].replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
        if (dot) targeted.add(dot);
      }
      // aggressive mode: enumerate ALL classes under a package prefix to force resolution
      // (a refill-type shell restores each method's code_item when its class is linked)
      if (prefix) for (const c of pd.classes) {
        const dot = c.name.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
        if (dot.startsWith(prefix) && !dot.includes('$$')) targeted.add(dot);
      }
    } catch (e) { log(`[unpack] coverage 目标枚举失败 sha=${s.sha}:`, (e as Error).message); }
  }
  const classes = [...new Set([...(body.triggerClasses ?? []), ...targeted])].slice(0, Number(body.maxClasses ?? (prefix ? 500 : 50)));
  const triggered: any[] = [];
  for (const c of classes) {
    try { const r = await sendCmd(sid, 'trigger', { className: c, method: body.triggerMethod ?? '', level }, 15_000);
          triggered.push({ class: c, loaded: r.loaded, invoked: r.invoked, skipped: r.skipped, reason: r.reason }); } catch { triggered.push({ class: c, error: 'timeout' }); }
  }
  const t1 = await snapshot('unpack-t1');
  const t1ByBegin = new Map(t1.map(x => [x.begin, x]));
  const dexes: any[] = [];
  for (const b of t0) {
    const rest = t1ByBegin.get(b.begin) ?? b;
    try {
      const baseBuf = await readFile(dumps.get(b.sha)!.path);
      const restBuf = await readFile(dumps.get(rest.sha)!.path);
      const pd = parseDex(baseBuf); const before = analyzeCoverage(baseBuf, pd);
      const { captures: caps, report } = recoverFromSnapshots(baseBuf, restBuf, pd);
      const rb = rebuildStandardDex(baseBuf, caps);
      let parseOk = true; try { parseDex(rb.dex); } catch { parseOk = false; }
      const outSha = createHash('sha256').update(rb.dex).digest('hex');
      const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
      if (!existsSync(path)) writeFileSync(path, rb.dex);
      const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'unpack-session', addr: b.begin, tag: 'rebuilt', sessionId: sid, package: sessions.get(sid)?.package ?? '', capturedAt: Date.now(), path, kind: 'dex' };
      dumps.set(outSha, meta); broadcast('dump.new', meta);
      const afterPresent = before.basePresent + report.recovered;
      dexes.push({ format: b.format, size: b.size, sha0: b.sha, sha1: rest.sha, rebuiltSha: outSha, parseOk,
        concreteJava: before.concreteJava, presentBefore: before.basePresent, recovered: report.recovered, stillMissing: report.stillMissing,
        recoveryBeforePct: +(before.recoveryRate * 100).toFixed(2),
        recoveryAfterPct: before.concreteJava ? +((afterPresent / before.concreteJava) * 100).toFixed(2) : 100 });
    } catch (e) { dexes.push({ sha0: b.sha, error: (e as Error).message }); }
  }
  return { ok: true, session: sid, phases: ['snapshot-t0', 'coverage', 'trigger', 'snapshot-t1', 'recover'],
    t0Count: t0.length, t1Count: t1.length, triggered, dexes };
}

async function autoDumpDex(sid: string) {
  // art_dexfiles failure propagates to the caller's .catch(log); per-dex dump failures logged inline
  const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
  for (const d of (r.dexfiles ?? [])) {
    const begin = d.begin;
    const size = Number(d.size ?? 0);
    if (!begin || !size || size > (64 << 20)) continue;
    try { await dumpRegion(sid, String(begin).replace(/^0x/, ''), size, 'dex-auto'); }
    catch (e) { log(`[capture] autoDumpDex ${sid} dump 失败 @0x${begin}:`, (e as Error).message); }
  }
}

const wss = new WebSocketServer({ noServer: true });
function broadcast(event: string, data: unknown) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  for (const c of wss.clients) if (c.readyState === WebSocket.OPEN) c.send(msg);
  if (event !== 'snapshot') recordEvent(event, data);   // persist for record/replay
}
function log(...a: unknown[]) {
  console.log(`[idhd ${new Date().toISOString()}]`, ...a);
}
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => resolve(b));
  });
}

// ---- Agent TCP server (NDJSON) -------------------------------------------

const agentServer = net.createServer((sock) => {
  let session: AgentSession | null = null;
  let acc: Buffer = Buffer.alloc(0);
  sock.setNoDelay(true);

  sock.on('data', (chunk: Buffer) => {
    acc = acc.length ? Buffer.concat([acc, chunk]) : chunk;
    for (;;) {
      if (acc.length < 5) break;
      const len = acc.readUInt32BE(0);
      const type = acc.readUInt8(4);
      if (len > FRAME_MAX) { log(`agent frame too large ${len} type=${type} — closing`); sock.destroy(); return; }
      if (acc.length < 5 + len) break;                 // wait for the rest of the frame
      const payload = acc.subarray(5, 5 + len);
      acc = acc.subarray(5 + len);
      if (type !== FRAME_JSON) { log(`agent unknown frame type ${type} — skipping`); continue; }
      let msg: AgentMsg;
      try { msg = JSON.parse(payload.toString('utf8')); } catch { log('bad json frame from agent, bytes=', len); continue; }
      handle(msg);
    }
  });

  function handle(msg: AgentMsg) {
    if (msg.t === 'hello') {
      const id = nextId();
      session = {
        sessionId: id,
        pid: msg.pid ?? 0,
        uid: msg.uid ?? 0,
        package: msg.package ?? '?',
        process: msg.process ?? msg.package ?? '?',
        abi: msg.abi ?? '?',
        android: msg.android ?? '?',
        sdk: msg.sdk ?? 0,
        entry: msg.entry ?? '?',
        agentVer: msg.agentVer ?? '?',
        connectedAt: Date.now(),
        lastSeen: Date.now(),
        online: true,
        mapsCount: 0,
        regionsSample: [],
      };
      sessions.set(id, session);
      agentSockets.set(id, sock);
      log(`agent HELLO ${session.package} pid=${session.pid} abi=${session.abi} entry=${session.entry} -> ${id}`);
      sock.write(frameJson({ t: 'ack', sessionId: id }));
      broadcast('agent.hello', session);
      startCaptureLoop(id);   // install persistent hooks + stream captures to the panel
    } else if (msg.t === 'maps' && session) {
      session.mapsCount = msg.count;
      session.regionsSample = (msg.regions ?? []).slice(0, 50);
      session.lastSeen = Date.now();
      log(`agent MAPS ${session.package} count=${msg.count}`);
      broadcast('agent.maps', { sessionId: session.sessionId, count: msg.count });
    } else if (msg.t === 'ping' && session) {
      session.lastSeen = Date.now();
      sock.write(frameJson({ t: 'pong' }));
    } else if (msg.t === 'cmdResult') {
      const p = pending.get(msg.id);
      log(`cmdResult op=${msg.op} id=${msg.id} matched=${!!p} bytes=${JSON.stringify(msg).length}`);
      if (p) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg); }
      if (session) session.lastSeen = Date.now();
    }
  }

  sock.on('close', () => {
    if (session) {
      session.online = false;
      session.lastSeen = Date.now();
      agentSockets.delete(session.sessionId);
      const t = captureTimers.get(session.sessionId);
      if (t) { clearInterval(t); captureTimers.delete(session.sessionId); }
      log(`agent CLOSE ${session.package} ${session.sessionId}`);
      broadcast('agent.close', { sessionId: session.sessionId });
    }
  });
  sock.on('error', (e) => log('agent sock error:', (e as Error).message));
});

// ---- dump engine ----------------------------------------------------------

function inferKind(b: Buffer): string {
  if (b.length >= 4 && b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a) return 'dex';
  if (b.length >= 4 && b[0] === 0x63 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return 'cdex';
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'so';
  if (b.length >= 2 && b[0] === 0x50 && b[1] === 0x4b) return 'zip';
  if (b.length >= 4 && b[0] === 0x76 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return 'vdex';
  if (b.length >= 4 && b[0] === 0x6f && b[1] === 0x61 && b[2] === 0x74 && b[3] === 0x0a) return 'oat';
  return 'region';
}

// Read [addr, addr+size) from the target via chunked agent reads. Stops on short read.
async function readMem(sid: string, addr: bigint, size: number): Promise<Buffer> {
  const CHUNK = 1 << 20;
  const parts: Buffer[] = [];
  let a = addr, remaining = size;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: a.toString(16), size: want }, 20_000);
    if (!r.ok) break;
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    a += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) break;
  }
  return Buffer.concat(parts);
}

interface ModuleInfo { name: string; path: string; base: string; end: string; size: number; segs: number; }
function modulesFromMaps(regions: MapsRegion[]): ModuleInfo[] {
  const by = new Map<string, MapsRegion[]>();
  for (const r of regions) {
    if (!r.path || !/\.(so|apk|jar|oat|odex|vdex|dex)$/.test(r.path)) continue;
    (by.get(r.path) ?? by.set(r.path, []).get(r.path)!).push(r);
  }
  const out: ModuleInfo[] = [];
  for (const [path, regs] of by) {
    const starts = regs.map(r => BigInt('0x' + r.start));
    const ends = regs.map(r => BigInt('0x' + r.end));
    const base = starts.reduce((m, v) => (v < m ? v : m));
    const end = ends.reduce((m, v) => (v > m ? v : m));
    out.push({ name: path.split('/').pop()!, path, base: base.toString(16), end: end.toString(16), size: Number(end - base), segs: regs.length });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// Reconstruct a loaded .so from memory into a valid ELF (SoFixer-lite):
// file offsets are laid out == virtual addresses, section headers dropped,
// program headers preserved so PT_DYNAMIC (dynsym/dynstr) resolves for analysis.
async function reconstructSo(sid: string, baseHex: string): Promise<Buffer> {
  const base = BigInt('0x' + baseHex);
  const ehdr = await readMem(sid, base, 64);
  if (ehdr.length < 64 || ehdr.readUInt32LE(0) !== 0x464c457f) throw new Error('no ELF header at base');
  if (ehdr[4] !== 2) throw new Error('only ELF64 supported in v0.2');
  const phoff = ehdr.readBigUInt64LE(32);
  const phentsize = ehdr.readUInt16LE(54);
  const phnum = ehdr.readUInt16LE(56);
  if (phnum === 0 || phentsize < 56) throw new Error('bad program headers');
  const phBuf = await readMem(sid, base + phoff, phnum * phentsize);

  // pass 1: image size = max(p_vaddr + p_memsz) over PT_LOAD
  let imgSize = 0n;
  const loads: { vaddr: bigint; memsz: bigint }[] = [];
  for (let i = 0; i < phnum; i++) {
    const p = phBuf.subarray(i * phentsize);
    if (p.readUInt32LE(0) !== 1) continue;              // PT_LOAD
    const vaddr = p.readBigUInt64LE(16), memsz = p.readBigUInt64LE(40);
    loads.push({ vaddr, memsz });
    if (vaddr + memsz > imgSize) imgSize = vaddr + memsz;
  }
  if (imgSize === 0n || imgSize > 512n * 1024n * 1024n) throw new Error('implausible image size');
  const image = Buffer.alloc(Number(imgSize));

  // pass 2: copy each PT_LOAD's memory to file offset == vaddr
  for (const { vaddr, memsz } of loads) {
    const seg = await readMem(sid, base + vaddr, Number(memsz));
    seg.copy(image, Number(vaddr));
  }
  // rewrite ehdr in image: drop section headers
  ehdr.copy(image, 0, 0, 64);
  image.writeBigUInt64LE(0n, 40);   // e_shoff = 0
  image.writeUInt16LE(0, 60);       // e_shnum = 0
  image.writeUInt16LE(0, 62);       // e_shstrndx = 0
  // rewrite each phdr: p_offset = p_vaddr, p_filesz = p_memsz
  for (let i = 0; i < phnum; i++) {
    const off = Number(phoff) + i * phentsize;
    if (off + 56 > image.length) break;
    const vaddr = image.readBigUInt64LE(off + 16);
    const memsz = image.readBigUInt64LE(off + 40);
    image.writeBigUInt64LE(vaddr, off + 8);   // p_offset = p_vaddr
    image.writeBigUInt64LE(memsz, off + 32);  // p_filesz = p_memsz
  }
  return image;
}

// ---- dex header repair ----------------------------------------------------

function adler32(buf: Buffer, start = 0): number {
  let a = 1, b = 0; const MOD = 65521;
  for (let i = start; i < buf.length; i++) {
    a = (a + buf[i]) % MOD;
    b = (b + a) % MOD;
  }
  return ((b << 16) | a) >>> 0;
}

// Repair a dumped dex's self-describing header fields (mutates buf):
//   file_size@32 = length ; signature@12(20) = SHA-1(bytes[32..]) ; checksum@8 = adler32(bytes[12..])
// Order matters: file_size is covered by signature & checksum; signature is covered by checksum.
function repairDexHeader(buf: Buffer): { fileSize: number; checksum: string; signature: string; magicOk: boolean } {
  const magicOk = buf.length >= 40 && buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a;
  const fileSize = buf.length;
  buf.writeUInt32LE(fileSize, 32);
  const sig = createHash('sha1').update(buf.subarray(32)).digest();
  sig.copy(buf, 12);
  const checksum = adler32(buf, 12);
  buf.writeUInt32LE(checksum, 8);
  return { fileSize, checksum: checksum.toString(16).padStart(8, '0'), signature: sig.toString('hex'), magicOk };
}

// Dump [addr, addr+size) by orchestrating chunked agent reads, then sha256 + dedup + persist.
async function dumpRegion(sid: string, addrHex: string, size: number, tag: string): Promise<{ meta: DumpMeta; dedup: boolean }> {
  const CHUNK = 1 << 20;                          // matches agent per-read cap
  let addr = BigInt('0x' + addrHex);
  const parts: Buffer[] = [];
  let remaining = size;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: addr.toString(16), size: want }, 20_000);
    if (!r.ok) { if (parts.length) break; throw new Error(`read failed @0x${addr.toString(16)}: ${r.error}`); }
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    addr += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) break;                   // short read (unreadable tail)
  }
  const buf = Buffer.concat(parts);
  const sha = createHash('sha256').update(buf).digest('hex');
  const existing = dumps.get(sha);
  if (existing) return { meta: existing, dedup: true };
  const s = sessions.get(sid);
  const kind = inferKind(buf);
  const path = join(CAPTURES, `${sha.slice(0, 16)}.${kind}.bin`);
  if (!existsSync(path)) writeFileSync(path, buf);
  const meta: DumpMeta = {
    sha256: sha, size: buf.length, source: 'region', addr: addrHex, tag,
    sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind,
  };
  dumps.set(sha, meta);
  broadcast('dump.new', meta);
  return { meta, dedup: false };
}

// ---- MCP Server (Streamable HTTP / JSON-RPC) ------------------------------
// Exposes the workbench Service Layer as MCP tools for AI clients. Shares the
// same logic as the REST API (no duplicate business logic).
const pickSid = (sid?: string) => sid ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
async function agentCmd(sid: string | undefined, op: string, args: Record<string, unknown> = {}, timeout = 15_000) {
  const s = pickSid(sid); if (!s) throw new Error('no online agent session');
  return sendCmd(s, op, args, timeout);
}
async function dumpBuf(a: any): Promise<Buffer> {
  if (a.b64) return Buffer.from(a.b64, 'base64');
  if (a.sha && dumps.get(a.sha)) {
    try { return await readFile(dumps.get(a.sha)!.path); }
    catch { const e: any = new Error('dump missing'); e.status = 404; throw e; }   // registry knows it, disk lost it
  }
  const e: any = new Error('need b64 or known sha'); e.status = 400; throw e;
}
// File-path variant for the shell-out analyzers (llvm-objdump/readelf need a path, not a
// Buffer). Known sha → its stored path (no copy); b64 → a unique temp file the caller unlinks.
let tmpSeq = 0;
async function dumpBufPath(a: any): Promise<{ path: string; tmp: string | null }> {
  if (a.sha && dumps.get(a.sha)) return { path: dumps.get(a.sha)!.path, tmp: null };
  if (a.b64) { const tmp = join(tmpdir(), `idh_so_${Date.now()}_${++tmpSeq}.so`); writeFileSync(tmp, Buffer.from(a.b64, 'base64')); return { path: tmp, tmp }; }
  const e: any = new Error('need b64 or known sha'); e.status = 400; throw e;
}
const S = { type: 'string' }, N = { type: 'number' };
const MCP_TOOLS: { name: string; description: string; inputSchema: any; handler: (a: any) => Promise<any> }[] = [
  { name: 'process_list', description: 'List connected target agent sessions', inputSchema: { type: 'object', properties: {} }, handler: async () => [...sessions.values()] },
  { name: 'dumps_list', description: 'List captured dump artifacts (dex/so/region)', inputSchema: { type: 'object', properties: {} }, handler: async () => [...dumps.values()] },
  { name: 'compat_probe', description: 'Self-assess agent env: tracer/seccomp/hook-backend availability', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'compat_probe') },
  { name: 'memory_maps', description: 'On-demand full /proc/self/maps of the target', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'maps') },
  { name: 'memory_read', description: 'Read target memory at hex addr for size bytes (base64 out)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: (a) => agentCmd(a.session, 'read', { addr: a.addr, size: a.size }) },
  { name: 'memory_search', description: 'Search target memory for hex or text pattern', inputSchema: { type: 'object', properties: { session: S, hex: S, text: S, limit: N } }, handler: (a) => agentCmd(a.session, 'search', { pat: a.hex ?? Buffer.from(String(a.text ?? ''), 'utf8').toString('hex'), limit: a.limit ?? 256 }, 90_000) },
  { name: 'memory_scan_magic', description: 'Scan target memory for dex/elf/oat/vdex/zip magics', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'scan_magic', {}, 90_000) },
  { name: 'art_dexfiles', description: 'Enumerate loaded DexFiles via ART ClassLoader structures (no magic scan)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'art_dexfiles', {}, 30_000) },
  { name: 'crypto_capture', description: 'Hook EVP_CipherUpdate + trigger the target’s crypto workload class; return captured plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'crypto_hook_test', { className: a.class ?? SANDBOX.crypto }, 20_000) },
  { name: 'net_capture', description: 'Hook SSL_write/SSL_read + trigger HTTPS; return captured TLS plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'net_hook_test', { className: a.class ?? SANDBOX.net }, 25_000) },
  { name: 'file_probe', description: 'Recon which loaded module’s GOT holds open/openat/read/write/close pointers (guides file_capture’s module arg)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'file_probe', {}, 20_000) },
  { name: 'file_capture', description: 'Hook open/openat/read/write/close + trigger the target’s file I/O; return captured paths + read/write bytes', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'file_hook_test', { module: a.module ?? settings.capture.fileModule, className: a.class ?? SANDBOX.file }, 25_000) },
  { name: 'detect_watch', description: 'Observe the target’s own anti-analysis checks (debug/root/prop)', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'detect_watch', { module: a.module ?? settings.capture.sysModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'object_inspect', description: 'Read a live Java object’s fields via reflection (static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S }, required: ['className', 'field'] }, handler: (a) => agentCmd(a.session, 'object_inspect', { className: a.className, field: a.field }) },
  { name: 'dex_search', description: 'Search a dex (b64|sha) for strings/classes/methods', inputSchema: { type: 'object', properties: { b64: S, sha: S, query: S, kinds: { type: 'array', items: S } }, required: ['query'] }, handler: async (a) => searchDex(parseDex(await dumpBuf(a)), a.query, a.kinds) },
  { name: 'dex_xref', description: 'Find callers of a method in a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, method: S }, required: ['method'] }, handler: async (a) => { const buf = await dumpBuf(a); const { xref } = invokeXref(buf, parseDex(buf)); const q = String(a.method).toLowerCase(); const out: Record<string, string[]> = {}; for (const [c, cs] of xref) if (c.toLowerCase().includes(q)) out[c] = cs.slice(0, 200); return out; } },
  { name: 'dex_crypto_scan', description: 'Static crypto scan of a dex (API refs + algorithm strings)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoScan(parseDex(await dumpBuf(a))) },
  { name: 'native_disasm', description: 'Disassemble an ELF .so (b64|sha) by symbol', inputSchema: { type: 'object', properties: { b64: S, sha: S, symbol: S }, required: ['symbol'] }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await disasmSo(t, { symbol: a.symbol }); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_analyze', description: 'Exports/imports/NEEDED/strings of an ELF .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await analyzeSo(t); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_crypto_const', description: 'Locate crypto by constant signatures in a stripped .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoConstScan(await dumpBuf(a)) },
  { name: 'native_syscall_scan', description: 'Find direct svc #0 syscalls in a .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => svcScan(await dumpBuf(a)) },
  { name: 'memory_dump', description: 'Dump target memory [addr,addr+size) to a capture artifact (sha256 dedup)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); const { meta, dedup } = await dumpRegion(sid, String(a.addr).replace(/^0x/, ''), Number(a.size), 'mcp'); return { ...meta, dedup }; } },
  { name: 'flow_correlate', description: 'Hook EVP+SSL_write, trigger encrypt-then-send, capture plaintext+request (tid/ts)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'object_invoke', description: 'Call a no-arg method on a live object (via static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S, method: S }, required: ['className', 'field', 'method'] }, handler: (a) => agentCmd(a.session, 'object_invoke', { className: a.className, field: a.field, method: a.method }) },
  { name: 'trace_function', description: 'Trace calls to a native symbol (args+tid+ts) while the target’s detection workload runs', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S, hookModule: S, class: S }, required: ['symbol', 'hookModule'] }, handler: (a) => agentCmd(a.session, 'trace_run', { symLib: a.symLib ?? 'libc.so', symbol: a.symbol, hookModule: a.hookModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'dex_method_code', description: 'Extract a method’s runtime code_item bytecode from a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, class: S, method: S }, required: ['class'] }, handler: async (a) => { const buf = await dumpBuf(a); return extractMethodCode(buf, parseDex(buf), String(a.class), a.method); } },
  { name: 'dex_repair', description: 'Repair a dumped dex header (file_size/checksum/signature)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const buf = await dumpBuf(a); const info = repairDexHeader(buf); return { ...info, repairedB64: buf.toString('base64') }; } },
  // ---- axis 1: one-glance crypto algorithm identification ----
  { name: 'crypto_identify', description: '一眼看清目标 App 用了哪些加密算法/密钥/IV — summarize all captured crypto (algorithm, key, iv, plaintext) into a plain-language report for non-experts', inputSchema: { type: 'object', properties: {} }, handler: async () => cryptoIdentify() },
  { name: 'live_captures', description: 'List the live captures streamed by the persistent hooks — crypto / net(TLS) / file / system, filterable by category (algorithm+op+preview, newest last)', inputSchema: { type: 'object', properties: { limit: N, category: S } }, handler: async (a) => { const cat = a.category ? String(a.category) : ''; const list = cat ? captures.filter(c => c.category === cat) : captures; return { total: list.length, on: captureTimers.size > 0, captures: list.slice(-(Number(a.limit) || 50)).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, inl: c.inl, tid: c.tid, ts: c.ts, preview: c.preview })) }; } },
  { name: 'capture_detail', description: 'Full detail of one capture by id: algorithm, key(hex), iv(hex), plaintext(utf8+hex), ciphertext(hex)', inputSchema: { type: 'object', properties: { id: N }, required: ['id'] }, handler: async (a) => { const c = captures.find(x => x.id === Number(a.id)); if (!c) throw new Error('not found'); const text = Buffer.from(c.hex, 'hex').toString('utf8'); return { ...c, text }; } },
  // ---- axis 2: one-click unpack (no AOSP flashing needed) ----
  { name: 'dex_coverage', description: '方法恢复率报告 — per-method state (native/abstract/present/extracted) + recovery rate over a dumped dex', inputSchema: { type: 'object', properties: { b64: S, sha: S }, required: [] }, handler: async (a) => { const buf = await dumpBuf(a); return analyzeCoverage(buf, parseDex(buf)); } },
  { name: 'unpack_run', description: '一键脱壳（无需刷 AOSP）— full unpack session: T0 snapshot → coverage → active trigger → T1 snapshot → recover+rebuild. Set triggerAllPrefix (e.g. "com.target.") to aggressively load ALL of the app\'s classes so a refill-type shell restores every method. Returns per-dex before/after recovery + rebuilt dex sha', inputSchema: { type: 'object', properties: { session: S, triggerAllPrefix: S, triggerClasses: { type: 'array', items: S }, triggerMethod: S, level: N, maxClasses: N } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return runUnpackSession(sid, a); } },
  { name: 'dex_recover', description: 'Recover extracted CodeItems from a restored snapshot into a base dex + rebuild (baseSha/baseB64 + restoredSha/restoredB64)', inputSchema: { type: 'object', properties: { baseB64: S, baseSha: S, restoredB64: S, restoredSha: S } }, handler: async (a) => { const base = await dumpBuf({ b64: a.baseB64, sha: a.baseSha }); const restored = await dumpBuf({ b64: a.restoredB64, sha: a.restoredSha }); const pd = parseDex(base); const { captures: caps, report } = recoverFromSnapshots(base, restored, pd); const rb = rebuildStandardDex(base, caps); const outSha = createHash('sha256').update(rb.dex).digest('hex'); const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`); if (!existsSync(path)) writeFileSync(path, rb.dex); dumps.set(outSha, { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' }); return { ...report, injected: rb.injected, sha256: outSha }; } },
  // ---- axis 3: everything the AI needs to drive a reversing session ----
  { name: 'trigger', description: 'Actively load a class (level 1) and invoke a safe static no-arg method (level 3) to force code paths — a trigger source for unpacking', inputSchema: { type: 'object', properties: { session: S, class: S, method: S, level: N }, required: ['class'] }, handler: (a) => agentCmd(a.session, 'trigger', { className: a.class, method: a.method ?? '', level: Number(a.level ?? 1) }, 20_000) },
  { name: 'qbdi_trace', description: 'QBDI instruction-level dynamic trace of a native function (per-instruction disassembly + return value)', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S }, required: ['symbol'] }, handler: (a) => agentCmd(a.session, 'qbdi_trace', { symLib: a.symLib ?? 'libidhdetect.so', symbol: a.symbol }, 30_000) },
  { name: 'net_correlate', description: 'Network↔crypto correlation: pair plaintext with the TLS request carrying its ciphertext (same thread + time window)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'load_library', description: '把任意 .so 加载进目标进程（如 frida-gadget，随后 gadget 会按 script 模式自动跑你的 frida 脚本）。可选 symbol 探测。dlopen from inside the target.', inputSchema: { type: 'object', properties: { session: S, path: S, symbol: S }, required: ['path'] }, handler: (a) => agentCmd(a.session, 'load_so', { path: a.path, symbol: a.symbol ?? '' }, 30_000) },
];
const MCP_MAP = new Map(MCP_TOOLS.map(t => [t.name, t]));

async function handleMcp(reqBody: string, res: http.ServerResponse) {
  let msg: any;
  try { msg = JSON.parse(reqBody); } catch { res.writeHead(400).end('bad json'); return; }
  const reply = (result?: unknown, error?: unknown) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...(error ? { error } : { result }) });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(body);
  };
  if (msg.method === 'initialize') return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'idhd', version: '0.1.0' } });
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') { res.writeHead(202).end(); return; }
  if (msg.method === 'ping') return reply({});
  if (msg.method === 'tools/list') return reply({ tools: MCP_TOOLS.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
  if (msg.method === 'tools/call') {
    const t = MCP_MAP.get(msg.params?.name);
    if (!t) return reply(undefined, { code: -32602, message: `unknown tool: ${msg.params?.name}` });
    try {
      const out = await t.handler(msg.params?.arguments ?? {});
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    } catch (e) { return reply({ content: [{ type: 'text', text: 'error: ' + (e as Error).message }], isError: true }); }
  }
  return reply(undefined, { code: -32601, message: `method not found: ${msg.method}` });
}

// ---- HTTP + WebSocket -----------------------------------------------------

async function handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost`);
  const send = (code: number, body: unknown, type = 'application/json') => {
    const s = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': type, 'access-control-allow-origin': '*' });
    res.end(s);
  };

  if (url.pathname === '/health') {
    return send(200, { ok: true, service: 'idhd', version: '0.1.0', agents: sessions.size, uptime: process.uptime(), mcpTools: MCP_TOOLS.length, web: webUrls() });
  }
  // MCP Streamable HTTP endpoint (JSON-RPC)
  if (url.pathname === '/mcp' && req.method === 'POST') {
    return handleMcp(await readBody(req), res);
  }
  // Live captures (auto-populated by the persistent hooks): GET /api/captures?since=&limit=
  if (url.pathname === '/api/captures') {
    const since = Number(url.searchParams.get('since') ?? 0);
    const limit = Math.min(Number(url.searchParams.get('limit') ?? 200), 1000);
    const list = captures.filter(c => c.id > since);
    // list view omits full hex; detail view (/api/captures/:id) carries it.
    // WS-C: `health` carries honest ring accounting — complete:false + dropped>0 when the
    // agent ring overflowed (no silent loss; the panel should show this in red).
    const health = captureHealth();
    return send(200, {
      total: captures.length, on: captureTimers.size > 0,
      complete: health.complete, dropped: health.dropped, jdropped: health.jdropped,
      seq: health.seq, backlog: health.backlog, health,
      captures: list.slice(-limit).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, func: c.func, inl: c.inl, tid: c.tid, ts: c.ts, preview: c.preview })),
    });
  }
  if (url.pathname.startsWith('/api/captures/')) {
    const id = Number(url.pathname.slice('/api/captures/'.length));
    const c = captures.find(x => x.id === id);
    if (!c) return send(404, { error: 'not found' });
    // decode as UTF-8 so Chinese plaintext (gray-market payloads) is readable, not dotted
    let text = '';
    try { text = Buffer.from(c.hex, 'hex').toString('utf8'); } catch { text = hexToPreview(c.hex, 4096); }
    return send(200, { ...c, text });
  }
  // Session events (record/replay): GET /api/events?type=&limit=&since=
  if (url.pathname === '/api/events') {
    const type = url.searchParams.get('type');
    const since = Number(url.searchParams.get('since') ?? 0);
    const limit = Math.min(Number(url.searchParams.get('limit') ?? 500), 5000);
    let list = events.filter(e => e.seq > since && (!type || e.type === type));
    return send(200, { total: events.length, returned: Math.min(list.length, limit), events: list.slice(-limit) });
  }
  // Diagnostic report / export (P/R) — metadata only, no captured keys/plaintext.
  if (url.pathname === '/api/export/report') {
    return send(200, {
      report: 'idh-diagnostic', version: '0.1.0', generatedAt: new Date().toISOString(), uptime: process.uptime(),
      agents: [...sessions.values()].map(s => ({ sessionId: s.sessionId, package: s.package, pid: s.pid, abi: s.abi, android: s.android, sdk: s.sdk, entry: s.entry, online: s.online, mapsCount: s.mapsCount })),
      dumps: [...dumps.values()].map(d => ({ sha256: d.sha256, kind: d.kind, size: d.size, source: d.source, tag: d.tag, capturedAt: d.capturedAt })),
      capabilities: { rest: true, websocket: true, mcp: true, mcpTools: MCP_TOOLS.length },
      note: 'metadata only — captured key/plaintext content is never in diagnostic reports',
    });
  }
  // ---- settings / config (web 设置面板；IDH 交互) ----
  // GET  /api/config          → { settings, stats }
  // POST /api/config          → section-merge patch, persist, apply live
  if (url.pathname === '/api/config') {
    if (req.method === 'POST') {
      let patch: any = {};
      try { patch = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      const applied = mergeSettings(patch);
      while (captures.length > settings.capture.retain) captures.shift();
      applyCaptureEnabled().catch((e) => log('[settings] applyCaptureEnabled:', (e as Error).message));
      // Persist last, and tell the truth: a failed write must NOT return ok — the UI would lie "已保存".
      try { saveSettings(); }
      catch (e) { return send(500, { error: '设置已在内存生效，但写入磁盘失败(重启后丢失): ' + (e as Error).message, applied, settings, persisted: false }); }
      return send(200, { ok: true, applied, settings, stats: configStats(), persisted: true });
    }
    return send(200, { settings, stats: configStats() });
  }
  // GET /api/settings/export → the raw settings object (for the 配置 JSON editor / download)
  if (url.pathname === '/api/settings/export') return send(200, settings);
  // POST /api/settings/import → section-merge (capture/ui), like IDH; returns { applied }
  if (url.pathname === '/api/settings/import' && req.method === 'POST') {
    let obj: any;
    try { obj = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'JSON 格式错误' }); }
    if (typeof obj !== 'object' || Array.isArray(obj)) return send(400, { error: '顶层必须是对象' });
    const applied = mergeSettings(obj);
    if (!applied.length) return send(400, { error: '没有可应用的板块(capture/ui)' });
    while (captures.length > settings.capture.retain) captures.shift();
    applyCaptureEnabled().catch((e) => log('[settings] applyCaptureEnabled:', (e as Error).message));
    try { saveSettings(); }
    catch (e) { return send(500, { error: '导入已在内存生效，但写入磁盘失败(重启后丢失): ' + (e as Error).message, applied, settings, persisted: false }); }
    return send(200, { ok: true, applied, settings, persisted: true });
  }
  // POST /api/data/clear { what: 'captures'|'events'|'dumps' } → 危险操作，清空对应存储
  if (url.pathname === '/api/data/clear' && req.method === 'POST') {
    let body: any;
    try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
    const what = String(body.what || '');
    const errors: string[] = [];
    if (what === 'captures') { captures.length = 0; recentJavaIn.clear(); }
    else if (what === 'events') {
      events.length = 0;
      try { writeFileSync(EVENTS_FILE, ''); } catch (e) { errors.push(`events 回放文件: ${(e as Error).message}`); }
    }
    else if (what === 'dumps') {
      for (const d of dumps.values()) {
        try { if (existsSync(d.path)) unlinkSync(d.path); } catch (e) { errors.push(`${d.path}: ${(e as Error).message}`); }
      }
      dumps.clear();
    } else return send(400, { error: 'what 必须是 captures|events|dumps' });
    broadcast('data.cleared', { what });
    // Fail loud: if any on-disk delete failed, the memory index is cleared but files remain — say so.
    if (errors.length) { log(`[data/clear] ${what} 部分磁盘删除失败:`, errors.join('; ')); return send(500, { error: `内存索引已清，但磁盘删除失败(${errors.length}项)`, cleared: what, errors, stats: configStats() }); }
    return send(200, { ok: true, cleared: what, stats: configStats() });
  }
  // MCP tool inventory as markdown (for docs/mcp-tools.md)
  if (url.pathname === '/api/mcp/doc') {
    const md = ['# ADH MCP Tools', '', `Generated from the live idhd registry (${MCP_TOOLS.length} tools). Endpoint: \`POST /mcp\` (JSON-RPC 2.0).`, '',
      '| Tool | Description | Args |', '|---|---|---|',
      ...MCP_TOOLS.map(t => `| \`${t.name}\` | ${t.description} | ${Object.keys(t.inputSchema.properties ?? {}).join(', ') || '—'} |`), ''].join('\n');
    res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' }); return res.end(md);
  }
  // Plain-language crypto identification (axis 1): GET /api/crypto/identify
  if (url.pathname === '/api/crypto/identify') return send(200, cryptoIdentify());
  // One-click MCP config (axis 3): GET /api/mcp/config — paste into Claude/Cursor, then ask the AI
  if (url.pathname === '/api/mcp/config') {
    const w = webUrls(); const lan = (w.lan[0] ?? w.local).replace(/^http/, 'http');
    const mcpUrl = `${lan}/mcp`;
    const cfg = {
      note: '把 mcpServers 这段粘进 Claude Desktop / Cursor 的 MCP 配置，重启后即可让 AI 调用 ADH 的全部逆向工具（分析内存/指令/hook/trace/事件搜索/抓包/脱壳/算法识别）',
      mcpServers: { adh: { type: 'http', url: mcpUrl } },
      endpoint: mcpUrl, tools: MCP_TOOLS.length,
      cli: `claude mcp add --transport http adh "${mcpUrl}"`,
      quickAsks: [
        '用 crypto_identify 看看这个 App 用了哪些加密算法和密钥',
        '用 unpack_run 一键脱壳，然后 dumps_list 给我下载链接',
        '用 live_captures 看实时加解密，挑一条用 capture_detail 展开明文',
        '用 trace_function hook 一下 access，看它检测了哪些 root 路径',
        '用 qbdi_trace 逐指令跟踪这个 native 函数',
      ],
    };
    return send(200, cfg);
  }
  if (url.pathname === '/api/agents') {
    return send(200, [...sessions.values()]);
  }
  if (url.pathname.startsWith('/api/agents/')) {
    const s = sessions.get(url.pathname.split('/')[3]);
    return s ? send(200, s) : send(404, { error: 'no such session' });
  }
  // On-demand full maps from the agent: GET /api/process/maps?session=ID
  // WS-D protocol self-test: GET /api/debug/frame_echo?session=ID&kb=N — send a command
  // frame with an N-KB `pad` field and a `tail` sentinel placed AFTER it; the agent echoes
  // back how many bytes it received and the tail. Proves the inbound command path carries
  // frames far past the old 8192 single-line cap without truncation.
  if (url.pathname === '/api/debug/frame_echo') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    const kb = Math.max(1, Math.min(4096, Number(url.searchParams.get('kb') ?? 64)));
    const padLen = kb * 1024;
    const pad = 'A'.repeat(padLen);            // JSON-safe ASCII; sits before `tail`
    const tail = 'IDH_FRAME_TAIL_v1';
    try {
      const r = await sendCmd(sid, 'frame_echo', { pad, tail, padLen }, 20_000);
      return send(r.ok ? 200 : 502, { ...r, sentPadLen: padLen, tailOk: r.tail === tail, notTruncated: (r.recvBytes ?? 0) > padLen });
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Java method-hook self-test (WS-A / LSPlant): GET /api/java/hook_test?session=ID
  if (url.pathname === '/api/java/hook_test') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'java_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.javaHook }, 25_000)); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  if (url.pathname === '/api/process/maps') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'maps');
      if (r.ok) { const s = sessions.get(sid); if (s) s.mapsCount = r.count; }
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Runtime Object Inspector (module T): POST /api/object/inspect {session, className, field}
  if (url.pathname === '/api/object/inspect' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, className, field } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !className || !field) return send(400, { error: 'need session, className, field' });
    try { const r = await sendCmd(sid, 'object_inspect', { className, field }); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Object method invocation (module T, low-risk): POST /api/object/invoke {session, className, field, method}
  if (url.pathname === '/api/object/invoke' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, className, field, method } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !className || !field || !method) return send(400, { error: 'need session, className, field, method' });
    try { const r = await sendCmd(sid, 'object_invoke', { className, field, method }); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Compatibility / anti-interference diagnostic (module S): GET /api/compat/probe?session=ID
  if (url.pathname === '/api/compat/probe') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'compat_probe'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // QBDI instruction-level trace (I.3): GET /api/trace/qbdi?session=ID&symLib=&symbol=
  if (url.pathname === '/api/trace/qbdi') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    const symLib = url.searchParams.get('symLib') ?? 'libidhdetect.so';
    const symbol = url.searchParams.get('symbol') ?? 'idh_trace_target';
    try { const r = await sendCmd(sid, 'qbdi_trace', { symLib, symbol }, 30_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Generic native function trace (I.2): GET /api/trace/run?session=ID&symLib=&symbol=&hookModule=
  if (url.pathname === '/api/trace/run') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    const symLib = url.searchParams.get('symLib') ?? 'libc.so';
    const symbol = url.searchParams.get('symbol') ?? 'access';
    const hookModule = url.searchParams.get('hookModule') ?? 'libidhdetect.so';
    try { const r = await sendCmd(sid, 'trace_run', { symLib, symbol, hookModule, className: url.searchParams.get('class') ?? SANDBOX.detect }, 20_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Anti-analysis behavior observation (module V): GET /api/detect/watch?session=ID
  if (url.pathname === '/api/detect/watch') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    // Suspend continuous capture: detect_watch installs+restores its own ptrace/access/prop
    // hooks on the same GOT slots the persistent system hooks now use.
    try { const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'detect_watch', { module: url.searchParams.get('module') ?? settings.capture.sysModule, className: url.searchParams.get('class') ?? SANDBOX.detect }, 20_000)); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Crypto hook recon: GET /api/crypto/probe?session=ID
  if (url.pathname === '/api/crypto/probe') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'crypto_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Network<->crypto correlation flow (取证闭环): GET /api/flow/watch?session=ID
  if (url.pathname === '/api/flow/watch') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'flow_watch', { className: url.searchParams.get('class') ?? SANDBOX.flow }, 25_000));
      const caps = (r.captures ?? []).map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      // correlate: pair each crypto capture with a network capture on the SAME thread
      // within a 200ms window (same tid, |Δts| <= 200ms).
      const WINDOW_NS = 200_000_000;
      const crypto = caps.filter((c: any) => c.func.startsWith('EVP_') || c.func === 'HMAC_Update');
      const net = caps.filter((c: any) => c.func.startsWith('SSL_'));
      const correlations = [];
      for (const cr of crypto) for (const nw of net) {
        if (cr.tid === nw.tid && Math.abs(cr.tsNs - nw.tsNs) <= WINDOW_NS) {
          correlations.push({ tid: cr.tid, deltaMs: Math.abs(cr.tsNs - nw.tsNs) / 1e6,
            plaintext: cr.ascii, cryptoFunc: cr.func, netFunc: nw.func, request: nw.ascii.slice(0, 120) });
        }
      }
      r.captures = caps;
      return send(r.ok ? 200 : 502, { ...r, correlations });
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Network TLS-plaintext capture test: GET /api/net/hook_test?session=ID
  if (url.pathname === '/api/net/hook_test') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'net_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.net }, 25_000));
      if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // File I/O hook recon: GET /api/file/probe?session=ID
  if (url.pathname === '/api/file/probe') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'file_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // File I/O plaintext-path capture test: GET /api/file/hook_test?session=ID&module=
  if (url.pathname === '/api/file/hook_test') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    const module = url.searchParams.get('module') ?? settings.capture.fileModule;
    try {
      const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'file_hook_test', { module, className: url.searchParams.get('class') ?? SANDBOX.file }, 25_000));
      if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Crypto plaintext-boundary hook test: GET /api/crypto/hook_test?session=ID
  if (url.pathname === '/api/crypto/hook_test') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'crypto_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.crypto }, 20_000));
      // decode captures to ascii preview for convenience
      if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // GOT hook engine self-test: GET /api/hook/selftest?session=ID
  if (url.pathname === '/api/hook/selftest') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'gothook_selftest'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // ART structural DexFile enumeration: GET /api/art/dexfiles?session=ID
  if (url.pathname === '/api/art/dexfiles') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Structural dex dump: POST /api/art/dump {session, begin, size} -> dump the exact DexFile
  if (url.pathname === '/api/art/dump' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, begin, size } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !begin || !size) return send(400, { error: 'need session, begin(hex), size' });
    try {
      const { meta, dedup } = await dumpRegion(sid, String(begin).replace(/^0x/, ''), Number(size), 'art_dexfile');
      return send(200, { ...meta, dedup });
    } catch (e) { return send(502, { error: (e as Error).message }); }
  }
  // JNI reflection probe (foundation for ART/Java work): GET /api/jni/probe?session=ID
  if (url.pathname === '/api/jni/probe') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'jni_probe'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Magic scan across process memory: GET /api/memory/scan_magic?session=ID
  if (url.pathname === '/api/memory/scan_magic') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'scan_magic', {}, 90_000);
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Memory read: POST /api/memory/read {session, addr, size}
  if (url.pathname === '/api/memory/read' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, addr, size } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
    try {
      const r = await sendCmd(sid, 'read', { addr: String(addr), size: Number(size) });
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Full unpack session (P3 capstone): POST /api/unpack/run {session, triggerClasses?[],
  // triggerMethod?, level?}. Orchestrates the whole pipeline:
  //   T0 snapshot(每个 DexFile) → coverage → active trigger → T1 snapshot → recover+rebuild
  // Returns a per-dex recovery report (before/after) + downloadable rebuilt dex. Ties P0-P2
  // together as one operation, matching the reviewed design's UnpackSession.
  if (url.pathname === '/api/unpack/run' && req.method === 'POST') {
    const body = JSON.parse((await readBody(req)) || '{}');
    const sid = pickSid(body.session);
    if (!sid) return send(400, { error: 'no session' });
    try { return send(200, await runUnpackSession(sid, body)); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Load an arbitrary .so into the target (frida-gadget / helper lib): POST /api/agent/load_so
  // {session, path, symbol?}. Gadget in script mode auto-runs its JS after this.
  if (url.pathname === '/api/agent/load_so' && req.method === 'POST') {
    const { session, path: soPath, symbol } = JSON.parse((await readBody(req)) || '{}');
    const sid = pickSid(session);
    if (!sid || !soPath) return send(400, { error: 'need session + path' });
    try { const r = await sendCmd(sid, 'load_so', { path: soPath, symbol: symbol ?? '' }, 30_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Active trigger (P2): GET /api/unpack/trigger?session=&class=&method=&level=
  // Level 1 loads the class; level 3 also invokes a SAFE static no-arg method. A trigger
  // source for the captor — pair with a dex re-snapshot + /api/dex/recover afterwards.
  if (url.pathname === '/api/unpack/trigger') {
    const sid = pickSid(url.searchParams.get('session'));
    const className = url.searchParams.get('class');
    const method = url.searchParams.get('method') ?? '';
    const level = Number(url.searchParams.get('level') ?? 1);
    if (!sid || !className) return send(400, { error: 'need session + class' });
    try {
      const r = await sendCmd(sid, 'trigger', { className, method, level }, 20_000);
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Memory search: POST /api/memory/search {session, hex?|text?, limit?}
  if (url.pathname === '/api/memory/search' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, hex, text, limit } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    const pat = hex ?? (text ? Buffer.from(String(text), 'utf8').toString('hex') : '');
    if (!sid || !pat) return send(400, { error: 'need session and hex|text' });
    try {
      const r = await sendCmd(sid, 'search', { pat, limit: Number(limit) || 256 }, 90_000);
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Region dump: POST /api/memory/dump {session, addr, size, tag?}
  if (url.pathname === '/api/memory/dump' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, addr, size, tag } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
    try {
      const { meta, dedup } = await dumpRegion(sid, String(addr).replace(/^0x/, ''), Number(size), String(tag ?? ''));
      return send(200, { ...meta, dedup });
    } catch (e) { return send(502, { error: (e as Error).message }); }
  }
  // Direct-syscall scan (E.9): POST /api/native/syscall_scan {b64|sha}
  if (url.pathname === '/api/native/syscall_scan' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    const r = svcScan(buf);
    return send(200, { execSegs: r.execSegs, scannedBytes: r.scanned, svcCount: r.hits.length, hits: r.hits.slice(0, 200) });
  }
  // Native crypto-constant scan (H.4): POST /api/native/crypto_const {b64|sha}
  if (url.pathname === '/api/native/crypto_const' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    const hits = cryptoConstScan(buf);
    const byName: Record<string, number> = {};
    for (const h of hits) byName[h.name] = (byName[h.name] ?? 0) + 1;
    return send(200, { size: buf.length, hits, byName, algorithms: Object.keys(byName) });
  }
  // Native binary analysis (Native Browser): POST /api/native/analyze {b64|sha, q?}
  if (url.pathname === '/api/native/analyze' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, q } = JSON.parse(body || '{}');
    let path: string, tmp: string | null;
    try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    try {
      const a = await analyzeSo(path);
      if (q) { const rx = new RegExp(String(q), 'i');
        a.exports = a.exports.filter((s: string) => rx.test(s)); a.imports = a.imports.filter((s: string) => rx.test(s));
        a.strings = a.strings.filter((s: string) => rx.test(s)); }
      // cap payload
      a.exports = a.exports.slice(0, 500); a.imports = a.imports.slice(0, 500); a.strings = a.strings.slice(0, 1000);
      return send(200, a);
    } catch (e) { return send(502, { error: (e as Error).message }); }
    finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
  }
  // Native disassembly (Native Browser): POST /api/native/disasm {b64|sha, symbol?|start?+stop?}
  if (url.pathname === '/api/native/disasm' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, symbol, start, stop } = JSON.parse(body || '{}');
    let path: string, tmp: string | null;
    try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    try {
      const insns = await disasmSo(path, { symbol, start, stop });
      return send(200, { symbol: symbol ?? null, count: insns.length, instructions: insns.slice(0, 2000) });
    } catch (e) { return send(502, { error: (e as Error).message, objdump: OBJDUMP }); }
    finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
  }
  // Module list (grouped from maps): GET /api/modules?session=ID
  if (url.pathname === '/api/modules') {
    const sid = pickSid(url.searchParams.get('session'));
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'maps');
      if (!r.ok) return send(502, r);
      return send(200, modulesFromMaps(r.regions ?? []));
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Reconstruct + dump a loaded .so from memory: POST /api/module/dump {session, name}
  if (url.pathname === '/api/module/dump' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, name } = JSON.parse(body || '{}');
    const sid = pickSid(session);
    if (!sid || !name) return send(400, { error: 'need session, name' });
    try {
      const maps = await sendCmd(sid, 'maps');
      const mod = modulesFromMaps(maps.regions ?? []).find(m => m.name === name || m.path.includes(name));
      if (!mod) return send(404, { error: `module not found: ${name}` });
      const buf = await reconstructSo(sid, mod.base);
      const sha = createHash('sha256').update(buf).digest('hex');
      const existing = dumps.get(sha);
      if (existing) return send(200, { ...existing, dedup: true, module: mod.name });
      const s = sessions.get(sid);
      const path = join(CAPTURES, `${sha.slice(0, 16)}.so`);
      if (!existsSync(path)) writeFileSync(path, buf);
      const meta: DumpMeta = { sha256: sha, size: buf.length, source: 'so-reassembly', addr: mod.base, tag: mod.name, sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind: 'so' };
      dumps.set(sha, meta);
      broadcast('dump.new', meta);
      return send(200, { ...meta, dedup: false, module: mod.name, segments: mod.segs });
    } catch (e) { return send(502, { error: (e as Error).message }); }
  }
  // Dex parse: POST /api/dex/parse {b64|sha} -> structure summary (+ optional full arrays)
  // Method body recovery (L.7): POST /api/dex/method_code {b64|sha, class, method?}
  if (url.pathname === '/api/dex/method_code' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, class: cls, method } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    if (!cls) return send(400, { error: 'need class' });
    let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    const codes = extractMethodCode(buf, parsed, String(cls), method ? String(method) : undefined);
    const recovered = codes.filter(c => c.insnsSize > 0).length;
    return send(200, { class: cls, method: method ?? null, count: codes.length, recovered, empty: codes.length - recovered, methods: codes.slice(0, 200) });
  }
  // Dex invoke-xref: POST /api/dex/xref {b64|sha, method} -> callers of matching methods
  if (url.pathname === '/api/dex/xref' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, method } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    if (!method) return send(400, { error: 'need method (substring of callee cls->name)' });
    let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    const { xref, methodsWithCode, skipped } = invokeXref(buf, parsed);
    const q = String(method).toLowerCase();
    const results: Record<string, string[]> = {};
    for (const [callee, callers] of xref) if (callee.toLowerCase().includes(q)) results[callee] = callers.slice(0, 200);
    return send(200, { method, methodsWithCode, skipped, matches: Object.keys(results).length, callers: results });
  }
  // Method-gap / recovery-rate report over a dumped dex: POST /api/dex/coverage {b64|sha}
  if (url.pathname === '/api/dex/coverage' && req.method === 'POST') {
    const { b64, sha, limitMissing } = JSON.parse((await readBody(req)) || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    const cov = analyzeCoverage(buf, parsed);
    const lm = Number(limitMissing ?? 100);
    return send(200, { magic: parsed.magic, counts: parsed.counts, ...cov,
      recoveryPct: +(cov.recoveryRate * 100).toFixed(2), missing: cov.missing.slice(0, lm), missingTotal: cov.missing.length });
  }
  // Passive gen-2 recovery: POST /api/dex/recover {baseB64|baseSha, restoredB64|restoredSha}
  // Lifts CodeItems for the base's extracted (empty) methods out of a RESTORED snapshot,
  // rebuilds a standard dex, and stores it. Returns recovery counts + rebuilt sha.
  if (url.pathname === '/api/dex/recover' && req.method === 'POST') {
    const body = JSON.parse((await readBody(req)) || '{}');
    // no input -> null (=> 400 below); registered-but-file-gone -> dumpBuf throws 404 (fail-loud,
    // not the old silent null that mislabeled a disk failure as "missing input")
    const load = (b64?: string, sha?: string) => (b64 || (sha && dumps.get(sha))) ? dumpBuf({ b64, sha }) : Promise.resolve(null);
    let base: Buffer | null, restored: Buffer | null;
    try { base = await load(body.baseB64, body.baseSha); restored = await load(body.restoredB64, body.restoredSha); }
    catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
    if (!base || !restored) return send(400, { error: 'need base + restored (b64 or known sha)' });
    let parsed; try { parsed = parseDex(base); } catch (e) { return send(422, { error: (e as Error).message }); }
    const { captures, report } = recoverFromSnapshots(base, restored, parsed);
    const rb = rebuildStandardDex(base, captures);
    let parseOk = true; try { parseDex(rb.dex); } catch { parseOk = false; }
    const outSha = createHash('sha256').update(rb.dex).digest('hex');
    const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
    if (!existsSync(path)) writeFileSync(path, rb.dex);
    const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
    dumps.set(outSha, meta); broadcast('dump.new', meta);
    return send(200, { ok: true, ...report, injected: rb.injected, classesRewritten: rb.classesRewritten, parseOk, sha256: outSha, size: rb.dex.length });
  }
  // Test util — simulate extraction: POST /api/dex/strip {b64|sha, midx} -> dex with that
  // method's code_off zeroed (same-length redundant uleb). Returns b64 + its original code.
  if (url.pathname === '/api/dex/strip' && req.method === 'POST') {
    const { b64, sha, midx } = JSON.parse((await readBody(req)) || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    const stripped = stripMethodCode(buf, Number(midx));
    return send(200, { ok: true, midx: Number(midx), b64: stripped.toString('base64') });
  }
  // Structural rebuild: POST /api/dex/rebuild {b64|sha, captures:[{midx,codeItemHex}]} ->
  // merge captured CodeItems into the base dex, store as a downloadable dump.
  if (url.pathname === '/api/dex/rebuild' && req.method === 'POST') {
    const { b64, sha, captures } = JSON.parse((await readBody(req)) || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    if (!Array.isArray(captures)) return send(400, { error: 'need captures[]' });
    let res; try { res = rebuildStandardDex(buf, captures); } catch (e) { return send(422, { error: (e as Error).message }); }
    let parseOk = true, methods = 0;
    try { const pd = parseDex(res.dex); methods = pd.counts.methods; } catch { parseOk = false; }
    const outSha = createHash('sha256').update(res.dex).digest('hex');
    const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
    if (!existsSync(path)) writeFileSync(path, res.dex);
    const meta: DumpMeta = { sha256: outSha, size: res.dex.length, source: 'dex-rebuild', addr: '0', tag: 'rebuilt', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
    dumps.set(outSha, meta); broadcast('dump.new', meta);
    return send(200, { ok: true, injected: res.injected, classesRewritten: res.classesRewritten, parseOk, methods, sha256: outSha, size: res.dex.length });
  }
  if ((url.pathname === '/api/dex/parse' || url.pathname === '/api/dex/crypto_scan' || url.pathname === '/api/dex/search') && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, full } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    let parsed;
    try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    if (url.pathname === '/api/dex/crypto_scan') {
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...cryptoScan(parsed) });
    }
    if (url.pathname === '/api/dex/search') {
      const { query, kinds } = JSON.parse(body || '{}');
      if (!query) return send(400, { error: 'need query' });
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...searchDex(parsed, String(query), kinds) });
    }
    // parse: counts + samples (or full arrays when full=true)
    const cap = full ? Infinity : 200;
    return send(200, {
      magic: parsed.magic, counts: parsed.counts,
      classes: parsed.classes.slice(0, cap).map(c => c.name),
      methods: parsed.methods.slice(0, cap),
      strings: parsed.strings.slice(0, cap),
    });
  }
  // Dex header repair: POST /api/dex/repair {b64} | {sha}
  if (url.pathname === '/api/dex/repair' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    const info = repairDexHeader(buf);
    return send(200, { ...info, size: buf.length, repairedB64: buf.toString('base64') });
  }
  // Dumps registry
  if (url.pathname === '/api/dumps') return send(200, [...dumps.values()]);
  if (url.pathname === '/api/dumps/download') {
    const sha = url.searchParams.get('sha') ?? '';
    const m = dumps.get(sha);
    if (!m) return send(404, { error: 'no such dump' });
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': `attachment; filename="${sha.slice(0, 16)}.${m.kind}.bin"` });
    return createReadStream(m.path).pipe(res);
  }
  if (url.pathname === '/' || url.pathname === '/index.html') {
    try {
      const html = await readFile(join(__dirname, '..', 'public', 'index.html'), 'utf8');
      return send(200, html, 'text/html; charset=utf-8');
    } catch { return send(500, { error: 'dashboard missing' }); }
  }
  send(404, { error: 'not found' });
}
// Top-level error net: no request may crash the daemon. An uncaught JSON.parse throws SyntaxError
// -> 400; typed errors carry their own status (e.g. dumpBuf 404/400); anything else -> 500.
const httpServer = http.createServer((req, res) => {
  handleHttp(req, res).catch((e: any) => {
    if (res.writableEnded) return;
    const status = e?.status ?? (e instanceof SyntaxError ? 400 : 500);
    try { res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }); res.end(JSON.stringify({ error: e?.message ?? 'internal error' })); } catch {}
  });
});

httpServer.on('upgrade', (req, socket, head) => {
  const { pathname } = new URL(req.url ?? '/', 'http://localhost');
  if (pathname === '/ws') {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(JSON.stringify({ event: 'snapshot', data: [...sessions.values()], ts: Date.now() }));
    });
  } else socket.destroy();
});

// ---- boot -----------------------------------------------------------------

agentServer.listen(AGENT_PORT, '0.0.0.0', () => log(`agent TCP listening on :${AGENT_PORT}`));
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  const w = webUrls();
  log(`HTTP + WS listening on 0.0.0.0:${HTTP_PORT}`);
  log('┌─ ADH web console ───────────────────────────────────────────');
  log(`│  local : ${w.local}   (this PC's browser)`);
  if (w.lan.length) {
    for (const u of w.lan) log(`│  LAN   : ${u}   (phone / any device on the same network)`);
  } else {
    // fail-loud, like the iOS ref: don't pretend LAN access works when it can't
    log('│  LAN   : (no LAN IPv4 found — console reachable locally only;');
    log('│          the phone can still open it via `adb reverse tcp:8760`)');
  }
  log(`│  phone : also run 'adb reverse tcp:${AGENT_PORT} tcp:${AGENT_PORT}' + 'adb reverse tcp:${HTTP_PORT} tcp:${HTTP_PORT}'`);
  log('└─────────────────────────────────────────────────────────────');
});

process.on('SIGINT', () => { log('shutting down'); process.exit(0); });

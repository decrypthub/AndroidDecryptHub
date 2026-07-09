// idhd — IDH daemon (v0.1)
// Three surfaces:
//   - Agent TCP server (NDJSON)         : device agents connect here (via `adb reverse`)
//   - HTTP server (REST + static)       : /health, /api/agents, dashboard
//   - WebSocket                         : pushes live agent/registry events to the browser
// v0.1 keeps all state in memory. Persistence (SQLite) arrives in v0.2.

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { mkdirSync, writeFileSync, existsSync, createReadStream, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { homedir, tmpdir } from 'node:os';
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
  } catch { /* readelf missing */ }
  const needed: string[] = [];
  try {
    const { stdout } = await execFileP(READELF, ['-d', path], { maxBuffer: 8 * 1024 * 1024 });
    for (const line of stdout.split('\n')) { const m = line.match(/\(NEEDED\).*\[(.+?)\]/); if (m) needed.push(m[1]); }
  } catch { /* */ }
  // printable string runs (>=4)
  const buf = await readFile(path);
  const strings: string[] = []; let cur = '';
  for (let i = 0; i < buf.length && strings.length < 5000; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
    else { if (cur.length >= 4) strings.push(cur); cur = ''; }
  }
  return { exports: [...new Set(exports)], imports: [...new Set(imports)], needed, strings: [...new Set(strings)],
    counts: { exports: exports.length, imports: imports.length, needed: needed.length, strings: strings.length } };
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
import { parseDex, cryptoScan, searchDex } from './dex.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CAPTURES = join(__dirname, '..', '..', 'captures');
mkdirSync(CAPTURES, { recursive: true });

const HTTP_PORT = Number(process.env.IDH_HTTP_PORT ?? 8760);
const AGENT_PORT = Number(process.env.IDH_AGENT_PORT ?? 8761);

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
function sendCmd(sessionId: string, op: string, args: Record<string, unknown> = {}, timeoutMs = 10_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = agentSockets.get(sessionId);
    if (!sock || sock.destroyed) return reject(new Error('agent not connected'));
    const id = nextCmdId();
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('command timeout')); }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    sock.write(JSON.stringify({ t: 'cmd', id, op, ...args }) + '\n');
  });
}

const wss = new WebSocketServer({ noServer: true });
function broadcast(event: string, data: unknown) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  for (const c of wss.clients) if (c.readyState === WebSocket.OPEN) c.send(msg);
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
  let buf = '';
  sock.setNoDelay(true);

  sock.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg: AgentMsg;
      try { msg = JSON.parse(line); } catch { log('bad json from agent:', line.slice(0, 120)); continue; }
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
      sock.write(JSON.stringify({ t: 'ack', sessionId: id }) + '\n');
      broadcast('agent.hello', session);
    } else if (msg.t === 'maps' && session) {
      session.mapsCount = msg.count;
      session.regionsSample = (msg.regions ?? []).slice(0, 50);
      session.lastSeen = Date.now();
      log(`agent MAPS ${session.package} count=${msg.count}`);
      broadcast('agent.maps', { sessionId: session.sessionId, count: msg.count });
    } else if (msg.t === 'ping' && session) {
      session.lastSeen = Date.now();
      sock.write(JSON.stringify({ t: 'pong' }) + '\n');
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

// ---- HTTP + WebSocket -----------------------------------------------------

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost`);
  const send = (code: number, body: unknown, type = 'application/json') => {
    const s = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': type, 'access-control-allow-origin': '*' });
    res.end(s);
  };

  if (url.pathname === '/health') {
    return send(200, { ok: true, service: 'idhd', version: '0.1.0', agents: sessions.size, uptime: process.uptime() });
  }
  if (url.pathname === '/api/agents') {
    return send(200, [...sessions.values()]);
  }
  if (url.pathname.startsWith('/api/agents/')) {
    const s = sessions.get(url.pathname.split('/')[3]);
    return s ? send(200, s) : send(404, { error: 'no such session' });
  }
  // On-demand full maps from the agent: GET /api/process/maps?session=ID
  if (url.pathname === '/api/process/maps') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
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
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid || !className || !field) return send(400, { error: 'need session, className, field' });
    try { const r = await sendCmd(sid, 'object_inspect', { className, field }); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Object method invocation (module T, low-risk): POST /api/object/invoke {session, className, field, method}
  if (url.pathname === '/api/object/invoke' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, className, field, method } = JSON.parse(body || '{}');
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid || !className || !field || !method) return send(400, { error: 'need session, className, field, method' });
    try { const r = await sendCmd(sid, 'object_invoke', { className, field, method }); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Compatibility / anti-interference diagnostic (module S): GET /api/compat/probe?session=ID
  if (url.pathname === '/api/compat/probe') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'compat_probe'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Anti-analysis behavior observation (module V): GET /api/detect/watch?session=ID
  if (url.pathname === '/api/detect/watch') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'detect_watch', {}, 20_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Crypto hook recon: GET /api/crypto/probe?session=ID
  if (url.pathname === '/api/crypto/probe') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'crypto_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Network<->crypto correlation flow (取证闭环): GET /api/flow/watch?session=ID
  if (url.pathname === '/api/flow/watch') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'flow_watch', {}, 25_000);
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
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'net_hook_test', {}, 25_000);
      if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Crypto plaintext-boundary hook test: GET /api/crypto/hook_test?session=ID
  if (url.pathname === '/api/crypto/hook_test') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try {
      const r = await sendCmd(sid, 'crypto_hook_test', {}, 20_000);
      // decode captures to ascii preview for convenience
      if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // GOT hook engine self-test: GET /api/hook/selftest?session=ID
  if (url.pathname === '/api/hook/selftest') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'gothook_selftest'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // ART structural DexFile enumeration: GET /api/art/dexfiles?session=ID
  if (url.pathname === '/api/art/dexfiles') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Structural dex dump: POST /api/art/dump {session, begin, size} -> dump the exact DexFile
  if (url.pathname === '/api/art/dump' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, begin, size } = JSON.parse(body || '{}');
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid || !begin || !size) return send(400, { error: 'need session, begin(hex), size' });
    try {
      const { meta, dedup } = await dumpRegion(sid, String(begin).replace(/^0x/, ''), Number(size), 'art_dexfile');
      return send(200, { ...meta, dedup });
    } catch (e) { return send(502, { error: (e as Error).message }); }
  }
  // JNI reflection probe (foundation for ART/Java work): GET /api/jni/probe?session=ID
  if (url.pathname === '/api/jni/probe') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid) return send(400, { error: 'no session' });
    try { const r = await sendCmd(sid, 'jni_probe'); return send(r.ok ? 200 : 502, r); }
    catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Magic scan across process memory: GET /api/memory/scan_magic?session=ID
  if (url.pathname === '/api/memory/scan_magic') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
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
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
    try {
      const r = await sendCmd(sid, 'read', { addr: String(addr), size: Number(size) });
      return send(r.ok ? 200 : 502, r);
    } catch (e) { return send(504, { error: (e as Error).message }); }
  }
  // Memory search: POST /api/memory/search {session, hex?|text?, limit?}
  if (url.pathname === '/api/memory/search' && req.method === 'POST') {
    const body = await readBody(req);
    const { session, hex, text, limit } = JSON.parse(body || '{}');
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
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
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
    if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
    try {
      const { meta, dedup } = await dumpRegion(sid, String(addr).replace(/^0x/, ''), Number(size), String(tag ?? ''));
      return send(200, { ...meta, dedup });
    } catch (e) { return send(502, { error: (e as Error).message }); }
  }
  // Native binary analysis (Native Browser): POST /api/native/analyze {b64|sha, q?}
  if (url.pathname === '/api/native/analyze' && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, q } = JSON.parse(body || '{}');
    let path: string | null = null, tmp: string | null = null;
    if (sha && dumps.get(sha)) path = dumps.get(sha)!.path;
    else if (b64) { tmp = join(tmpdir(), `idh_an_${Date.now()}.so`); writeFileSync(tmp, Buffer.from(b64, 'base64')); path = tmp; }
    else return send(400, { error: 'need b64 or known sha' });
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
    let path: string | null = null, tmp: string | null = null;
    if (sha && dumps.get(sha)) path = dumps.get(sha)!.path;
    else if (b64) { tmp = join(tmpdir(), `idh_disasm_${Date.now()}.so`); writeFileSync(tmp, Buffer.from(b64, 'base64')); path = tmp; }
    else return send(400, { error: 'need b64 or known sha' });
    try {
      const insns = await disasmSo(path, { symbol, start, stop });
      return send(200, { symbol: symbol ?? null, count: insns.length, instructions: insns.slice(0, 2000) });
    } catch (e) { return send(502, { error: (e as Error).message, objdump: OBJDUMP }); }
    finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
  }
  // Module list (grouped from maps): GET /api/modules?session=ID
  if (url.pathname === '/api/modules') {
    const sid = url.searchParams.get('session') ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
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
    const sid = session ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
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
  if ((url.pathname === '/api/dex/parse' || url.pathname === '/api/dex/crypto_scan' || url.pathname === '/api/dex/search') && req.method === 'POST') {
    const body = await readBody(req);
    const { b64, sha, full } = JSON.parse(body || '{}');
    let buf: Buffer;
    if (b64) buf = Buffer.from(b64, 'base64');
    else if (sha && dumps.get(sha)) { try { buf = await readFile(dumps.get(sha)!.path); } catch { return send(404, { error: 'dump file missing' }); } }
    else return send(400, { error: 'need b64 or known sha' });
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
    if (b64) buf = Buffer.from(b64, 'base64');
    else if (sha && dumps.get(sha)) { try { buf = await readFile(dumps.get(sha)!.path); } catch { return send(404, { error: 'dump file missing' }); } }
    else return send(400, { error: 'need b64 or known sha' });
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
  log(`HTTP + WS listening on http://127.0.0.1:${HTTP_PORT}`);
  log(`dashboard: http://127.0.0.1:${HTTP_PORT}/  | run 'adb reverse tcp:${AGENT_PORT} tcp:${AGENT_PORT}' before launching the target`);
});

process.on('SIGINT', () => { log('shutting down'); process.exit(0); });

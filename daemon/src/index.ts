// idhd — IDH daemon (v0.1)
// Three surfaces:
//   - Agent TCP server (NDJSON)         : device agents connect here (via `adb reverse`)
//   - HTTP server (REST + static)       : /health, /api/agents, dashboard
//   - WebSocket                         : pushes live agent/registry events to the browser
// v0.1 keeps all state in memory. Persistence (SQLite) arrives in v0.2.

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { mkdirSync, writeFileSync, existsSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';

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

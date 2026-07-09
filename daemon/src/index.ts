// idhd — IDH daemon (v0.1)
// Three surfaces:
//   - Agent TCP server (NDJSON)         : device agents connect here (via `adb reverse`)
//   - HTTP server (REST + static)       : /health, /api/agents, dashboard
//   - WebSocket                         : pushes live agent/registry events to the browser
// v0.1 keeps all state in memory. Persistence (SQLite) arrives in v0.2.

import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';

const __dirname = dirname(fileURLToPath(import.meta.url));

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
  | { t: 'ping'; ts?: number };

// ---- registry -------------------------------------------------------------

const sessions = new Map<string, AgentSession>();
let seq = 0;
const nextId = () => `s_${(++seq).toString(36)}${Date.now().toString(36).slice(-3)}`;

const wss = new WebSocketServer({ noServer: true });
function broadcast(event: string, data: unknown) {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  for (const c of wss.clients) if (c.readyState === WebSocket.OPEN) c.send(msg);
}
function log(...a: unknown[]) {
  console.log(`[idhd ${new Date().toISOString()}]`, ...a);
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
    }
  }

  sock.on('close', () => {
    if (session) {
      session.online = false;
      session.lastSeen = Date.now();
      log(`agent CLOSE ${session.package} ${session.sessionId}`);
      broadcast('agent.close', { sessionId: session.sessionId });
    }
  });
  sock.on('error', (e) => log('agent sock error:', (e as Error).message));
});

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

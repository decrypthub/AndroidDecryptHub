// ADH Daemon — Android DecryptHub host daemon.
// Boot + agent-TCP frame decode live here. REST route domains live under src/http/.
import http from 'node:http';
import net from 'node:net';
import { AGENT_PORT, HTTP_PORT, webUrls } from './config.ts';
import { handleHttp } from './http/router.ts';
import { startCaptureLoop, forgetCaptureSession, pruneArtifactsAndIndex } from './service.ts';
import {
  agentSockets, broadcast, captureTimers, frameJson, FRAME_JSON, FRAME_MAX,
  log, nextId, pending, pruneSessions, sessions, wss,
}
from './state.ts';
import type { AgentMsg, AgentSession } from './state.ts';

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
        selfModule: msg.selfModule ?? '',
        selfBase: msg.selfBase ?? '',
        connectedAt: Date.now(),
        lastSeen: Date.now(),
        online: true,
        mapsCount: 0,
        regionsSample: [],
      };
      sessions.set(id, session);
      pruneSessions();   // a new dial-in is the natural moment to drop stale dead sessions
      agentSockets.set(id, sock);
      log(`agent HELLO ${session.package} pid=${session.pid} abi=${session.abi} entry=${session.entry} self=${session.selfModule || '?'} -> ${id}`);
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
      if (t) { clearInterval(t); captureTimers.delete(session.sessionId); forgetCaptureSession(session.sessionId); }
      log(`agent CLOSE ${session.package} ${session.sessionId}`);
      broadcast('agent.close', { sessionId: session.sessionId });
      pruneSessions();
    }
  });
  sock.on('error', (e) => log('agent sock error:', (e as Error).message));
});
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

agentServer.listen(AGENT_PORT, '0.0.0.0', () => log(`ADH Daemon agent TCP listening on :${AGENT_PORT}`));
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  const w = webUrls();
  log(`ADH Daemon HTTP + WS listening on 0.0.0.0:${HTTP_PORT}`);
  log('┌─ ADH Daemon web console ────────────────────────────────────');
  log(`│  local : ${w.local}   (this PC's browser)`);
  if (w.lan.length) {
    for (const u of w.lan) log(`│  LAN   : ${u}   (phone / any device on the same network)`);
  } else {
    // fail-loud, like the iOS ref: don't pretend LAN access works when it can't
    log('│  LAN   : (no LAN IPv4 found — console reachable locally only;');
    log(`│          the phone can still open it via \`adb reverse tcp:${HTTP_PORT}\`)`);
  }
  log(`│  phone : also run 'adb reverse tcp:${AGENT_PORT} tcp:${AGENT_PORT}' + 'adb reverse tcp:${HTTP_PORT} tcp:${HTTP_PORT}'`);
  log('└─────────────────────────────────────────────────────────────');
});

process.on('SIGINT', () => { log('shutting down'); process.exit(0); });

// Periodic session sweep: closes can be missed (kill -9, lost sockets), so bound the map anyway.
// The same tick enforces artifact retention: the dump helpers prune right after they write, but a
// few routes write artifacts directly, so a periodic sweep is what keeps captures/ bounded no
// matter which path produced the file.
setInterval(() => {
  const dropped = pruneSessions();
  if (dropped.length) log(`session prune: dropped ${dropped.length} stale offline session(s)`);
  pruneArtifactsAndIndex();
}, 60_000).unref();

// Boot-time reconciliation: adopt what is already on disk (the module body of state.ts does the
// load) and apply retention once, so a daemon that was down while files piled up starts bounded.
pruneArtifactsAndIndex();

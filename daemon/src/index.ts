// ADH Daemon — Android DecryptHub host daemon.
// Boot + agent-TCP frame decode live here. REST route domains live under src/http/.
import http from 'node:http';
import net from 'node:net';
import { AGENT_PORT, HTTP_PORT, webUrls } from './config.ts';
import { handleHttp } from './http/router.ts';
import { sendHttpError } from './http/response_error.ts';
import { ensureAdbReverse } from './scope_list.ts';
import { startCaptureLoop, forgetCaptureSession, clearCaptureArmProtect } from './service.ts';
import { applyCaptureSettingsOnConnect } from './settings_service.ts';
import { initializeHost } from './host_lifecycle.ts';
import { initializeOperations } from './operation_host.ts';
import {
  agentSockets, broadcast, captureTimers, failPendingFor, frameJson, FRAME_JSON, FRAME_MAX,
  log, nextId, pending, pruneSessions, sessions, wss,
}
from './state.ts';
import type { AgentMsg, AgentSession } from './state.ts';
import { normalizeStarttimeTicks } from './proc_identity.ts';

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
        starttimeTicks: normalizeStarttimeTicks(msg.starttimeTicks),
        package: msg.package ?? '?',
        process: msg.process ?? msg.package ?? '?',
        abi: msg.abi ?? '?',
        android: msg.android ?? '?',
        sdk: msg.sdk ?? 0,
        entry: msg.entry ?? '?',
        agentVer: msg.agentVer ?? '?',
        selfModule: msg.selfModule ?? '',
        selfBase: msg.selfBase ?? '',
        policy: msg.policy ?? '',
        earlyPlan: msg.earlyPlan ?? null,
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
      // Fresh process after unpack: allow auto-arm again (protect only blocks the live post-unpack session).
      clearCaptureArmProtect(session.package);
      broadcast('agent.hello', session);
      // Draining starts immediately. The algorithms checked in the panel are installed here,
      // on this process, so a restarted app keeps the same hooks.
      startCaptureLoop(id,{skipArm:true});
      void applyCaptureSettingsOnConnect(id).then(result => {
        if (result?.ok === false) log(`[capture] family arm ${id}:`, result.error || 'capture settings not applied');
      }).catch(error => log(`[capture] family arm ${id}:`, (error as Error).message));
    } else if (msg.t === 'caps' && session) {
      // Arrives right after the hello (before the maps sample). Stored on the session, never
      // merged from another session: two processes of the same app can run different builds.
      session.caps = {
        ops: Array.isArray(msg.ops) ? msg.ops : [],
        limits: (msg.limits && typeof msg.limits === 'object') ? msg.limits : {},
        ...(msg.error ? { error: msg.error } : {}),
      };
      session.lastSeen = Date.now();
      log(`agent CAPS ${session.package} ops=${session.caps.ops?.length ?? 0}${msg.error ? ` error=${msg.error}` : ''}`);
      broadcast('agent.caps', { sessionId: session.sessionId, caps: session.caps });
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
      // Commands still waiting on this session can never be answered: fail them NOW with a reason, so a
      // caller sees "the target disconnected while this command was running" instead of a timeout that
      // looks like a slow target.
      const failed = failPendingFor(session.sessionId, 'the target disconnected while this command was running (it may have crashed)');
      if (failed) log(`agent CLOSE ${session.package} ${session.sessionId}: failed ${failed} pending command(s)`);
      const t = captureTimers.get(session.sessionId);
      if (t) { clearInterval(t); captureTimers.delete(session.sessionId); forgetCaptureSession(session.sessionId); }
      log(`agent CLOSE ${session.package} ${session.sessionId}`);
      broadcast('agent.close', { sessionId: session.sessionId, package: session.package, pid: session.pid });
      pruneSessions();
    }
  });
  sock.on('error', (e) => log('agent sock error:', (e as Error).message));
});
// Top-level error net: no request may crash the daemon. An uncaught JSON.parse throws SyntaxError
// -> 400; typed errors carry their own status (e.g. readBody's 413, dumpBuf's 404/400); anything
// else -> 500.
const httpServer = http.createServer((req, res) => {
  handleHttp(req, res).catch(error=>sendHttpError(req,res,error));
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

initializeHost();
initializeOperations();
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
  log(`│  phone : adb reverse tcp:${AGENT_PORT} and tcp:${HTTP_PORT}, or the LAN address the Manager remembers for tcp:${AGENT_PORT}`);
  log('└─────────────────────────────────────────────────────────────');
});

process.on('SIGINT', () => { log('shutting down'); process.exit(0); });

// Periodic session sweep: closes can be missed (kill -9, lost sockets), so bound the map anyway.
// Data retention is an explicit maintenance operation, never part of startup/session sweeps.
setInterval(() => {
  const dropped = pruneSessions();
  if (dropped.length) log(`session prune: dropped ${dropped.length} stale offline session(s)`);
}, 60_000).unref();

// The injected agent only reaches this process through adb reverse. Re-apply it on a
// short interval so a USB reconnect does not leave the panel looking at a dead target.
const keepReverse = () => ensureAdbReverse([AGENT_PORT, HTTP_PORT], (line) => log(line));
keepReverse();
setInterval(keepReverse, 15_000).unref();

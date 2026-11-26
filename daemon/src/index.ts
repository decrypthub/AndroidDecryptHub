// ADH Daemon — Android DecryptHub host daemon.
// Boot + agent-TCP frame decode live here. REST route domains live under src/http/.
import http from 'node:http';
import net from 'node:net';
import {acceptAgentSocket} from './agent_transport.ts';
import {UsbAgentRoutes,setUsbAgentRoutes} from './usb_agent_routes.ts';
import {withDeviceScope,httpDeviceScope} from './agent_scope.ts';
import {DEVICE_AGENT_PORT} from './config.ts';
import {parseAdbDevices,realAdbRunner} from './transport/adb_device.ts';
import { AGENT_PORT, HTTP_PORT, webUrls } from './config.ts';
import { acceptsLocalHello, initLocalObserver, isOwnDemoPackage, localObserver, localObserverHost, observerHost, noteObservedPid } from './local_observer.ts';
import { handleHttp } from './http/router.ts';
import { sendHttpError } from './http/response_error.ts';
import { ensureAdbReverse } from './scope_list.ts';
import { adbTrackDevices } from './adb_wire.ts';
import { armSandboxCapture, setCapture, startCaptureLoop, forgetCaptureSession, clearCaptureArmProtect, ingestAgentCaptureFrame } from './service.ts';
import { applyCaptureSettingsOnConnect } from './settings_service.ts';
import { initializeHost } from './host_lifecycle.ts';
import { initializeOperations } from './operation_host.ts';
import {
  agentSockets, broadcast, broadcastLive, captureTimers, failPendingFor, frameJson, FRAME_JSON, FRAME_MAX,
  log, nextId, pending, pruneSessions, sessions, wss,
}
from './state.ts';
import type { AgentMsg, AgentSession } from './state.ts';
import { normalizeStarttimeTicks } from './proc_identity.ts';

// ---- Agent TCP server (NDJSON) -------------------------------------------

let routesReady=false;
const startupSockets=new Set<net.Socket>();
const agentServer=net.createServer(sock=>{
  if(!routesReady){if(startupSockets.size>=32){sock.destroy();return;}startupSockets.add(sock);sock.once('close',()=>startupSockets.delete(sock));return;}
  acceptAgentSocket(sock);
});
// Top-level error net: no request may crash the daemon. An uncaught JSON.parse throws SyntaxError
// -> 400; typed errors carry their own status (e.g. readBody's 413, dumpBuf's 404/400); anything
// else -> 500.
const httpServer = http.createServer((req, res) => {
  const requestTarget = req.url ?? '/';
  const originPath = requestTarget.startsWith('/') && !requestTarget.startsWith('//') && !requestTarget.includes('\\');
  const foreignBrowser=(localObserver?.fileBrowserOnly || localObserver?.demoApiSerial) && (
    (req.headers.origin && req.headers.origin!=='http://'+localObserverHost) || req.headers['sec-fetch-site']==='cross-site');
  if (localObserver && (!observerHost(req.headers.host) || !originPath || foreignBrowser)) {
    res.writeHead(403, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ ok: false, error: '当前本机入口未授权此操作。' }));
    return;
  }
  try { withDeviceScope(httpDeviceScope(req.headers),()=>handleHttp(req,res)).catch(error=>sendHttpError(req,res,error)); }
  catch(error){void sendHttpError(req,res,error); }
});

httpServer.on('upgrade', (req, socket, head) => {
  const { pathname } = new URL(req.url ?? '/', 'http://localhost');
  if (pathname === '/ws' && (!localObserver ||
    (observerHost(req.headers.host) && (!req.headers.origin || req.headers.origin === 'http://' + req.headers.host)))) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(JSON.stringify({ event: 'snapshot', data: [...sessions.values()], ts: Date.now() }));
    });
  } else socket.destroy();
});

// ---- boot -----------------------------------------------------------------

await initLocalObserver();
initializeHost();
initializeOperations();
const bindAddress = localObserver ? '127.0.0.1' : '0.0.0.0';
const usbRoutes=new UsbAgentRoutes({deviceAgentPort:DEVICE_AGENT_PORT,legacyHostPort:AGENT_PORT,
  ownsLegacyListener:()=>agentServer.listening,onConnection:(sock,lease)=>acceptAgentSocket(sock,lease)});
setUsbAgentRoutes(usbRoutes);
if(!localObserver?.fileBrowserOnly&&!localObserver?.demoApiSerial){
  await new Promise<void>((resolve,reject)=>{agentServer.once('error',reject);agentServer.listen(AGENT_PORT,bindAddress,()=>{agentServer.off('error',reject);resolve();});});
  if(process.env.ADH_SKIP_ARTIFACT_LOAD!=='1'){
    try{
      const rows=parseAdbDevices(await realAdbRunner(['devices','-l']));
      const selected=localObserver?.usbSerial||process.env.ANDROID_SERIAL||process.env.ADH_SERIAL;
      for(const row of rows.filter(r=>r.state==='device'&&(!selected||r.serial===selected))){
        try{await usbRoutes.ensure(row.serial);}catch(e){log('[agent-route]',row.serial,(e as Error).message);}
      }
    }catch(e){log('[agent-route]',(e as Error).message);}
  }
}
routesReady=true;
// These connections arrived during route publication and have no immutable provenance.
// Redial into the new listener; never relabel an existing unverified connection.
for(const sock of startupSockets)sock.destroy();startupSockets.clear();
httpServer.listen(HTTP_PORT, bindAddress, () => {
  if (localObserver) {
    log(localObserver.fileBrowserOnly ? `Owned USB file browser: ${localObserver.model} · ${localObserver.package} (no Agent listener)`
      : localObserver.demoApiSerial ? `Owned USB Demo API observation: ${localObserver.model} · ${localObserver.package}`
      : `Local observation: ${localObserver.model} · ${localObserver.package} PID ${localObserver.pid}`);
    log(`ADH web viewer http://${localObserverHost}/${localObserver.package}`);
    return;
  }
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

let shuttingDown=false;
async function shutdown(){if(shuttingDown)return;shuttingDown=true;log('shutting down');
  const timer=setTimeout(()=>process.exit(1),10000);timer.unref();
  await usbRoutes.closeAll();clearTimeout(timer);process.exit(0);
}
process.on('SIGINT',()=>void shutdown());process.on('SIGTERM',()=>void shutdown());

// Periodic session sweep: closes can be missed (kill -9, lost sockets), so bound the map anyway.
// Data retention is an explicit maintenance operation, never part of startup/session sweeps.
setInterval(() => {
  const dropped = pruneSessions();
  if (dropped.length) log(`session prune: dropped ${dropped.length} stale offline session(s)`);
}, 60_000).unref();

// The injected agent only reaches this process through adb reverse. Re-apply it on a
// short interval so a USB reconnect does not leave the panel looking at a dead target.
const keepReverse = () => ensureAdbReverse([HTTP_PORT], (line) => log(line));
if (!localObserver) {
  keepReverse();
  setInterval(keepReverse, 15_000).unref();
}

// host:track-devices 常驻推送：设备插拔即时广播给面板，不必等 4s 轮询。
{
  let devTimer: ReturnType<typeof setTimeout> | undefined;
  adbTrackDevices(() => {
    clearTimeout(devTimer);
    devTimer = setTimeout(() => broadcastLive('devices.changed', {}), 300);
  });
}

import {getCaptureControls} from './capture_controls.ts';
import {independentDeviceScope} from './agent_scope.ts';
import net from 'node:net';
import {acceptsLocalHello,isOwnDemoPackage,localObserver,noteObservedPid} from './local_observer.ts';
import {armSandboxCapture,setCapture,startCaptureLoop,forgetCaptureSession,clearCaptureArmProtect,ingestAgentCaptureFrame} from './service.ts';
import {applyCaptureSettingsOnConnect} from './settings_service.ts';
import {agentSockets,broadcast,captureTimers,failPendingFor,frameJson,FRAME_JSON,FRAME_MAX,log,nextId,pending,pruneSessions,sessions} from './state.ts';
import type {AgentMsg,AgentSession} from './state.ts';
import {normalizeStarttimeTicks} from './proc_identity.ts';
import type {UsbAgentLease} from './usb_agent_routes.ts';

export function acceptAgentSocket(sock:net.Socket,lease?:UsbAgentLease) {
  let queue=Promise.resolve();
  let session: AgentSession | null = null;
  let acc: Buffer = Buffer.alloc(0);
  sock.setNoDelay(true);

  sock.on('data', (chunk: Buffer) => {
    if(acc.length+chunk.length>FRAME_MAX+65536){sock.destroy();return;}
    acc = acc.length ? Buffer.concat([acc, chunk]) : chunk;
    for (;;) {
      if (acc.length < 5) break;
      const len = acc.readUInt32BE(0);
      const type = acc.readUInt8(4);
      if (len === 0 || len > FRAME_MAX) { log(`agent frame too large ${len} type=${type} — closing`); sock.destroy(); return; }
      if (acc.length < 5 + len) break;                 // wait for the rest of the frame
      const payload = acc.subarray(5, 5 + len);
      acc = acc.subarray(5 + len);
      if (type !== FRAME_JSON) { log(`agent unknown frame type ${type} — skipping`); continue; }
      let msg: AgentMsg;
      try { msg = JSON.parse(payload.toString('utf8')); } catch { log('bad json frame from agent, bytes=', len); continue; }
      if (!msg || typeof msg !== 'object') { sock.destroy(); return; }
      queue=queue.then(async()=>{
        if(sock.destroyed)return;
        if(session?msg.t==='hello':msg.t!=='hello'){sock.destroy();return;}
        if(!lease&&localObserver&&!session&&!acceptsLocalHello(localObserver,msg)){sock.destroy();return;}
        await handle(msg);
      }).catch(error=>{log('agent identity/frame rejected:',(error as Error).message);sock.destroy();});
    }
  });

  async function handle(msg: AgentMsg) {
    if (msg.t === 'hello') {
      const binding=lease?await lease.attest(msg):undefined;
      if(sock.destroyed)return;
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
      if(binding)Object.defineProperty(session,'deviceBinding',{value:binding,enumerable:true,writable:false,configurable:false});
      sessions.set(id, session);
      pruneSessions();   // a new dial-in is the natural moment to drop stale dead sessions
      agentSockets.set(id, sock);
      log(`agent HELLO ${session.package} pid=${session.pid} abi=${session.abi} entry=${session.entry} self=${session.selfModule || '?'} -> ${id}`);
      sock.write(frameJson({ t: 'ack', sessionId: id }));
      // Fresh process after unpack: allow auto-arm again (protect only blocks the live post-unpack session).

      broadcast('agent.hello', session);
      // Draining starts immediately. The algorithms checked in the panel are installed here,
      // on this process, so a restarted app keeps the same hooks.
      independentDeviceScope(binding?{serial:binding.serial,package:session.package,session:id}:{},()=>{
      clearCaptureArmProtect(session!.package);
      startCaptureLoop(id,{skipArm:true});
      const explicitControls=binding&&getCaptureControls().has(binding.serial,session!.package);
      if (binding&&!localObserver&&!explicitControls) void applyCaptureSettingsOnConnect(id).then(result => {
        if (result?.ok === false) log(`[capture] family arm ${id}:`, result.error || 'capture settings not applied');
      }).catch(error => log(`[capture] family arm ${id}:`, (error as Error).message));
      else if (binding&&!explicitControls&&localObserver&&binding.serial===localObserver.usbSerial&&session.package === localObserver.package) {
        // The observer tracks the live generation: a restarted app arrives with a new pid and
        // must update it or status/own-files checks keep pointing at the dead process. Only the
        // main process counts — `pkg:remote` helper pids are still sessions, just not THE app.
        if (!session.process || session.process === session.package) noteObservedPid(session.package, session.pid, binding.serial);
        void (isOwnDemoPackage(session.package)
        ? armSandboxCapture(id)
        : setCapture(id, true, { fileModule: 'libc.so', sysModule: 'libc.so' }))
        .then(result => log(`[capture] example arm ${id}: ok=${result.ok} installed=${result.installed}/${result.attempted}${result.notInstalled.length ? ' missing=' + result.notInstalled.join(',') : ''}${result.error ? ' ' + result.error : ''}`))
        .catch(error => log(`[capture] example arm ${id}:`, (error as Error).message));
      }
      });
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
    } else if (msg.t === 'captureBatch' && session) {
      ingestAgentCaptureFrame(session.sessionId, msg);
      session.lastSeen = Date.now();
    } else if (msg.t === 'cmdResult') {
      const p = pending.get(msg.id);
      log(`cmdResult op=${msg.op} id=${msg.id} matched=${!!p} bytes=${JSON.stringify(msg).length}`);
      if (p && session && p.sessionId===session.sessionId) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg); }
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
}

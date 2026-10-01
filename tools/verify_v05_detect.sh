#!/usr/bin/env bash
# v0.5 anti-analysis behavior observation (module V). Arms the persistent system hooks
# (ptrace / access / __system_property_get in the caller-named module), provokes the target's
# own detection workload through java_call, and asserts the agent observed the defense map:
# debug (ptrace TRACEME), root (su paths), prop (ro.debuggable).
# The old one-shot op also NEUTRALIZED TRACEME while it ran; that switch is gone with it
# (2026-10-01) - the persistent path is observe-only by design, so this script asserts
# observation only. Target survives. Exit 0 = PASS.
#
# The footprint assertion below assumes a process that has not run an inline hook yet
# (Dobby keeps its trampoline pool resident, which shows up as rwx/anon-exec). verify_all
# force-stops + relaunches the sandbox per script, so it always measures a fresh process.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
CLASS="com.adh.sandbox.Detection"
SYSMOD="libadhdetect.so"

set +e
OUT="$(node - "$HTTP" "$CLASS" "$SYSMOD" <<'EOF'
const [http, cls, sysmod]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  const on=await call('capture_start',{session:sid,sysModule:sysmod,cryptoModule:'libjavacrypto.so'});
  console.log(`capture_start: ok=${on.ok} installed=${on.installed}/${on.attempted} (sys=${JSON.stringify(on.reply?.sys ?? {})})`);
  const invoked=await call('java_call',{session:sid,className:cls,method:'run',params:'',args:[]});
  console.log(`java_call ${cls}.run -> ${JSON.stringify(invoked.result ?? invoked.error ?? null)}`);
  // Only events produced by MY trigger count: live_captures lists the whole store newest-last, so
  // a busy target fills the window with unrelated system captures (measured in the gate: 300
  // records, none of them mine) - and the trigger's own events are older than those.
  const t0=Date.now();
  let evs=[];
  for(let i=0;i<10 && evs.length===0;i++){
    await sleep(1000);
    const caps=await call('live_captures',{session:sid,category:'system',limit:1000,includeText:true});
    evs=(caps.captures||[]).filter(c=>Number(c.ts)>=t0);
  }
  evs.forEach(c=>console.log(`  [${c.func}] ${(c.ascii||'').slice(0,60)}`));
  const hasDebug = evs.some(c=>c.func==='ptrace' && /PTRACE_TRACEME/.test(c.ascii||''));
  const hasRoot  = evs.some(c=>c.func==='access' && /su/.test(c.ascii||''));
  const hasProp  = evs.some(c=>c.func==='sysprop' && /ro\.debuggable/.test(c.ascii||''));
  const detectPass = on.ok && hasDebug && hasRoot && hasProp;
  console.log(`observed: debug=${hasDebug} root=${hasRoot} prop=${hasProp} events=${evs.length}`);

  // S diagnostic: compatibility/anti-interference self-assessment
  const c=await (await fetch(`${base}/api/compat/probe?session=${sid}`)).json();
  const b=c.backends||{};
  console.log(`compat: tracerPid=${c.tracerPid} seccomp=${c.seccomp} backends=${JSON.stringify(b)}`);
  const fpShape = c.mapsReadOk===true && c.baselineValid===true && c.baseline && c.delta
    && Number.isInteger(c.execMappings) && Number.isInteger(c.anonExecMappings)
    && Number.isInteger(c.anonNamedExecMappings) && Number.isInteger(c.memfdExecMappings)
    && Number.isInteger(c.rwxMappings);
  const fpOk = fpShape && c.agentExecMappings>=1 && c.rwxMappings===0;
  console.log(`footprint: exec=${c.execMappings} anon=${c.anonExecMappings} anonNamed=${c.anonNamedExecMappings} memfd=${c.memfdExecMappings} rwx=${c.rwxMappings} agent=${c.agentExecMappings} zygisk=${c.zygiskExecMappings} baselineAnon=${c.baseline?.anonExecMappings} deltaAnon=${c.delta?.anonExecMappings}`);
  const compatPass = c.ok && b.gotHook && b.jniReflect && b.artDexCapture && b.memRead && c.tracerPid===0 && fpOk;

  const pass = detectPass && compatPass;
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.5 anti-analysis observation (defense map captured from the persistent system hooks)" 1 && exit 0 || exit 1

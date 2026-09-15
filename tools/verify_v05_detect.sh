#!/usr/bin/env bash
# v0.5 anti-analysis behavior observation (module V). GOT-hooks the target's native
# detection calls (in libidhdetect.so), triggers them via JNI reflection, and asserts
# the agent observed the target's defense map: debug (ptrace TRACEME), root (su paths),
# prop (ro.debuggable). Also neutralizes TRACEME (S). Target survives. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/detect/watch?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`hooked=${JSON.stringify(r.hooked)} triggered=${r.triggered} count=${r.count}`);
(r.detections||[]).forEach(x=>console.log(`  [${x.category}] ${x.detail}`));
const cats=(r.detections||[]);
const hasDebug = cats.some(x=>x.category==='debug' && /TRACEME/.test(x.detail));
const hasRoot  = cats.some(x=>x.category==='root' && /su/.test(x.detail));
const hasProp  = cats.some(x=>x.category==='prop' && /ro\.debuggable/.test(x.detail));
const detectPass = r.ok && r.triggered && r.hooked.ptrace>=1 && r.hooked.access>=1 && r.hooked.prop>=1
            && hasDebug && hasRoot && hasProp;
console.log(`observed: debug=${hasDebug} root=${hasRoot} prop=${hasProp}`);

// S diagnostic: compatibility/anti-interference self-assessment
const c=await (await fetch(`${base}/api/compat/probe?session=${a.sessionId}`)).json();
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
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.5 anti-analysis observation (defense map captured, TRACEME neutralized)" 1 && exit 0 || exit 1

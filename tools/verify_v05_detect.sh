#!/usr/bin/env bash
# v0.5 anti-analysis behavior observation (module V). GOT-hooks the target's native
# detection calls (in libidhdetect.so), triggers them via JNI reflection, and asserts
# the agent observed the target's defense map: debug (ptrace TRACEME), root (su paths),
# prop (ro.debuggable). Also neutralizes TRACEME (S). Target survives. Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
SERIAL="${IDH_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
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
const compatPass = c.ok && b.gotHook && b.jniReflect && b.artDexCapture && b.memRead && c.tracerPid===0;

const pass = detectPass && compatPass;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
ALIVE=$(adb -s "$SERIAL" shell pidof com.idh.sandbox 2>/dev/null | tr -d '\r ')
echo "sandbox alive: ${ALIVE:-NO}"
if echo "$OUT" | grep -q 'RESULT:PASS' && [ -n "$ALIVE" ]; then
  echo "✅ v0.5 anti-analysis observation PASS (defense map captured, TRACEME neutralized)"; exit 0
else echo "❌ v0.5 FAIL"; exit 1; fi

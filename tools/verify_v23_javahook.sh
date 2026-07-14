#!/usr/bin/env bash
# v2.1 WS-A — LSPlant Java-method hook, deterministic smoke test.
# Proves the ART method-hook backend works end-to-end: init LSPlant, hook a real Java method
# (com.idh.sandbox.HookTarget.secret), call it, and assert the callback fired capturing the
# real argument AND the original still returned its real value (backup.invoke worked — no
# recursion, no crash). This is the foundation for algorithm-agnostic crypto/privacy hooks.
# Exit 0 = PASS. Prereq: idhd running, device, sandbox running, tools/fetch_lsplant.sh ran.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
SERIAL="${IDH_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/java/hook_test?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`initOk=${r.initOk} hooked=${r.hooked} fired=${r.fired} origOk=${r.origOk} hits=${r.hits} lastArg=${r.lastArg} ret=${r.ret}`);
const pass = r.initOk===true && r.hooked===true && r.fired===true && r.origOk===true
  && r.lastArg==='IDH_HOOK_PING' && r.ret==='REAL_SECRET:IDH_HOOK_PING';
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
ALIVE=$(adb -s "$SERIAL" shell pidof com.idh.sandbox 2>/dev/null | tr -d '\r ')
echo "sandbox alive: ${ALIVE:-NO}"
if echo "$OUT" | grep -q 'RESULT:PASS' && [ -n "$ALIVE" ]; then
  echo "✅ v2.1 WS-A LSPlant Java-method hook PASS (init + hook + callback captured arg + original ran, no crash)"; exit 0
else echo "❌ v2.1 WS-A FAIL"; exit 1; fi

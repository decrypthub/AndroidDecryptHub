#!/usr/bin/env bash
# v0.4 GOT hook engine self-test. Prereq: idhd running, device, sandbox running.
#   Hooks the agent's own close() GOT slot, triggers a close, asserts:
#   replaced>=1 (slot found+swapped) AND fired (wrapper ran) AND process alive
#   (proves interception + trampoline-through-to-original without crash/hang).
# Exit 0 = PASS.
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
const r=await (await fetch(`${base}/api/hook/selftest?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`gothook: replaced=${r.replaced} fired=${r.fired} hits=${r.hitsAfter-r.hitsBefore}`);
const pass = r.ok && r.replaced>=1 && r.fired===true;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
PASS=$(echo "$OUT" | grep -c 'RESULT:PASS')
# also confirm the target process survived the hook (no crash)
ALIVE=$(adb -s "$SERIAL" shell pidof com.idh.sandbox 2>/dev/null | tr -d '\r ')
echo "sandbox alive after hook: ${ALIVE:-NO}"
if [ "$PASS" -ge 1 ] && [ -n "$ALIVE" ]; then
  echo "✅ v0.4 GOT hook engine PASS (intercept + trampoline, no crash)"; exit 0
else
  echo "❌ v0.4 GOT hook FAIL"; exit 1
fi

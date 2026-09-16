#!/usr/bin/env bash
# v1.4 Active-trigger scheduler (device). Asserts the trigger source works AND its safety
# policy holds: a SAFE static no-arg method (safeCompute) is invoked, while a dangerous one
# (deleteAll — blacklisted name) is SKIPPED, not called. This is the P2 "trigger source"
# that gives a refill-type shell a chance to restore CodeItems (then re-snapshot + recover).
# Exit 0 = PASS. Prereq: adhd + device + sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const C='com.adh.sandbox.TriggerProbe';
const trig=async(method,level)=> (await (await fetch(`${base}/api/unpack/trigger?session=${a.sessionId}&class=${encodeURIComponent(C)}&method=${method}&level=${level}`)).json());

const load=await trig('',1);
console.log(`level1 load: loaded=${load.loaded} reason=${load.reason||''}`);
const safe=await trig('safeCompute',3);
console.log(`safe invoke: invoked=${safe.invoked} result=${JSON.stringify(safe.result)} skipped=${safe.skipped}`);
const danger=await trig('deleteAll',3);
console.log(`danger invoke: invoked=${danger.invoked} skipped=${danger.skipped} reason=${JSON.stringify(danger.reason)}`);

const pass = load.loaded===true
  && safe.invoked===true && String(safe.result).includes('ADH_TRIGGER_OK')
  && danger.invoked===false && danger.skipped===true;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v1.4 active-trigger (安全 static 方法被调用 · 危险方法按策略跳过 · 类可加载)" 0 && exit 0 || exit 1

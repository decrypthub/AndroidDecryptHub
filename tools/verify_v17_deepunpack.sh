#!/usr/bin/env bash
# v1.7 Deep one-click unpack (device, axis 2 便捷性). Runs the unpack session in aggressive
# mode: triggerAllPrefix enumerates ALL of the app's classes from the dumped dex and loads
# them (Level 1) so a refill-type extraction shell restores every method's CodeItem — then
# re-snapshots and recovers. No AOSP flashing. Asserts many classes were enumerated+loaded,
# the safe method still invoked, and per-dex recovery reported + rebuilt parses. Exit 0=PASS.
set -uo pipefail
HTTP="${IDH_HTTP_PORT:-8760}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/unpack/run`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({session:a.sessionId,triggerAllPrefix:'com.idh.sandbox.',triggerClasses:['com.idh.sandbox.TriggerProbe'],triggerMethod:'safeCompute',level:3,maxClasses:200})})).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
const trig=r.triggered||[];
const loaded=trig.filter(t=>t.loaded===true).length;
const tp=trig.find(t=>String(t.class).includes('TriggerProbe'));
console.log(`triggered=${trig.length} loaded=${loaded} safeInvoked=${tp&&tp.invoked}`);
const dexOk=(r.dexes||[]).some(d=>!d.error && typeof d.recoveryBeforePct==='number' && d.parseOk===true);
console.log(`t0=${r.t0Count} t1=${r.t1Count} dexOk=${dexOk}`);
// aggressive mode should enumerate MANY app classes (Sandbox has 10+ classes), not just 1
const pass = r.ok===true && trig.length>=8 && loaded>=8 && !!(tp&&tp.invoked===true) && dexOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v1.7 deep unpack PASS (按包名枚举全类主动加载 · 安全调用 · 恢复+重建，无需刷 AOSP)"; exit 0
else echo "❌ v1.7 deep unpack FAIL"; exit 1; fi

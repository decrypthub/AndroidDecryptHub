#!/usr/bin/env bash
# v1.5 Full unpack SESSION (device). Runs the P3 capstone that ties P0-P2 together:
# T0 snapshot(每 DexFile) → coverage → active trigger → T1 snapshot → recover+rebuild.
# Asserts all phases complete, ≥1 base dex snapshotted, the trigger phase invoked our safe
# method, per-dex before/after recovery reported, and the rebuilt dex parses. On the
# (unpacked) sandbox recovered=0 by design — this verifies the ORCHESTRATION end-to-end
# (recovery correctness itself is proven byte-identical in v13). Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/unpack/run`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({session:a.sessionId,triggerClasses:['com.idh.sandbox.TriggerProbe'],triggerMethod:'safeCompute',level:3})})).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`phases=${(r.phases||[]).join('>')} t0=${r.t0Count} t1=${r.t1Count} triggered=${(r.triggered||[]).length} dexes=${(r.dexes||[]).length}`);
const tp=(r.triggered||[]).find(t=>String(t.class).includes('TriggerProbe'));
console.log(`trigger TriggerProbe: invoked=${tp&&tp.invoked}`);
const withCov=(r.dexes||[]).filter(d=>!d.error && typeof d.recoveryBeforePct==='number' && d.concreteJava>0);
const anyParse=withCov.some(d=>d.parseOk===true);
withCov.slice(0,3).forEach(d=>console.log(`  [${d.format}] java=${d.concreteJava} recover ${d.recoveryBeforePct}%→${d.recoveryAfterPct}% rebuilt=${d.parseOk}`));
const pass = r.ok===true && (r.phases||[]).length===5 && r.t0Count>=1 && r.t1Count>=1
  && !!(tp&&tp.invoked===true) && withCov.length>=1 && anyParse;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.5 unpack session (T0→触发→T1→恢复 五阶段贯通 · 前后覆盖率 · 重建可解析)" 0 && exit 0 || exit 1

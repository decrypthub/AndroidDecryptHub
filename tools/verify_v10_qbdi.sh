#!/usr/bin/env bash
# v1.0 QBDI instruction-level dynamic trace (I.3). Traces the sandbox's known native
# function adh_trace_target (sum i*3, i=0..4 -> 30) under QBDI's VM and asserts the
# correct return value + a real per-instruction trace (>=10 insns with arm64 mnemonics).
# Requires libQBDI.so bundled (tools/fetch_qbdi.sh). SKIPs cleanly if QBDI unavailable.
# Exit 0 = PASS (or SKIP). Prereq: adhd, device, sandbox running with libQBDI bundled.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
// The agent no longer knows any fixture name: the caller must name the library and symbol.
const r=await (await fetch(`${base}/api/trace/qbdi?session=${a.sessionId}&symLib=libadhdetect.so&symbol=adh_trace_target`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
if(r.ok===false && /not available|dlopen/.test(r.error||JSON.stringify(r))){console.log('QBDI not bundled -> SKIP');console.log('RESULT:SKIP');process.exit(0);}
console.log(`ok=${r.ok} retval=${r.retval} insnCount=${r.count} seen=${r.seen} truncated=${r.truncated} cap=${r.cap}`);
(r.insns||[]).slice(0,6).forEach(i=>console.log(`  ${i.addr}: ${i.text}`));
const texts=(r.insns||[]).map(i=>i.text).join(' ');
const hasMnemonics=/\b(ldr|str|add|sub|cmp|b\.)\b/.test(texts);
// v4.91: the reply must describe what it carries (count == insns.length) and say whether the
// trace was clipped - the digest can only be trusted if a clipped trace says so.
const shapeOk = Number(r.count)===(r.insns||[]).length && Number(r.seen)>=Number(r.count) && r.truncated===false;
if(!shapeOk) console.log(`trace shape: count=${r.count} insns=${(r.insns||[]).length} seen=${r.seen} truncated=${r.truncated}`);
const pass = r.ok===true && Number(r.retval)===30 && r.count>=10 && hasMnemonics && shapeOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then echo "✅ v1.0 QBDI instruction trace PASS (retval 30, real per-insn trace)"; exit 0;
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then echo "⏭  QBDI unavailable — SKIP"; exit 0;
else echo "❌ v1.0 QBDI FAIL"; exit 1; fi

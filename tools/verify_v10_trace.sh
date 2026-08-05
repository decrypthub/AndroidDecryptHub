#!/usr/bin/env bash
# v1.0 generic native function tracer (I.2 function-level). Traces calls to an
# arbitrary native symbol (args + tid + ts) via the GOT hook engine. Traces
# access() in libidhdetect during Detection.run() -> expects 2 calls (su-path
# checks) on one thread. Exit 0 = PASS. Prereq: idhd, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/trace/run?session=${a.sessionId}&symLib=libc.so&symbol=access&hookModule=libidhdetect.so`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`symbol=${r.symbol} replaced=${r.replaced} triggered=${r.triggered} calls=${r.count}`);
(r.calls||[]).forEach(c=>console.log(`  access("${c.a0str}") tid=${c.tid}`));
const tids=new Set((r.calls||[]).map(c=>c.tid));
const argsOk=(r.calls||[]).every(c=>c.a0 && c.tid && c.tsNs);
const suPaths=(r.calls||[]).filter(c=>/su$/.test(c.a0str||'')).length;   // arg string resolved
const pass = r.ok && r.replaced>=1 && r.triggered && r.count===2 && tids.size===1 && argsOk && suPaths===2;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v1.0 native function tracer (access() args + tid + ts captured)" 0 && exit 0 || exit 1

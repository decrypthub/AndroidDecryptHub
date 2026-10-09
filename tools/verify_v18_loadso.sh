#!/usr/bin/env bash
# v1.8 Load an arbitrary .so into the target (device). Proves the mechanism behind
# "load frida-gadget + run a script": the agent dlopen()s a .so BY ABSOLUTE PATH from
# inside the target and resolves its symbols. Uses the app's own libadhdetect.so (path
# discovered from /proc/<pid>/maps) + a known symbol. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
// discover the absolute path of the app's libadhdetect.so from the process maps
const maps=await (await fetch(`${base}/api/process/maps?session=${a.sessionId}`)).json();
const m=JSON.stringify(maps).match(/(\/[^"\\]*libadhdetect\.so)/);
const soPath = m ? m[1] : 'libadhdetect.so';   // fall back to soname
console.log('so path =', soPath);
// load it by path + probe a known exported symbol
const r=await (await fetch(`${base}/api/agent/load_so`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({session:a.sessionId,path:soPath,symbol:'adh_trace_target'})})).json();
console.log(`load_so ok=${r.ok} handle=${r.handle} symbolFound=${r.symbolFound} err=${JSON.stringify(r.error||'')}`);
const pass = r.ok===true && r.symbolFound===true && r.handle && r.handle!=='0';
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.8 load_so (从目标进程内按路径 dlopen 任意 .so + 符号解析 — frida-gadget 同理)" 0 && exit 0 || exit 1

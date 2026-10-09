#!/usr/bin/env bash
# v2.5 Filesystem browser (device). Proves the agent's new collect-only fs commands that
# back the web「文件」panel: list_dir a real directory + read_file a real file, both from
# inside the target with the target's own permissions. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
// 1) list the app's own private data dir — it can always stat its home
const dd=`/data/data/${a.package}`;
const ls=await (await fetch(`${base}/api/fs/list?path=${encodeURIComponent(dd)}&session=${a.sessionId}`)).json();
console.log(`list_dir ${dd} ok=${ls.ok} count=${ls.count} truncated=${ls.truncated} err=${JSON.stringify(ls.error||'')}`);
// 2) read a guaranteed-present file that proves identity: /proc/self/cmdline == package
const rd=await (await fetch(`${base}/api/fs/read`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({session:a.sessionId,path:'/proc/self/cmdline'})})).json();
const text=(rd.text||'');
console.log(`read_file /proc/self/cmdline ok=${rd.ok} size=${rd.size} hasPkg=${text.includes(a.package)}`);
// 3) honest failure: a path that cannot exist must return ok:false + errno, not a silent empty
const bad=await (await fetch(`${base}/api/fs/list?path=${encodeURIComponent('/nonexistent-'+Date.now())}&session=${a.sessionId}`)).json();
console.log(`list_dir bad-path ok=${bad.ok} err=${JSON.stringify((bad.error||'').slice(0,40))}`);
const pass = ls.ok===true && rd.ok===true && rd.size>0 && text.includes(a.package) && bad.ok===false;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v2.5 fs browser (list_dir 私有目录 + read_file 真实文件 + 坏路径 fail-loud)" 0 && exit 0 || exit 1

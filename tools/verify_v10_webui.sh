#!/usr/bin/env bash
# Host-only Vue console contract. Component/SSR flow tests are not browser/device acceptance.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
OUT="$(node --input-type=module - "$ROOT" "$BASE" <<'EOF'
import {spawnSync} from 'node:child_process';
const [root,base]=process.argv.slice(2),checks=[],chk=(name,ok,detail='')=>{checks.push(!!ok);console.log((ok?'PASS ':'FAIL ')+name+(detail?' — '+detail:''));};
let html='';try{const r=await fetch(base+'/',{signal:AbortSignal.timeout(8000)});html=await r.text();chk('page serves',r.status===200&&html.length>1000);}catch(e){chk('page serves',false,e.message);}
chk('ADH brand and all primary user areas',/<title>ADH/.test(html)&&['加解密','系统','网络','文件','脱壳','设置','raven.svg'].every(s=>html.includes(s)));
chk('retired Gadget, phone automation and marketing surfaces absent',!['load_frida_gadget','AdhHookPlansPanel','wechat-follow.png','公众号'].some(s=>html.includes(s)));
const ui=spawnSync(process.execPath,['--test','--test-reporter=tap',root+'/panel/test/*.test.mjs'],{encoding:'utf8',env:{...process.env,ADH_PANEL_ROOT:root+'/panel'}}),pass=Number(/# pass (\d+)/.exec(ui.stdout??'')?.[1]??0),fail=Number(/# fail (\d+)/.exec(ui.stdout??'')?.[1]??-1);
chk('actual Vue capture/filter/detail/paging/copy/export/device/app/settings flows',ui.status===0&&pass>=85&&fail===0,'pass='+pass+' fail='+fail);if(ui.status!==0)console.log(ui.stdout,ui.stderr);
const blocks=[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1]).filter(s=>s.trim());chk('inline production modules exist and parse',blocks.length>0&&blocks.every(input=>spawnSync(process.execPath,['--check','--input-type=module'],{input,encoding:'utf8'}).status===0));
for(const path of ['/api/captures','/api/dumps','/api/agents']){try{const r=await fetch(base+path,{signal:AbortSignal.timeout(8000)});chk(path+' responds with JSON',r.status===200&&/json/.test(r.headers.get('content-type')||''));}catch(e){chk(path+' responds',false,e.message);}}
try{const r=await fetch(base+'/workbench?taskId=fixture',{redirect:'manual',signal:AbortSignal.timeout(8000)});chk('legacy history entry redirects to viewer',r.status===302);}catch(e){chk('legacy history redirect',false,e.message);}
try{const r=await fetch(base+'/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'}),signal:AbortSignal.timeout(8000)}),j=await r.json();chk('MCP tools/list responds',r.status===200&&Array.isArray(j.result?.tools)&&j.result.tools.length>=25);}catch(e){chk('MCP tools/list responds',false,e.message);}
console.log(checks.every(Boolean)?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
rc=$?
echo "$OUT"
[ "$rc" -eq 0 ] || { echo "RESULT:FAIL node exited $rc"; exit "$rc"; }
verify_gate 'Vue Web console contracts (browser/device verification separate)' 0

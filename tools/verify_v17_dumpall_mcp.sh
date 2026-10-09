#!/usr/bin/env bash
# v1.7 MCP one-click dump-all DEX (device). Calls the MCP tool `dump_all_dex` through
# /mcp JSON-RPC (not the REST endpoint) and asserts the tool exists, the old session-based
# unpack tool is gone, and the returned dump list contains at least one stored DEX.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const list=await rpc('tools/list',{});
const names=(list.result?.tools||[]).map(t=>t.name);
const hasNew=names.includes('dump_all_dex');
const oldGone=!names.includes('unpack_run');
const call=await rpc('tools/call',{name:'dump_all_dex',arguments:{session:a.sessionId}});
let r={}; try{ r=JSON.parse(call.result?.content?.[0]?.text||'{}'); }catch{}
const okDex=(r.dexes||[]).filter(d=>!d.error && d.sha256);
console.log(`tools: dump_all_dex=${hasNew} unpack_run_absent=${oldGone} count=${r.count} dumped=${r.dumped} failed=${r.failed}`);
okDex.slice(0,3).forEach(d=>console.log(`  [${d.format}] ${d.size}B @${d.begin} sha=${d.sha256.slice(0,16)}`));
const pass = hasNew && oldGone && r.ok===true && r.count>=1 && r.dumped>=1 && r.failed===0 && okDex.length>=1;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.7 MCP one-click dump-all DEX (dump_all_dex · ART DexFile 枚举 + dump + SHA-256 去重)" 0 && exit 0 || exit 1

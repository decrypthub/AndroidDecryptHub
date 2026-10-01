#!/usr/bin/env bash
# v1.0 MCP Server (HOST-ONLY). Speaks MCP JSON-RPC to /mcp: initialize, tools/list,
# and a tools/call (dex_search on the probe dex). Asserts protocol + a real tool result.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
PROBE_B64="ZGV4CjAzOAAldROcj4AnW/EXyPvKv8zYfcWhEh6enuXYAgAAcAAAAHhWNBIAAAAAAAAAAFACAAAKAAAAcAAAAAQAAACYAAAAAgAAAKgAAAAAAAAAAAAAAAMAAADAAAAAAQAAANgAAADgAQAA+AAAADABAAA4AQAARgEAAEkBAABgAQAAdAEAAIgBAACUAQAAlwEAAJ4BAAADAAAABAAAAAUAAAAHAAAAAgAAAAIAAAAAAAAABwAAAAMAAAAAAAAAAAABAAAAAAAAAAAACAAAAAEAAQAAAAAAAAAAAAEAAAABAAAAAAAAAAYAAAAAAAAAQAIAAAAAAAABAAAAAAAAACgBAAADAAAAGgABABEAAAABAAEAAQAAACwBAAAEAAAAcBACAAAADgADAA4AAgAOAAY8aW5pdD4ADElESF9QUk9CRV9PSwABTAAVTGNvbS9pZGgvcHJvYmUvUHJvYmU7ABJMamF2YS9sYW5nL09iamVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwAKUHJvYmUuamF2YQABVgAFaGVsbG8AnwF+fkQ4eyJiYWNrZW5kIjoiZGV4IiwiY29tcGlsYXRpb24tbW9kZSI6InJlbGVhc2UiLCJoYXMtY2hlY2tzdW1zIjpmYWxzZSwibWluLWFwaSI6MjYsInNoYS0xIjoiYTdhZDE4YTcwNDYwYjc5OWQwNDgyZTQ5N2MxMDlhNzViZjdmOTFkZSIsInZlcnNpb24iOiI4LjEwLjktZGV2In0AAAACAACBgASQAgEJ+AEAAAsAAAAAAAAAAQAAAAAAAAABAAAACgAAAHAAAAACAAAABAAAAJgAAAADAAAAAgAAAKgAAAAFAAAAAwAAAMAAAAAGAAAAAQAAANgAAAABIAAAAgAAAPgAAAADIAAAAgAAACgBAAACIAAACgAAADABAAAAIAAAAQAAAEACAAAAEAAAAQAAAFACAAA="

set +e
OUT="$(node - "$HTTP" "$PROBE_B64" <<'EOF'
const [http, probe]=process.argv.slice(2); const url=`http://127.0.0.1:${http}/mcp`;
const rpc=(m,p)=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const init=await rpc('initialize',{});
console.log('initialize:',init.result?.protocolVersion, init.result?.serverInfo?.name);
const list=await rpc('tools/list',{});
const names=(list.result?.tools||[]).map(t=>t.name);
console.log('tools:',names.length);
const need=['process_list','memory_read','memory_disasm','native_call','syscall_watch','qbdi_trace','art_dexfiles','capture_start','capture_stop','live_captures','dex_search','dex_xref','native_disasm'];
const haveAll=need.every(n=>names.includes(n));
// tools/call: dex_search on probe dex
const call=await rpc('tools/call',{name:'dex_search',arguments:{b64:probe,query:'Probe',kinds:['class']}});
const text=call.result?.content?.[0]?.text||'';
const foundProbe=/Lcom\/idh\/probe\/Probe;/.test(text);
console.log('dex_search via MCP -> found Probe class:',foundProbe);
// tools/call: process_list (works without device)
const pl=await rpc('tools/call',{name:'process_list',arguments:{}});
const plOk=Array.isArray(JSON.parse(pl.result?.content?.[0]?.text||'null'));
const pass = init.result?.protocolVersion==='2024-11-05' && names.length>=15 && haveAll && foundProbe && plOk;
console.log(`tools present=${haveAll} process_list ok=${plOk}`);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v1.0 MCP server (initialize + tools/list + tools/call)" 0 && exit 0 || exit 1

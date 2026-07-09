#!/usr/bin/env bash
# v0.6 Runtime Object Inspector (module T). Reflectively reads a live object's fields.
# Reads HeapProbe.sConfig (a Config with known values) and asserts token/count/note.
# Exit 0 = PASS. Prereq: idhd running, device, sandbox running.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const POST=(p,b)=>fetch(`${base}${p}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await POST('/api/object/inspect',{session:a.sessionId,className:'com.idh.sandbox.HeapProbe',field:'sConfig'});
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`objectClass=${r.objectClass} fields=${r.fieldCount}`);
(r.fields||[]).forEach(f=>console.log(`  ${f.name} = ${f.value}`));
const fv=Object.fromEntries((r.fields||[]).map(f=>[f.name,f.value]));
const pass = r.ok && /HeapProbe\$Config/.test(r.objectClass)
  && fv.token==='IDH_TOKEN_abc123' && fv.count==='42' && fv.note==='live-object';
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
echo "$OUT" | grep -q 'RESULT:PASS' && exit 0 || exit 1

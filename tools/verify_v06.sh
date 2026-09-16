#!/usr/bin/env bash
# v0.6 Runtime Object Inspector (module T). Reflectively reads a live object's fields.
# Reads HeapProbe.sConfig (a Config with known values) and asserts token/count/note.
# Exit 0 = PASS. Prereq: adhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const POST=(p,b)=>fetch(`${base}${p}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await POST('/api/object/inspect',{session:a.sessionId,className:'com.adh.sandbox.HeapProbe',field:'sConfig'});
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`objectClass=${r.objectClass} fields=${r.fieldCount}`);
(r.fields||[]).forEach(f=>console.log(`  ${f.name} = ${f.value}`));
const fv=Object.fromEntries((r.fields||[]).map(f=>[f.name,f.value]));
const readPass = r.ok && /HeapProbe\$Config/.test(r.objectClass)
  && fv.token==='ADH_TOKEN_abc123' && fv.count==='42' && fv.note==='live-object';

// low-risk method invocation
const inv=await POST('/api/object/invoke',{session:a.sessionId,className:'com.adh.sandbox.HeapProbe',field:'sConfig',method:'getToken'});
console.log(`invoke getToken() -> ${inv.result||inv.error}`);
const invPass = inv.ok && inv.result==='ADH_TOKEN_abc123';

const pass = readPass && invPass;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v0.6 runtime object inspector (live object field read + method invoke)" 0 && exit 0 || exit 1

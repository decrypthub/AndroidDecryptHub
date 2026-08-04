#!/usr/bin/env bash
# v2.2 WS-A native inline hook acceptance. The sandbox JNI bridge calls the target function
# directly inside libidhdetect.so, so there is no imported GOT slot to replace. Dobby must
# patch the function entry, preserve the original trampoline, capture the known plaintext,
# and remain stable across an idempotent second call in the same process. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const J=(p)=>fetch(`${base}${p}`).then(async r=>({status:r.status,body:await r.json()}));
const agents=(await J('/api/agents')).body;
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const results=[];
for(let i=0;i<2;i++) results.push(await J(`/api/native/inline_hook_test?session=${encodeURIComponent(a.sessionId)}`));
let pass=true;
for(const [i,r] of results.entries()){
  const b=r.body;
  const hits=(b.captures||[]).filter(x=>x.func==='INLINE_EVP_CipherUpdate');
  const marker=hits.some(x=>(x.ascii||'').includes('IDH_INLINE_CRYPTO_v1'));
  console.log(`run=${i+1} status=${r.status} ok=${b.ok} hooked=${b.hooked} installed=${b.installed} triggered=${b.triggered} result=${b.result} captures=${b.captureCount} marker=${marker} error=${JSON.stringify(b.error)}`);
  pass&&=r.status===200&&b.ok===true&&b.hooked===true&&b.triggered===true&&b.result===1&&hits.length===1&&marker;
}
pass&&=results[0].body.installed===true&&results[1].body.installed===false;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v2.2 native inline hook (direct entry, original trampoline, marker capture, idempotent reuse)" 1 && exit 0 || exit 1

#!/usr/bin/env bash
# Java crypto hook gate. JavaCrypto.javaHookProbe runs AES-CBC (encrypt and decrypt),
# AES-GCM, HmacSHA256, SHA-256, RSA-2048 and SHA256withRSA on a platform provider,
# skipping the sandbox's own ADH-Intercept reporter. A java-source capture of those
# markers is the plugin hook. The probe return value shows the original methods still ran.
# Prereq: adhd + device + sandbox (verify_all relaunches it). Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ]; then
  echo "SKIP verify_v104_java_hook.sh (no device)"
  exit 0
fi

verify_restart_sandbox || true
verify_sandbox_alive
if [ -z "${ALIVE:-}" ]; then
  echo "SKIP verify_v104_java_hook.sh (sandbox not running)"
  exit 0
fi

SID=""
for _ in 1 2 3 4 5 6 7 8; do
  SID="$(cd "$ROOT/daemon" && node src/cli.ts target --package com.adh.sandbox --quiet 2>/dev/null)" && [ -n "$SID" ] && break
  SID=""
  sleep 1
done

# JCA hooks are not armed at inject. Ask for them, then wait for the installer log.
if [ -n "$SID" ]; then
  node - "$HTTP" "$SID" <<'EOF'
const http = process.argv[2], sid = process.argv[3];
const body = { jsonrpc: '2.0', id: 104, method: 'tools/call', params: { name: 'java_hook', arguments: { session: sid, action: 'crypto' } } };
const r = await fetch(`http://127.0.0.1:${http}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const j = await r.json();
const text = j.result?.content?.[0]?.text ?? JSON.stringify(j.error ?? j);
console.log(`arm: ${String(text).slice(0, 240)}`);
if (!String(text).includes('"ok":true') && !String(text).includes('"ok": true')) process.exit(2);
EOF
fi

HOOK_LINE=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  HOOK_LINE="$(adb -s "$SERIAL" logcat -d --pid="$ALIVE" -t 800 2>/dev/null | grep -F "java crypto on " | tail -1 | tr -d '\r')"
  if printf '%s\n' "$HOOK_LINE" | grep -qE 'java crypto on [1-9]'; then break; fi
  sleep 1
done
echo "hook install: ${HOOK_LINE:-none}"
HOOK_N="$(printf '%s\n' "$HOOK_LINE" | sed -n 's/.*java crypto on \([0-9][0-9]*\).*/\1/p' | tail -1)"

set +e
if [ -z "$SID" ]; then
  OUT="NO_AGENT
RESULT:FAIL"
else
OUT="$(node - "$HTTP" "$SID" "${HOOK_N:-0}" <<'EOF'
const http=process.argv[2]; const sid=process.argv[3]; const hookN=Number(process.argv[4]||0);
const base=`http://127.0.0.1:${http}`;
const J=(p)=>fetch(`${base}${p}`).then(r=>r.json());
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const C='com.adh.sandbox.JavaCrypto';
const trig=(method)=>J(`/api/unpack/trigger?session=${encodeURIComponent(sid)}&class=${encodeURIComponent(C)}&method=${method}&level=3`);

console.log(`java crypto hooks installed: ${hookN}`);
if(!(hookN>=1)){ console.log('RESULT:FAIL (java crypto hooks not installed)'); process.exit(0); }

await trig('stopLive');
await sleep(1500);
const base0=await J('/api/captures?limit=1');
console.log(`baseline: on=${base0.on} total=${base0.total}`);
if(base0.on!==true){ console.log('RESULT:FAIL (capture not on)'); process.exit(0); }
const since=(base0.captures&&base0.captures.length)?base0.captures[base0.captures.length-1].id:0;

const probe=await trig('javaHookProbe');
const result=String(probe.result||'');
console.log(`probe: invoked=${probe.invoked} result=${result} reason=${probe.reason||''}`);
if(probe.invoked!==true || !result.startsWith('ok ')){
  console.log('RESULT:FAIL (probe did not complete)');
  process.exit(0);
}

let list=[];
for(let i=0;i<12;i++){
  await sleep(800);
  const c=await J(`/api/captures?since=${since}&limit=500`);
  list=c.captures||[];
  if(list.filter(x=>x.source==='java').length>=8) break;
}
const java=list.filter(x=>x.source==='java');
console.log(`captures since=${since}: total=${list.length} java=${java.length}`);

const details=[];
for(const h of java) details.push(await J(`/api/captures/${h.id}`));
const hit=(pred)=>details.some(pred);
const aes=hit(d=>(d.text||'').includes('ADH_JHOOK_AES_v1') && String(d.algo||'').includes('AES/CBC') && d.op==='encrypt' && String(d.keyHex||'').length>=32);
const aesDec=hit(d=>String(d.algo||'').includes('AES/CBC') && d.op==='decrypt');
const gcm=hit(d=>(d.text||'').includes('ADH_JHOOK_GCM_v1') && String(d.algo||'').includes('AES/GCM') && d.op==='encrypt');
const hmac=hit(d=>(d.text||'').includes('ADH_JHOOK_HMAC_v1') && String(d.algo||'').includes('HmacSHA256') && String(d.keyHex||'').length>=32);
const digest=hit(d=>(d.text||'').includes('ADH_JHOOK_DIGEST_v1') && String(d.algo||'').includes('SHA-256') && d.op==='digest');
const rsa=hit(d=>(d.text||'').includes('ADH_JHOOK_RSA_v1') && String(d.algo||'').includes('RSA'));
const sign=hit(d=>String(d.algo||'').includes('SHA256withRSA') && d.op==='sign' && String(d.outHex||'').length>0);
const verify=hit(d=>String(d.algo||'').includes('SHA256withRSA') && d.op==='verify' && Number(d.inl||0)>0);
console.log(`hook hits aes=${aes} decrypt=${aesDec} gcm=${gcm} hmac=${hmac} digest=${digest} rsa=${rsa} sign=${sign} verify=${verify}`);

const pass=aes&&aesDec&&gcm&&hmac&&digest&&rsa&&sign&&verify;
if(!pass){
  for(const d of details.slice(0, 24)){
    console.log(`java algo=${d.algo} op=${d.op} key=${String(d.keyHex||'').length} text=${String(d.text||'').slice(0,48)}`);
  }
}
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
fi
echo "$OUT"
verify_sandbox_alive
verify_gate "Java crypto hooks capture AES/GCM/HMAC/digest/RSA/Signature and the original methods still return" 1 && exit 0 || exit 1

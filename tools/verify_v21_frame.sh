#!/usr/bin/env bash
# v2.0 WS-D — length-framed protocol ([u32 len][u8 type][payload]) acceptance.
#   A) Oversized command (daemon→agent direction): send a 1MB `pad` command frame with a
#      `tail` sentinel placed AFTER the pad (past byte 8192). The old NDJSON reader capped
#      inbound command lines at 8192 bytes and would have truncated the tail; framing must
#      deliver the whole frame so the agent echoes recvBytes>padLen and the exact tail.
#   B) 16MB region dump integrity (agent→daemon direction): dump 16MB from a stable
#      read-only file-backed region (daemon reads it in 1MB frames), then independently
#      re-read the same 16MB in 256KB frames; assert byte-exact sha256 match + exact size.
#      Proves multi-MB responses survive across differing frame boundaries with no
#      corruption/truncation (old 8192 single-line limit is gone).
# Exit 0 = PASS. Prereq: adhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const J=(p,b)=>fetch(`${base}${p}`,b?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}:{}).then(r=>r.json());
const sha256=async(u8)=>Buffer.from(await crypto.subtle.digest('SHA-256',u8)).toString('hex');
const agents=await J('/api/agents');
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;

// A) oversized command frame — 1MB pad, tail sentinel past the old 8192 cap
const fe=await J(`/api/debug/frame_echo?session=${sid}&kb=1024`);
console.log(`A frame_echo: ok=${fe.ok} recvBytes=${fe.recvBytes} sentPadLen=${fe.sentPadLen} tailOk=${fe.tailOk} notTruncated=${fe.notTruncated}`);
const aPass = !!fe.ok && fe.tailOk===true && fe.notTruncated===true && (fe.recvBytes||0)>(fe.sentPadLen||0);

// B) 16MB dump integrity across frame sizes
const SIZE=16*1024*1024;
const maps=await J(`/api/process/maps?session=${sid}`);
const szOf=(r)=>Number(BigInt('0x'+r.end)-BigInt('0x'+r.start));
const cand=(maps.regions||[]).filter(r=>
  r.perms && r.perms[0]==='r' && r.perms[1]!=='w' && r.path && r.path[0]!=='[' && szOf(r)>=SIZE
).sort((x,y)=>szOf(y)-szOf(x));
let bPass=false, detail='no candidate region>=16MB';
for(const r of cand.slice(0,5)){
  const d=await J('/api/memory/dump',{session:sid,addr:r.start,size:SIZE,tag:'ws-d-16mb'});
  if(!d.sha256||d.size!==SIZE){ detail=`dump ${r.path.split('/').pop()} size=${d.size} want=${SIZE}`; continue; }
  const parts=[]; let off=0, ok=true; const base16=BigInt('0x'+r.start); const CH=256*1024;
  while(off<SIZE){
    const want=Math.min(CH,SIZE-off);
    const rr=await J('/api/memory/read',{session:sid,addr:(base16+BigInt(off)).toString(16),size:want});
    if(!rr.ok||!rr.b64){ ok=false; detail=`reread fail @${off}`; break; }
    const buf=Buffer.from(rr.b64,'base64');
    if(buf.length!==want){ ok=false; detail=`reread short @${off} got=${buf.length} want=${want}`; break; }
    parts.push(buf); off+=buf.length;
  }
  if(!ok) continue;
  const rsha=await sha256(Buffer.concat(parts));
  const match=rsha===d.sha256;
  console.log(`B region ${r.path.split('/').pop()} @${r.start} dumpSha=${d.sha256.slice(0,16)} rereadSha=${rsha.slice(0,16)} match=${match}`);
  if(match){ bPass=true; detail='ok'; break; }
  detail='sha mismatch';
}
console.log(`B 16MB dump integrity: ${bPass?'PASS':'FAIL'} (${detail})`);

const pass=aPass&&bPass;
console.log(`aPass=${aPass} bPass=${bPass}`);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v2.0 WS-D length-framed protocol (1MB command frame past 8192 cap + 16MB dump byte-exact across 1MB/256KB frame sizes)" 1 && exit 0 || exit 1

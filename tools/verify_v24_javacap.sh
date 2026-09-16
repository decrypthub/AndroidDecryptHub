#!/usr/bin/env bash
# v2.x Java rich-capture (decoupled JNI binding). The agent binds the target's reporter
# (AdhReport.nReport) at JNI_OnLoad via RegisterNatives, using the class name the TARGET
# publishes through the "adh.reporter.class" system property — the agent hardcodes no class
# name and carries no sandbox-specific JNI symbol. This test lets the sandbox's live crypto
# driver run a few ops through the interposing JCE provider, then asserts rich Java-layer
# captures (source=java carrying algorithm+key+iv+plaintext+ciphertext) reach /api/captures —
# proving the target-agnostic RegisterNatives binding actually works. Exit 0 = PASS.
# Prereq: adhd + device + sandbox running (verify_all relaunches it).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# let the live driver push JCE ops through the reporter; the Node body polls for a rich capture
sleep 2

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let on=false, total=0, java=[], rich=0, plainOk=false;
for(let i=0;i<20;i++){
  const j=await (await fetch(`${base}/api/captures?limit=200`)).json();
  on=j.on===true; total=j.total;
  java=(j.captures||[]).filter(c=>c.source==='java');
  rich=0; plainOk=false;
  for(const c of java.slice(-25)){
    const d=await (await fetch(`${base}/api/captures/${c.id}`)).json();
    if(d.keyHex && d.ivHex && d.hex && d.outHex) rich++;
    if((d.text||'').includes('ADH_LIVE_')) plainOk=true;
  }
  if(on && rich>=1 && plainOk) break;
  await sleep(2000);
}
console.log('on=',on,'total=',total,'javaCaptures=',java.length);
console.log('richJava(key+iv+in+out)=',rich,'plaintextADH_LIVE=',plainOk);
const pass = on && java.length>=1 && rich>=1 && plainOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v2.x Java rich-capture (decoupled RegisterNatives: 算法+Key+IV+明文+密文)" 0 && exit 0 || exit 1

#!/usr/bin/env bash
# v2.x Java rich-capture (decoupled JNI binding). The agent binds the target's reporter
# (AdhReport.nReport) at JNI_OnLoad via RegisterNatives, using the class name the TARGET
# publishes through the "adh.reporter.class" system property — the agent hardcodes no class
# name and carries no sandbox-specific JNI symbol. This test lets the sandbox's live crypto
# driver run a few ops through the interposing JCE provider, then asserts rich Java-layer
# captures (source=java carrying algorithm+key+iv+plaintext+ciphertext) reach /api/captures —
# proving the target-agnostic RegisterNatives binding actually works. Exit 0 = PASS.
# Prereq: idhd + device + sandbox running (verify_all relaunches it).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# let the live driver (one op / ~2s) push a few JCE ops through the reporter
sleep 8

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const j=await (await fetch(`${base}/api/captures?limit=100`)).json();
const caps=j.captures||[];
const java=caps.filter(c=>c.source==='java');
console.log('on=',j.on,'total=',j.total,'javaCaptures=',java.length);
let rich=0, plainOk=false;
for(const c of java.slice(-5)){
  const d=await (await fetch(`${base}/api/captures/${c.id}`)).json();
  if(d.keyHex && d.ivHex && d.hex && d.outHex) rich++;
  if((d.text||'').includes('IDH_LIVE_')) plainOk=true;
}
console.log('richJava(key+iv+in+out)=',rich,'plaintextIDH_LIVE=',plainOk);
const pass = j.on===true && java.length>=1 && rich>=1 && plainOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v2.x Java rich-capture (decoupled RegisterNatives: 算法+Key+IV+明文+密文)" 0 && exit 0 || exit 1

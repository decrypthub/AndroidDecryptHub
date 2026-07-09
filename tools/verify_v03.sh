#!/usr/bin/env bash
# v0.3 acceptance (grows per increment). Prereq: idhd running, device attached, sandbox running.
#   (1) jni_probe: agent does JNI reflection from its native thread -> Build.VERSION.SDK_INT==36
# Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const P=(o)=>fetch(`${base}${o.path}`,o.body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(o.body)}:{}).then(r=>r.json());
const agents=await P({path:'/api/agents'});
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).pop();
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}

// (1) JNI reflection foundation
const j=await P({path:`/api/jni/probe?session=${a.sessionId}`});
console.log(`jni_probe: ok=${j.ok} sdk_int=${j.sdk_int} release=${j.release} attached=${j.attached}`);
const jniPass = j.ok && j.sdk_int===36;

const pass = jniPass;
console.log(pass?'✅ v0.3 PASS (JNI reflection foundation)':'❌ v0.3 FAIL');
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
echo "$OUT" | grep -q 'RESULT:PASS' && exit 0 || exit 1

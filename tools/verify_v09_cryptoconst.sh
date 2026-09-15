#!/usr/bin/env bash
# v0.9 native crypto-constant scan (H.4, HOST-ONLY). Locates crypto algorithms in a
# stripped native lib by constant signatures (no symbols). libadhdetect.so embeds the
# real AES S-box + Base64 alphabet; the scan must find both. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
bash "$ROOT/tools/build_detect.sh" >/dev/null 2>&1
SO="$ROOT/sandbox-app/app/src/main/jniLibs/arm64-v8a/libadhdetect.so"
[ -f "$SO" ] || { echo "❌ libadhdetect.so missing"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$SO" <<'EOF'
import fs from 'node:fs';
const [http, so]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const b64=fs.readFileSync(so).toString('base64');
const r=await (await fetch(`${base}/api/native/crypto_const`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({b64})})).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`size=${r.size} algorithms=${JSON.stringify(r.algorithms)} byName=${JSON.stringify(r.byName)}`);
const pass = (r.byName['AES-Sbox']>=1) && (r.byName['Base64-std']>=1);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v0.9 native crypto-constant scan (AES S-box + Base64 alphabet found)" 0 && exit 0 || exit 1

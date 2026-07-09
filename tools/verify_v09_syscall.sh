#!/usr/bin/env bash
# v0.9 direct-syscall scan (E.9, HOST-ONLY). Locates `svc #0` in a .so's exec
# segments (direct syscalls bypass libc/PLT hooks). libidhdetect.so has one direct
# gettid via inline svc; the scan must find >=1 svc site. Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
bash "$ROOT/tools/build_detect.sh" >/dev/null 2>&1
SO="$ROOT/sandbox-app/app/src/main/jniLibs/arm64-v8a/libidhdetect.so"
[ -f "$SO" ] || { echo "❌ libidhdetect.so missing"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$SO" <<'EOF'
import fs from 'node:fs';
const [http, so]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const b64=fs.readFileSync(so).toString('base64');
const r=await (await fetch(`${base}/api/native/syscall_scan`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({b64})})).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`execSegs=${r.execSegs} scannedBytes=${r.scannedBytes} svcCount=${r.svcCount}`);
(r.hits||[]).slice(0,4).forEach(h=>console.log(`  svc @file ${h.fileOff} vaddr ${h.vaddr}`));
const pass = r.execSegs>=1 && r.svcCount>=1;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
echo "$OUT" | grep -q 'RESULT:PASS' && exit 0 || exit 1

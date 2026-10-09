#!/usr/bin/env bash
# v0.2 dex header repair acceptance (HOST-ONLY — no device needed).
# Uses a REAL dex (classes.dex from the sandbox APK):
#   1) read good dex; record its checksum/signature/file_size
#   2) corrupt those header fields (zero them)
#   3) POST /api/dex/repair -> repaired fields
#   4) assert repaired checksum/signature/file_size EXACTLY match the original good dex
# Exit 0 = PASS. Prereq: adhd running; sandbox APK built.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "❌ APK missing (build sandbox first)"; echo "RESULT:FAIL"; exit 1; }

# extract classes.dex
TMP="$ROOT/_classes.dex"
unzip -p "$APK" classes.dex > "$TMP" 2>/dev/null
[ -s "$TMP" ] || { echo "❌ could not extract classes.dex"; echo "RESULT:FAIL"; exit 1; }

set +e
OUT="$(node - "$HTTP" "$TMP" <<'EOF'
import fs from 'node:fs';
const [http, file] = process.argv.slice(2);
const base=`http://127.0.0.1:${http}`;
const good = fs.readFileSync(file);
// original header fields
const origChecksum = good.readUInt32LE(8).toString(16).padStart(8,'0');
const origSig = good.subarray(12,32).toString('hex');
const origFileSize = good.readUInt32LE(32);
console.log(`good dex: len=${good.length} fileSize=${origFileSize} checksum=${origChecksum} sig=${origSig.slice(0,16)}…`);
const validSelf = origFileSize===good.length; // real dex file_size == length
// corrupt a COPY
const bad = Buffer.from(good);
bad.writeUInt32LE(0,8); bad.fill(0,12,32); bad.writeUInt32LE(0,32);
// repair
const r=await (await fetch(`${base}/api/dex/repair`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({b64:bad.toString('base64')})})).json();
console.log(`repaired: fileSize=${r.fileSize} checksum=${r.checksum} sig=${(r.signature||'').slice(0,16)}… magicOk=${r.magicOk}`);
// The repaired dex is stored, not echoed back inline (a packed target's dex can be 100 MB+), so
// fetch it by the sha the reply carries and check the bytes that came back are the repaired ones.
let backOk=false, backInfo='no sha256 in reply';
if (r.sha256) {
  const dl=await fetch(`${base}/api/dumps/download?sha=${r.sha256}`);
  const got=Buffer.from(await dl.arrayBuffer());
  backOk = dl.ok && got.length===origFileSize &&
    got.readUInt32LE(8).toString(16).padStart(8,'0')===origChecksum &&
    got.subarray(12,32).toString('hex')===origSig;
  backInfo=`GET by sha -> http=${dl.status} len=${got.length} sha=${String(r.sha256).slice(0,16)}…`;
}
console.log(backInfo);
const pass = r.magicOk && r.fileSize===origFileSize && r.checksum===origChecksum && r.signature===origSig && validSelf && backOk;
console.log(`match original: fileSize=${r.fileSize===origFileSize} checksum=${r.checksum===origChecksum} sig=${r.signature===origSig} retrievableBySha=${backOk}`);
console.log(pass?'✅ v0.2 dex-repair PASS (corrupted header restored to match real dex byte-for-byte, and the repaired artifact is fetchable by sha)':'❌ v0.2 dex-repair FAIL');
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
rm -f "$TMP"
verify_gate "v0.2 dex-repair (corrupted header restored to match real dex byte-for-byte)" 0 && exit 0 || exit 1

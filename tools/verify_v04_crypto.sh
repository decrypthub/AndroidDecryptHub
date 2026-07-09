#!/usr/bin/env bash
# v0.4 dynamic crypto channel (THE #1 selling point): plaintext-boundary capture.
# Installs a GOT hook on BoringSSL EVP_CipherUpdate in libjavacrypto (Conscrypt),
# triggers the sandbox's AES/CBC via JNI reflection, asserts the wrapper captured
# the known plaintext "IDH_CRYPTO_PLAINTEXT_v1" (i.e. we read it BEFORE encryption),
# and the target survived (trampoline-through worked). Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
SERIAL="${IDH_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"
EXPECT="IDH_CRYPTO_PLAINTEXT_v1"

set +e
OUT="$(node - "$HTTP" "$EXPECT" <<'EOF'
const [http, expect]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/crypto/hook_test?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`replaced=${r.replaced} triggered=${r.triggered} captures=${r.count}`);
(r.captures||[]).forEach(c=>console.log(`  ${c.func} inl=${c.inl} ascii="${c.ascii}"`));
const got = (r.captures||[]).some(c=>c.ascii && c.ascii.includes(expect));
const pass = r.ok && r.replaced>=1 && r.triggered===true && got;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
ALIVE=$(adb -s "$SERIAL" shell pidof com.idh.sandbox 2>/dev/null | tr -d '\r ')
echo "sandbox alive after hook: ${ALIVE:-NO}"
if echo "$OUT" | grep -q 'RESULT:PASS' && [ -n "$ALIVE" ]; then
  echo "✅ v0.4 dynamic crypto PASS — plaintext captured at EVP boundary, trampoline OK"; exit 0
else
  echo "❌ v0.4 dynamic crypto FAIL"; exit 1
fi

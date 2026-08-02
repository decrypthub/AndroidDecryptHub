#!/usr/bin/env bash
# v1.6 One-glance crypto identification (device, axis 1 通用性). Asserts the identify
# report turns raw captures into a plain-language algorithm inventory spanning symmetric +
# ASYMMETRIC(RSA) + digest + HMAC, with keys bound — so a non-expert can read off what the
# app uses. Also checks the MCP crypto_identify tool returns the same. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
sleep 24   # let the live driver rotate through the full menu (incl RSA)

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const id=await (await fetch(`${base}/api/crypto/identify`)).json();
console.log('summary:', id.summary);
const f=id.families;
console.log(`families: sym=${f.symmetric} asym=${f.asymmetric} digest=${f.digest} hmac=${f.hmac} tls=${f.tls}`);
const names=id.algorithms.map(a=>a.algo);
const hasRSA=names.some(n=>/RSA/.test(n)), hasAES=names.some(n=>/AES/.test(n)), hasSHA=names.some(n=>/SHA/.test(n)), hasHmac=names.some(n=>/Hmac/i.test(n));
const withKey=id.algorithms.filter(a=>a.keyHex).length;
console.log(`algos=${names.length} hasRSA=${hasRSA} hasAES=${hasAES} hasSHA=${hasSHA} hasHmac=${hasHmac} withKey=${withKey}`);
// MCP tool returns the same shape
const mcp=await (await fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'crypto_identify',arguments:{}}})})).json();
const mcpOk=!!(mcp.result&&mcp.result.content&&/families|summary/.test(mcp.result.content[0].text));
console.log('mcp crypto_identify ok=',mcpOk);
const pass = f.symmetric>0 && f.asymmetric>0 && f.digest>0 && f.hmac>0
  && hasRSA && hasAES && hasSHA && hasHmac && withKey>=1 && !!id.summary && mcpOk;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT" | grep -vE "Assertion failed|async\.c"
verify_gate "v1.6 crypto identify (对称+非对称+摘要+HMAC 自动识别 · 绑定密钥 · MCP 可调)" 0 && exit 0 || exit 1

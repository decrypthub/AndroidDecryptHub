#!/usr/bin/env bash
# v1.1 Live capture surface (device). Asserts the persistent hooks auto-capture the FULL
# crypto surface exercised by the sandbox live driver — not just AES: symmetric + digest
# + HMAC all appear in /api/captures without any manual trigger, and a capture detail
# decodes the (Chinese) plaintext. Also checks DEX was auto-dumped + is downloadable.
# Exit 0 = PASS. Prereq: idhd + device + sandbox running (verify_all relaunches it).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"

# give the live driver (one op / ~2s) time to rotate through symmetric+digest+hmac
sleep 16

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const j=await (await fetch(`${base}/api/captures?limit=60`)).json();
const cats=new Set((j.captures||[]).map(c=>c.algo));
console.log('on=',j.on,'total=',j.total,'cats=',[...cats].join(' | '));
const hasSym = [...cats].some(c=>/对称/.test(c));
const hasDig = [...cats].some(c=>/摘要/.test(c));
const hasHmac= [...cats].some(c=>/HMAC/.test(c));
// detail of the last capture must carry decoded plaintext
let plain='';
const last=(j.captures||[]).slice(-1)[0];
if(last){ const d=await (await fetch(`${base}/api/captures/${last.id}`)).json(); plain=d.text||''; }
console.log('last plaintext =', JSON.stringify(plain).slice(0,60));
// DEX auto-dumped + downloadable
const dumps=await (await fetch(`${base}/api/dumps`)).json();
const dex=dumps.filter(d=>d.kind==='dex');
console.log('dex dumps =', dex.length);
let dl=false;
if(dex.length){ const r=await fetch(`${base}/api/dumps/download?sha=${dex[0].sha256}`); dl=r.ok; }
const pass = j.on===true && hasSym && hasDig && hasHmac && plain.includes('IDH_LIVE_') && dex.length>=1 && dl;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v1.1 live capture surface PASS (对称+摘要+HMAC 自动捕获 · 明文解码 · DEX 可下载)"; exit 0
else echo "❌ v1.1 live capture FAIL"; exit 1; fi

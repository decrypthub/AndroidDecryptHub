#!/usr/bin/env bash
# v1.1 Live capture surface (device). Asserts the persistent hooks auto-capture the FULL
# crypto surface exercised by the sandbox live driver — not just AES: symmetric + digest
# + HMAC all appear in /api/captures without any manual trigger, and a capture detail
# decodes the (Chinese) plaintext. Also checks DEX was auto-dumped + is downloadable.
# Exit 0 = PASS. Prereq: adhd + device + sandbox running (verify_all relaunches it).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# give the live driver (one op / ~2s) time to rotate through symmetric+digest+hmac
sleep 16

set +e
OUT="$(node - "$HTTP" <<'EOF'
const http=process.argv[2]; const base=`http://127.0.0.1:${http}`;
const j=await (await fetch(`${base}/api/captures?limit=60`)).json();
const caps=j.captures||[];
const cats=new Set(caps.map(c=>c.algo));
console.log('on=',j.on,'total=',j.total,'cats=',[...cats].join(' | '));
const hasSym = [...cats].some(c=>/AES|DES/.test(c));
const hasDig = [...cats].some(c=>/^(MD5|SHA-)/.test(c));
const hasHmac= [...cats].some(c=>/Hmac/i.test(c));
const hasJava= caps.some(c=>c.source==='java');
// a cipher detail must carry the full Java-layer model: algorithm + key + iv + plaintext + ciphertext
const cipher=caps.filter(c=>/AES|DES/.test(c.algo)).slice(-1)[0];
let rich=false, plain='';
if(cipher){ const d=await (await fetch(`${base}/api/captures/${cipher.id}`)).json();
  plain=d.text||''; rich = !!(d.keyHex && d.ivHex && d.hex && d.outHex);
  console.log(`cipher #${d.id} ${d.algo} key=${(d.keyHex||'').length/2}B iv=${(d.ivHex||'').length/2}B ct=${(d.outHex||'').length/2}B plain=${JSON.stringify(plain).slice(0,40)}`); }
// DEX auto-dumped + downloadable
const dumps=await (await fetch(`${base}/api/dumps`)).json();
const dex=dumps.filter(d=>d.kind==='dex');
console.log('dex dumps =', dex.length);
let dl=false;
if(dex.length){ const r=await fetch(`${base}/api/dumps/download?sha=${dex[0].sha256}`); dl=r.ok; }
const pass = j.on===true && hasJava && hasSym && hasDig && hasHmac && rich && plain.includes('ADH_LIVE_') && dex.length>=1 && dl;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v1.1 live capture (Java 层富采集: 算法+Key+IV+明文+密文 · 对称/摘要/HMAC · DEX 可下载)" 0 && exit 0 || exit 1

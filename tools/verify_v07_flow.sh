#!/usr/bin/env bash
# v0.7 network<->crypto correlation (取证闭环). Hooks EVP_CipherUpdate + SSL_write,
# triggers an encrypt-then-send flow, and asserts idhd correlated the captured
# plaintext (IDH_CORRELATE_v1) with the TLS request carrying its ciphertext, by
# same thread + time window. Exit 0 = PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${IDH_HTTP_PORT:-8760}"
SERIAL="${IDH_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"
TLS_PORT="${IDH_TLS_PORT:-8762}"
PT="IDH_CORRELATE_v1"

for p in $(powershell.exe -NoProfile -Command "(Get-NetTCPConnection -LocalPort $TLS_PORT -State Listen -ErrorAction SilentlyContinue).OwningProcess" 2>/dev/null | tr -d '\r'); do taskkill //F //PID "$p" >/dev/null 2>&1; done
( node "$ROOT/daemon/tls_test_server.mjs" > /tmp/idh_tls.log 2>&1 & )
sleep 2
adb -s "$SERIAL" reverse tcp:$TLS_PORT tcp:$TLS_PORT >/dev/null

set +e
OUT="$(node - "$HTTP" "$PT" <<'EOF'
const [http, pt]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.idh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/flow/watch?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`hooked=${JSON.stringify(r.hooked)} triggered=${r.triggered} result=${r.result} captures=${r.count} correlations=${(r.correlations||[]).length}`);
(r.captures||[]).forEach(c=>console.log(`  [${c.func} tid=${c.tid}] ${(c.ascii||'').slice(0,50)}`));
(r.correlations||[]).forEach(x=>console.log(`  CORR tid=${x.tid} Δ=${x.deltaMs.toFixed(1)}ms plaintext="${x.plaintext}" -> ${x.netFunc}`));
const corr=(r.correlations||[]).find(x=>x.plaintext.includes(pt) && x.netFunc==='SSL_write');
const pass = r.ok && r.triggered && r.hooked.evp>=1 && r.hooked.sslWrite>=1 && /^200:/.test(r.result||'') && !!corr;
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v0.7 network<->crypto correlation PASS (plaintext linked to its encrypted request)"; exit 0
else echo "❌ v0.7 correlation FAIL"; exit 1; fi

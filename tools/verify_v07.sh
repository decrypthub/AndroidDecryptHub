#!/usr/bin/env bash
# v0.7 network TLS-plaintext capture. Hooks Conscrypt's SSL_write/SSL_read GOT
# slots, triggers an HTTPS request (via JNI reflection) to a self-contained local
# HTTPS server over `adb reverse`, and asserts the agent captured the request
# plaintext (X-Adh-Marker) at SSL_write and the response (ADH_NET_RESPONSE_v1) at
# SSL_read — i.e. TLS plaintext read at the boundary, bypassing encryption/pinning.
# Exit 0 = PASS. Prereq: idhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
TLS_PORT="${ADH_TLS_PORT:-${IDH_TLS_PORT:-8762}}"
MARKER="ADH_NET_MARKER_v1"; RESP="ADH_NET_RESPONSE_v1"

# start a fresh local HTTPS server (kill any stale one holding the port)
for p in $(powershell.exe -NoProfile -Command "(Get-NetTCPConnection -LocalPort $TLS_PORT -State Listen -ErrorAction SilentlyContinue).OwningProcess" 2>/dev/null | tr -d '\r'); do taskkill //F //PID "$p" >/dev/null 2>&1; done
( node "$ROOT/daemon/tls_test_server.mjs" > /tmp/idh_tls.log 2>&1 & )
sleep 2
adb -s "$SERIAL" reverse tcp:$TLS_PORT tcp:$TLS_PORT >/dev/null

set +e
OUT="$(node - "$HTTP" "$MARKER" "$RESP" <<'EOF'
const [http, marker, resp]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const r=await (await fetch(`${base}/api/net/hook_test?session=${a.sessionId}`)).json();
if(r.error){console.log('ERR',r.error);console.log('RESULT:FAIL');process.exit(0);}
console.log(`hooked=${JSON.stringify(r.hooked)} triggered=${r.triggered} result=${r.result} captures=${r.count}`);
(r.captures||[]).forEach(c=>console.log(`  [${c.func} inl=${c.inl}] ${(c.ascii||'').slice(0,80)}`));
const wrote=(r.captures||[]).find(c=>c.func==='SSL_write' && c.ascii.includes(marker));
const read =(r.captures||[]).find(c=>c.func==='SSL_read'  && c.ascii.includes(resp));
const pass = r.ok && r.hooked.write>=1 && r.hooked.read>=1 && r.triggered
  && /^200:/.test(r.result||'') && !!wrote && !!read;
console.log(`request-plaintext(SSL_write) has marker: ${!!wrote}; response-plaintext(SSL_read) has marker: ${!!read}`);
console.log(pass?'RESULT:PASS':'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.7 network TLS-plaintext capture (SSL_write+SSL_read, bypasses TLS)" 1 && exit 0 || exit 1

#!/usr/bin/env bash
# v0.7 network TLS-plaintext capture. Arms the persistent capture set (SSL_write/SSL_read in
# every module that holds them), provokes an HTTPS request to a self-contained local HTTPS
# server over `adb reverse` through java_call, and asserts the agent captured the request
# plaintext (X-Adh-Marker) at SSL_write and the response (ADH_NET_RESPONSE_v1) at SSL_read —
# i.e. TLS plaintext read at the boundary, bypassing encryption/pinning.
# Exit 0 = PASS. Prereq: adhd running, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
TLS_PORT="${ADH_TLS_PORT:-8762}"
MARKER="ADH_NET_MARKER_v1"; RESP="ADH_NET_RESPONSE_v1"
CLASS="com.adh.sandbox.Network"

# start a fresh local HTTPS server (kill any stale one holding the port)
verify_kill_port "$TLS_PORT" >/dev/null   # cross-platform: the old powershell/taskkill pair was a silent no-op on Linux
( node "$ROOT/daemon/tls_test_server.mjs" > /tmp/adh_tls.log 2>&1 & )
# Wait for the LISTENER, not for a fixed 2s: node has to read the script off this SMB tree, and the
# first start after a kill was measured taking longer than that - the fixed sleep made v07 fail
# with "nothing is listening" while the very next script bound fine (2s is a guess, the listener is
# a fact).
for _ in $(seq 1 30); do [ -n "$(daemon_pid_on_port "$TLS_PORT")" ] && break; sleep 1; done
adb -s "$SERIAL" reverse tcp:$TLS_PORT tcp:$TLS_PORT >/dev/null

# Prove the FIXTURE before blaming the target. Without this a broken server or a dead tunnel shows
# up only as the app's "error:connection closed", which names neither - and a gate run where the
# app happened to talk to a leftover server would pass for the wrong reason.
if [ -z "$(daemon_pid_on_port "$TLS_PORT")" ]; then
  echo "RESULT:FAIL"
  echo "❌ TLS fixture FAIL (nothing is listening on $TLS_PORT after starting tls_test_server.mjs)"
  exit 1
fi
FIXTURE_BODY="$(curl -sk -m 5 "https://127.0.0.1:$TLS_PORT/" 2>/dev/null | tr -d '\r')"
case "$FIXTURE_BODY" in
  *ADH_NET_RESPONSE_v1*) echo "fixture: server + tunnel OK" ;;
  *) echo "RESULT:FAIL"
     echo "❌ TLS fixture FAIL (host-side GET through the tunnel returned '${FIXTURE_BODY:0:60}')"
     tail -3 /tmp/adh_tls.log 2>/dev/null | sed 's/^/   /'
     exit 1 ;;
esac

set +e
OUT="$(node - "$HTTP" "$MARKER" "$RESP" "$CLASS" <<'EOF'
const [http, marker, resp, cls]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  const on=await call('capture_start',{session:sid});
  console.log(`capture_start: ok=${on.ok} installed=${on.installed}/${on.attempted} notInstalled=[${(on.notInstalled||[]).join(',')}]`);
  if(!on.ok){ console.log('FAIL capture_start did not install the hook set'); console.log('RESULT:FAIL'); process.exit(0); }
  const invoked=await call('java_call',{session:sid,className:cls,method:'run',params:'',args:[]});
  console.log(`java_call ${cls}.run -> result="${String(invoked.result?.result ?? '').slice(0,40)}"`);
  let wrote=null, read=null, caps=[];
  for(let i=0;i<12 && !(wrote&&read);i++){
    await sleep(1000);
    const lc=await call('live_captures',{session:sid,category:'net',limit:300,includeText:true});
    caps=lc.captures||[];
    wrote=caps.find(c=>c.func==='SSL_write' && String(c.ascii||'').includes(marker));
    read =caps.find(c=>c.func==='SSL_read'  && String(c.ascii||'').includes(resp));
  }
  caps.slice(0,8).forEach(c=>console.log(`  [${c.func} inl=${c.inl}] ${String(c.ascii||'').slice(0,80)}`));
  const pass = on.ok && !!wrote && !!read;
  console.log(`request-plaintext(SSL_write) has marker: ${!!wrote}; response-plaintext(SSL_read) has marker: ${!!read}`);
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.7 network TLS-plaintext capture (SSL_write+SSL_read, bypasses TLS)" 1 && exit 0 || exit 1

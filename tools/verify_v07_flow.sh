#!/usr/bin/env bash
# v0.7 network<->crypto correlation (取证闭环). Arms the persistent capture set (EVP_CipherUpdate
# + SSL_write across every module that holds them), provokes an encrypt-then-send flow through
# java_call, and asserts the DAEMON joined the captured plaintext (ADH_CORRELATE_v1) to the TLS
# request carrying its ciphertext by same-thread + time-window (daemon/src/flow.ts).
# The caveat the tool returns is the point: this is co-occurrence, not a content-hash proof. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
TLS_PORT="${ADH_TLS_PORT:-8762}"
PT="ADH_CORRELATE_v1"
CLASS="com.adh.sandbox.CorrelatedFlow"

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
OUT="$(node - "$HTTP" "$PT" "$CLASS" <<'EOF'
const [http, pt, cls]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
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
  let corr=null, seen=[];
  for(let i=0;i<12 && !corr;i++){
    await sleep(1000);
    // The join reads the daemon's live store; it can only answer once the drain loop has moved
    // the ring into it, hence the poll instead of a single shot.
    const f=await call('flow_correlate',{session:sid,sinceMs:Date.now()-120000});
    seen=f.considered||{};
    corr=(f.correlations||[]).find(x=>String(x.plaintext).includes(pt) && x.netFunc==='SSL_write');
    if(!corr && i===11) console.log(`  last: considered=${JSON.stringify(seen)} pairs=${f.totalPairs} reason=${f.reason||''}`);
  }
  if(corr) console.log(`  CORR tid=${corr.tid} Δ=${corr.deltaMs.toFixed(1)}ms plaintext="${corr.plaintext}" -> ${corr.netFunc}`);
  console.log(`considered=${JSON.stringify(seen)} caveat=${corr? 'present' : 'n/a'}`);
  const pass = on.ok && !!corr;
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.7 network<->crypto correlation (plaintext linked to its encrypted request)" 1 && exit 0 || exit 1

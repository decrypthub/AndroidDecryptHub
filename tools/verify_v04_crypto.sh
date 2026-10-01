#!/usr/bin/env bash
# v0.4 dynamic crypto channel (THE #1 selling point): plaintext-boundary capture.
# Arms the PERSISTENT capture set (MCP capture_start — the module-agnostic path the agent
# actually ships: no hardcoded target module, no hardcoded trigger method), provokes the
# target's AES/CBC workload through java_call {className, method} with the class coming from
# THIS script, and asserts the live store holds the known plaintext "ADH_CRYPTO_PLAINTEXT_v1"
# (i.e. we read it BEFORE encryption). The target must survive (trampoline-through worked).
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
EXPECT="ADH_CRYPTO_PLAINTEXT_v1"
CLASS="com.adh.sandbox.JavaCrypto"

set +e
OUT="$(node - "$HTTP" "$EXPECT" "$CLASS" <<'EOF'
const [http, expect, cls]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  // 1) arm the persistent hooks. ok is the daemon's VERDICT (installed>0, and no missing symbol
  //    when the crypto module is left empty = "scan every file-backed module").
  const on=await call('capture_start',{session:sid});
  console.log(`capture_start: ok=${on.ok} installed=${on.installed}/${on.attempted} notInstalled=[${(on.notInstalled||[]).join(',')}] partial=${on.partial}`);
  if(!on.ok){ console.log('FAIL capture_start did not install the hook set'); console.log('RESULT:FAIL'); process.exit(0); }
  // 2) provoke the workload: the class and method come from this script, not from the agent.
  const before=(await call('live_captures',{session:sid,category:'crypto'})).total||0;
  const invoked=await call('java_call',{session:sid,className:cls,method:'run',params:'',args:[]});
  console.log(`java_call ${cls}.run -> ok=${invoked.ok!==false}`);
  // 3) the drain loop pushes the ring into the store; give it a few ticks, then look.
  let hit=null;
  for(let i=0;i<10 && !hit;i++){
    await sleep(1000);
    const caps=await call('live_captures',{session:sid,category:'crypto',limit:200,includeText:true});
    hit=(caps.captures||[]).find(c=>String(c.ascii||'').includes(expect));
  }
  if(hit) console.log(`captured ${hit.func} algo=${hit.algo} inl=${hit.inl} ascii="${(hit.ascii||'').slice(0,60)}"`);
  const pass = on.ok && !!hit;
  console.log(`captures before trigger=${before}`);
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v0.4 dynamic crypto — plaintext captured at EVP boundary, trampoline OK" 1 && exit 0 || exit 1

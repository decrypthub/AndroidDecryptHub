#!/usr/bin/env bash
# v2.2 WS-A native inline hook acceptance. The sandbox JNI bridge calls the target function
# directly inside libadhdetect.so, so there is no imported GOT slot to replace: Dobby must patch
# the function ENTRY, keep the original trampoline working, and stay stable across calls.
#
# Rewritten onto the tool-level path (2026-10-01): the one-shot inline_crypto_test op is gone.
# native_hook mode=inline installs the same thing from the caller's module+symbol, the workload is
# provoked through java_call, and the evidence is the hook's own hit counters plus the target's
# return value (which proves the trampoline still runs the original body).
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
MODULE="libadhdetect.so"; SYMBOL="adh_static_EVP_CipherUpdate"
CLASS="com.adh.sandbox.Detection"; METHOD="staticCrypto"

set +e
OUT="$(node - "$HTTP" "$MODULE" "$SYMBOL" "$CLASS" "$METHOD" <<'EOF'
const [http, mod, sym, cls, meth]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  // 1) install at the function entry (address-based, no GOT slot involved)
  const h=await call('native_hook',{session:sid,action:'hook',mode:'inline',module:mod,symbol:sym,confirm:true});
  const hookId=h.hookId;
  console.log(`native_hook inline: ok=${h.ok} hookId=${hookId} error=${JSON.stringify(h.error??null)}`);
  if(!h.ok || !hookId){ console.log('FAIL inline hook did not install'); console.log('RESULT:FAIL'); process.exit(0); }

  // 2) trigger through the target's own path; the return value proves the trampoline ran the
  //    original body (staticCrypto returns 1). status nests its list under status.hooks and keys
  //    the entries by `id`.
  const r1=await call('java_call',{session:sid,className:cls,method:meth,params:'',args:[]});
  const entry=async()=>{const st=await call('native_hook',{session:sid,action:'status'}); return ((st.status?.hooks)||[]).find(x=>x.id===hookId)||{};};
  await sleep(600);
  const e1=await entry();
  const s1={hits:Number(e1.hits??0), verdict:e1.verdict, mode:e1.mode};
  console.log(`trigger #1 result=${JSON.stringify(r1.result?.result)} -> hits=${s1.hits} verdict=${s1.verdict} mode=${s1.mode}`);

  // 3) a second call must increment by exactly one (no double-count, no lost trampoline)
  const r2=await call('java_call',{session:sid,className:cls,method:meth,params:'',args:[]});
  await sleep(600);
  const s2={hits:Number((await entry()).hits??0)};
  console.log(`trigger #2 result=${JSON.stringify(r2.result?.result)} -> hits=${s2.hits}`);

  // 4) installing the SAME module+symbol again must fail loud rather than silently double-patch
  const dup=await call('native_hook',{session:sid,action:'hook',mode:'inline',module:mod,symbol:sym,confirm:true});
  console.log(`re-hook same target: ok=${dup.ok} error=${JSON.stringify(dup.error??null)}`);

  const pass = h.ok===true && r1.result?.result==="1" && r2.result?.result==="1"
    && s1.hits===1 && s2.hits===2 && String(s1.verdict)==='fired'
    && dup.ok!==true && /already hooked/i.test(String(dup.error??''));
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
  // SOFT unhook: this one leaves the target re-hookable in the same process. A hard unhook marks
  // the backend state stale and the agent then refuses to re-hook that target until the process
  // restarts ("target was hard-unhooked earlier in this process") - correct fail-loud behaviour,
  // but it would make every later script in the same run fail for the wrong reason.
  await call('native_hook',{session:sid,action:'unhook',hookId}).catch(()=>{});
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_sandbox_alive
verify_gate "v2.2 native inline hook (direct entry, original trampoline, exact hit counting, duplicate refused)" 1 && exit 0 || exit 1

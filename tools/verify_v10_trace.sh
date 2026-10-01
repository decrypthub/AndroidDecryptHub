#!/usr/bin/env bash
# v1.0 generic native function tracer (I.2 function-level). Traces calls to an arbitrary native
# symbol (args + tid + ts) through the hook engine, and resolves an argument pointer back into
# target memory. Traces access() in libadhdetect during Detection.run() -> expects one call per
# invocation on a single thread, with the su-path checks readable at x0.
#
# Rewritten onto the tool-level path (2026-10-01): the one-shot trace_run op is gone (it also
# hardcoded the target's run() trigger). native_hook mode=got installs the same slot from the
# caller's module+symbol, java_call provokes the workload, and the events come out of the live
# capture stream — where the argument is a REGISTER, so the string is read back with memory_read.
# Exit 0 = PASS. Prereq: adhd, device, sandbox running.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
MODULE="libadhdetect.so"; SYMBOL="access"; CLASS="com.adh.sandbox.Detection"

set +e
OUT="$(node - "$HTTP" "$MODULE" "$SYMBOL" "$CLASS" <<'EOF'
const [http, mod, sym, cls]=process.argv.slice(2); const base=`http://127.0.0.1:${http}`;
const sleep=(ms)=>new Promise(r=>setTimeout(r,ms));
const rpc=(m,p)=>fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:Math.floor(Math.random()*1e6),method:m,params:p})}).then(r=>r.json());
const call=async(name,args)=>{const r=await rpc('tools/call',{name,arguments:args}); if(r.error) throw new Error(`${name}: ${r.error.message}`); const t=r.result?.content?.[0]?.text ?? 'null'; try { return JSON.parse(t); } catch { return t; }};
const agents=await (await fetch(`${base}/api/agents`)).json();
const a=agents.filter(x=>x.package==='com.adh.sandbox'&&x.online).sort((x,y)=>y.connectedAt-x.connectedAt)[0];
if(!a){console.log('NO_AGENT');console.log('RESULT:FAIL');process.exit(0);}
const sid=a.sessionId;
try{
  const h=await call('native_hook',{session:sid,action:'hook',mode:'got',module:mod,symbol:sym,confirm:true});
  const hookId=h.hookId;
  console.log(`native_hook got ${mod}!${sym}: ok=${h.ok} hookId=${hookId}`);
  if(!h.ok || !hookId){ console.log('FAIL GOT hook did not install'); console.log('RESULT:FAIL'); process.exit(0); }
  // native_hook action:status nests its list under status.hooks and keys the entries by `id`.
  const entry=async()=>{const st=await call('native_hook',{session:sid,action:'status'}); return ((st.status?.hooks)||[]).find(x=>x.id===hookId)||null;};

  const invoked=await call('java_call',{session:sid,className:cls,method:'run',params:'',args:[]});
  console.log(`java_call ${cls}.run -> ${JSON.stringify(invoked.result?.result ?? invoked.error ?? null)}`);
  const t0=Date.now();   // events must be MINE: hook ids are reused after a target restart, so an
                         // old NATIVE_HOOK record with the same id would be read at a dead address.

  // The event payload is the register snapshot; the argument STRING lives at x0, so read it back
  // (that read is itself part of the assertion: the tracer's arg is a real, resolvable pointer).
  let evs=[];
  for(let i=0;i<10 && evs.length<1;i++){
    await sleep(1000);
    const lc=await call('live_captures',{session:sid,limit:400,includeText:true});
    evs=(lc.captures||[]).filter(c=>c.func==='NATIVE_HOOK' && Number(c.ts)>=t0).map(c=>{
      let j=null; try { j=JSON.parse(String(c.ascii||'')); } catch {}
      return {rec:c, j};
    }).filter(e=>e.j && Number(e.j.hookId)===Number(hookId));
  }
  const resolved=[];
  for(const e of evs.slice(0,8)){
    const x0=e.j.x0;
    if(!x0 || x0==='0x0') continue;
    const m=await call('memory_read',{session:sid,addr:x0,size:64});
    const text=Buffer.from(String(m.b64??''),'base64').toString('latin1').replace(/\0.*$/,'');
    resolved.push({x0, tid:e.rec.tid, text});
    console.log(`  access("${text}") x0=${x0} tid=${e.rec.tid}`);
  }
  const tids=new Set(evs.map(e=>e.rec.tid));
  const argsOk=evs.length>0 && evs.every(e=>e.j.x0 && e.rec.tid);
  const suPaths=resolved.filter(r=>/su$/.test(r.text)).length;
  // The target checks exactly two su paths (the same expectation the pre-2026-10-01 op encoded).
  const twoCalls=evs.length===2, oneThread=tids.size===1;
  const st=await entry();
  console.log(`events=${evs.length} tids=${tids.size} x0-resolved=${resolved.length} suPaths=${suPaths} hits=${st?.hits} verdict=${st?.verdict}`);

  const unh=await call('native_hook',{session:sid,action:'unhook',hookId});
  const gone=!(await entry());
  console.log(`soft unhook ok=${unh.ok} entry-gone=${gone} (re-hookable)`);

  const pass = h.ok===true && twoCalls && oneThread && argsOk && suPaths===2
    && Number(st?.hits)===2 && String(st?.verdict)==='fired' && gone;
  console.log(pass?'RESULT:PASS':'RESULT:FAIL');
}catch(e){ console.log('ERR',e.message); console.log('RESULT:FAIL'); }
EOF
)"
echo "$OUT"
verify_gate "v1.0 native function tracer (access() args + tid + ts captured, argument read back)" 0 && exit 0 || exit 1

#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_unit_pass 'native observation/ABI support' native_hook_controls.test.ts 8 || exit 1
verify_unit_pass 'MCP native fields and trace closure reachability' mcp_native_reachability.test.ts 4 || exit 1
cd "$ROOT"
OUT="$(node --input-type=module - "$BASE" "$SERIAL" "$ROOT" "${ADH_TEST_PACKAGE:-com.adh.sandbox}" <<'EOF'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
const [base,serial,repo,testPackage]=process.argv.slice(2), fixture=join(repo,'agent/build/libadh_native_controls.so');
if(!serial||!existsSync(fixture)){console.log('RESULT:SKIP device or built native fixture missing');process.exit(0);}
const adb=args=>{const r=spawnSync('adb',['-s',serial,...args],{encoding:'utf8',timeout:20000,windowsHide:true});if(r.error||r.status!==0)throw new Error(String(r.error??r.stderr));return r.stdout.trim();};
if(adb(['shell','su','-c','id -u'])!=='0'){console.log('RESULT:SKIP rooted test device required');process.exit(0);}
const all=await(await fetch(`${base}/api/agents`)).json(), target=all.filter(a=>a.online&&a.package===testPackage).sort((a,b)=>b.connectedAt-a.connectedAt)[0];
if(!target){console.log('RESULT:SKIP no online sandbox');process.exit(0);}
const call=async(name,args={},allowFailure=false)=>{
 const r=await(await fetch(`${base}/mcp`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:{session:target.sessionId,...args}}})})).json();
 if(r.error)throw new Error(JSON.stringify(r.error));const text=r.result?.content?.find(c=>c.type==='text')?.text;
 if(r.result?.isError)throw new Error(text);const value=JSON.parse(text);if(value.ok===false&&!allowFailure)throw new Error(JSON.stringify(value));return value;
};
const nativeHarness=testPackage==='com.adh.nativefixture';
assert.ok(nativeHarness||testPackage==='com.adh.sandbox','only dedicated sandbox/nativefixture packages accepted');
const libdir=nativeHarness?'/data/local/tmp':adb(['shell','su','-c','ls -d /data/app/*/com.adh.sandbox*/lib/arm64']);
if(!nativeHarness)assert.match(libdir,/^\/data\/app\/[^\r\n]+\/com\.adh\.sandbox[^\r\n]*\/lib\/arm64$/);
const token=randomUUID(),staged=`/data/local/tmp/adh-native-${token}.so`,lib=`${libdir}/libadh_native_controls_${token.replaceAll('-','')}.so`,module=lib.split('/').at(-1);
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
const active=new Set();
const native=async(symbol,args=[])=>call('native_call',{module,symbol,args,confirm:true});
const arm=async(symbol,opts={})=>{const r=await call('native_hook',{action:'hook',mode:'inline',module,symbol,...opts});active.add(r.hookId);return r.hookId;};
const stop=async(id)=>{const r=await call('native_hook',{action:'unhook',hookId:id},true);if(r.ok)active.delete(id);return r;};
const bits=r=>r.fpResultDouble??Number.NaN;
try{
 adb(['push',fixture,staged]);
 const stage=`cp ${q(staged)} ${q(lib)} && chmod 755 ${q(lib)}${nativeHarness?'':` && chcon u:object_r:apk_data_file:s0 ${q(lib)}`}`;
 adb(['shell',nativeHarness?stage:`su -c ${q(stage)}`]);
 await call('load_library',{path:lib});
 const args=[1,2,3,4,5,6,7,8].map(x=>`d:${x}`);
 assert.equal(bits(await native('adh_fp8_target',args)),204);
 let id=await arm('adh_fp8_target',{maxEvents:2});
 assert.equal(bits(await native('adh_fp8_target',args)),204,'ordinary hook corrupted d7');
 assert.equal((await stop(id)).ok,true);
 // Plain and after stubs are intentionally different shapes; a second unique symbol avoids
 // the old soft-unhook stub shape, whose backend cannot be switched without touching Dobby.
 id=await arm('adh_pair_target',{memAfter:'x0:8'});
 assert.equal(BigInt((await native('adh_pair_probe')).result),30n,'memAfter clobbered x1 aggregate return');
 assert.equal((await stop(id)).ok,true);
 // An after-stub at a fresh exported alias exercises all eight input FP registers explicitly.
 id=await arm('adh_fp8_after_target',{memAfter:'x0:8',maxEvents:2});
 assert.equal(bits(await native('adh_fp8_after_target',args)),204,'after hook corrupted d7');
 await call('native_look',{action:'read',hookId:id});
 const rows=(await call('live_captures',{hookId:id,includeText:true,encoding:'b64',limit:12})).captures;
 const parsed=rows.map(c=>({func:c.func,...JSON.parse(Buffer.from(c.b64,'base64').toString())}));
 assert.ok(parsed.some(e=>e.func==='NATIVE_HOOK_MEM'&&e.phase==='after'&&e.seq>0));
 assert.equal((await stop(id)).ok,true);
 id=await arm('adh_control_target',{maxEvents:2,sampleEvery:3});
 assert.equal(BigInt((await native('adh_control_probe',['8'])).result),328n);
 let h=(await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===id);
 assert.deepEqual([h.hits,h.selected,h.sampledOut,h.limited,h.emitted],[8,8,5,1,2]);
 assert.equal((await stop(id)).ok,true);
 id=await arm('adh_control_target',{maxEvents:1,sampleEvery:2,skipOriginal:true,returnValue:'0x63'});
 assert.equal(BigInt((await native('adh_control_probe',['8'])).result),792n,'sampling/quota suppressed replacements');
 h=(await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===id);
 assert.deepEqual([h.hits,h.selected,h.sampledOut,h.limited,h.emitted],[8,8,4,3,1]);
 assert.equal((await stop(id)).ok,true);
 for(const select of [{tid:1},{returnAddress:'0x1'}]){
  id=await arm('adh_control_target',{...select,skipOriginal:true,returnValue:'0x63'});
  assert.equal(BigInt((await native('adh_control_probe',['8'])).result),328n,'filter mismatch changed original');
  h=(await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===id);
  assert.deepEqual([h.hits,h.filtered,h.selected,h.emitted],[8,8,0,0]);
  assert.equal((await stop(id)).ok,true);
 }
 id=await arm('adh_control_target',{throttleMs:60000,skipOriginal:true,returnValue:'0x63'});
 assert.equal(BigInt((await native('adh_control_probe',['8'])).result),792n,'throttle suppressed replacements');
 h=(await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===id);
 assert.deepEqual([h.hits,h.throttled,h.emitted],[8,7,1]);
 assert.equal((await stop(id)).ok,true);
 const hook=await call('native_hook',{action:'hook',mode:'sites',module,symbol:'adh_slow_target',sites:4});id=hook.hookId;active.add(id);
 assert.equal(BigInt((await native('adh_start_slow',['6000'])).result),0n);
 let state=0;for(let i=0;i<20;i++){state=Number((await native('adh_slow_state')).result);if(state===1)break;await new Promise(r=>setTimeout(r,20));}
 assert.equal(state,1,'background fixture did not enter slow original');
 const began=Date.now(),pending=await stop(id),elapsed=Date.now()-began;
 assert.equal(pending.ok,false,'busy thunk was reported unhooked');assert.match(pending.error,/not-unhooked/);
 assert.ok(elapsed>=1400&&elapsed<3500,`unhook wait not bounded: ${elapsed}ms`);
 const retained=pending.status.inactive.find(h=>h.id===id);assert.equal(retained.state,'unhook-pending');assert.ok(retained.inFlight>0);
 for(let i=0;i<80;i++){state=Number((await native('adh_slow_state')).result);if(state===2)break;await new Promise(r=>setTimeout(r,100));}
 assert.equal(state,2,'background fixture did not finish');
 const retired=await stop(id);assert.equal(retired.ok,true,'retry did not retire restored thunk');
 const entry=retired.status.inactive.find(h=>h.id===id);
 assert.equal(entry.state,'retired');assert.equal(entry.patchesRestored,true);assert.equal(entry.resourcesReclaimed,false);assert.ok(entry.retiredPages>0);
 const oldId=id,oldThunk=hook.status.hooks.find(h=>h.id===id).sites[0].thunk;
 await call('native_look',{action:'read',hookId:oldId});
 const oldCount=(await call('live_captures',{hookId:oldId,limit:128})).total;
 const fresh=await call('native_hook',{action:'hook',mode:'sites',module,symbol:'adh_retire_target_0',sites:4});id=fresh.hookId;active.add(id);
 assert.notEqual(id,oldId);
 assert.equal(BigInt((await call('native_call',{addr:oldThunk,args:['0'],confirm:true})).result),84n,'late old thunk called the wrong target');
 let freshStatus=(await call('native_hook',{action:'status'})).status;
 assert.equal(freshStatus.hooks.find(h=>h.id===id).hits,0,'late old thunk mixed a new hook generation');
 await call('native_look',{action:'read',hookId:oldId});
 assert.equal((await call('live_captures',{hookId:oldId,limit:128})).total,oldCount,'retired thunk emitted a fresh event');
 assert.equal(BigInt((await native('adh_retire_probe_0')).result),20n);
 assert.equal((await stop(id)).ok,true);
 const lateChecks=[{id:oldId,addr:oldThunk,arg:'0',expected:84n}];
 const got=await call('native_hook',{action:'hook',mode:'got',module,symbol:'adh_retire_target_14'});id=got.hookId;active.add(id);
 assert.equal(BigInt((await native('adh_retire_probe_14')).result),34n);
 const gotStub=got.status.hooks.find(h=>h.id===id).replacement,gotId=id;
 const gotRetired=await stop(id);assert.equal(gotRetired.ok,true);assert.equal(gotRetired.status.inactive.find(h=>h.id===gotId).state,'retired');
 lateChecks.push({id:gotId,addr:gotStub,arg:'20',expected:34n});
 const hard=await arm('adh_retire_target_15'),hardInfo=(await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===hard);
 assert.equal(BigInt((await native('adh_retire_target_15',['20'])).result),35n);
 const hardRetired=await call('native_hook',{action:'unhook',hookId:hard,hard:true});active.delete(hard);
 assert.equal(hardRetired.status.inactive.find(h=>h.id===hard).state,'retired');
 lateChecks.push({id:hard,addr:hardInfo.replacement,arg:'20',expected:35n});
 assert.equal(BigInt((await native('adh_pointer_probe',['20'])).result),353n);
 const ptr=await call('native_hook',{action:'hook',mode:'vtable',module,symbol:'adh_pointer_target'});id=ptr.hookId;active.add(id);
 const ptrInfo=ptr.status.hooks.find(h=>h.id===id);
 assert.ok(ptrInfo.slots.length>0);assert.ok(ptrInfo.slots.some(s=>s.kind==='data'&&!String(s.perms).includes('w')));
 assert.equal(BigInt((await native('adh_pointer_probe',['20'])).result),353n);
 assert.ok((await call('native_hook',{action:'status'})).status.hooks.find(h=>h.id===id).hits>0,'indirect pointer-slot call did not enter the hook');
 const ptrRetired=await stop(id),ptrEntry=ptrRetired.status.inactive.find(h=>h.id===id);
 assert.equal(ptrRetired.ok,true);assert.equal(ptrEntry.state,'retired');assert.equal(ptrEntry.patchesRestored,true);
 assert.equal(ptrEntry.resourcesReclaimed,false);assert.equal(ptrEntry.retiredPages,1);
 assert.equal(BigInt((await native('adh_pointer_probe',['20'])).result),353n,'pointer slot was not restored');
 lateChecks.push({id,addr:ptrInfo.slots[0].thunk,arg:'20',expected:353n});
 for(const late of lateChecks){
  await call('native_look',{action:'read',hookId:late.id});
  late.events=(await call('live_captures',{hookId:late.id,limit:128})).total;
 }
 // Known absent symbols never publish a thunk and therefore must not burn a physical context.
 const beforeFailure=(await call('native_hook',{action:'status'})).status.slots.free;
 for(let n=0;n<3;n++)assert.equal((await call('native_hook',{action:'hook',mode:'sites',module,symbol:'adh_no_such_symbol'},true)).ok,false);
 assert.equal((await call('native_hook',{action:'status'})).status.slots.free,beforeFailure);
 // Run last: retirement intentionally consumes the fixed context budget for this process.
 let final=(await call('native_hook',{action:'status'})).status;
 for(let n=1;final.slots.free>0;n++){
  assert.ok(n<16,'fixture needs more distinct retirement targets');
  const installed=await call('native_hook',{action:'hook',mode:'sites',module,symbol:`adh_retire_target_${n}`,sites:4});id=installed.hookId;active.add(id);
  assert.equal(BigInt((await native(`adh_retire_probe_${n}`)).result),BigInt(20+n));
  const done=await stop(id);assert.equal(done.ok,true);assert.equal(done.status.slots.free,final.slots.free-1);
  final=done.status;
 }
 const exhausted=await call('native_hook',{action:'hook',mode:'sites',module,symbol:'adh_retire_target_15'},true);
 assert.equal(exhausted.ok,false);assert.match(exhausted.error,/slot budget exhausted.*new target process/);
 assert.equal(final.slots.used,16);assert.ok(final.slots.retired>0);assert.ok(final.retiredBytes<=16*8*4096);
 assert.equal(BigInt((await call('native_call',{addr:oldThunk,args:['0'],confirm:true})).result),84n);
 for(const late of lateChecks){
  assert.equal(BigInt((await call('native_call',{addr:late.addr,args:[late.arg],confirm:true})).result),late.expected);
  await call('native_look',{action:'read',hookId:late.id});
  assert.equal((await call('live_captures',{hookId:late.id,limit:128})).total,late.events,'retired context emitted or mixed events');
 }
 console.log(JSON.stringify({fp8:204,pair:30,pointerSlot:353,hotUnhookMs:elapsed,lateThunk:true,noGenerationMix:true,slots:final.slots,retiredBytes:final.retiredBytes}));console.log('RESULT:PASS');
}finally{
 for(const id of active)await stop(id).catch(e=>console.error('cleanup:',e.message));
 const cleanup=`rm -f ${q(staged)} ${q(lib)}`;
 adb(['shell',nativeHarness?cleanup:`su -c ${q(cleanup)}`]);
}
EOF
)"
echo "$OUT"
verify_gate 'native ABI preservation and bounded busy-thunk unhook' 0

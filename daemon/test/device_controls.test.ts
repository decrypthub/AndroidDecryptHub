import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {Operations,type Principal} from '../src/operations.ts';
import {trackedEffect} from '../src/execution_context.ts';

const ai:Principal={role:'ai',id:'fixture',source:'test'},operator:Principal={role:'operator',id:'human',source:'test'};
const first='00000000-0000-4000-8000-000000000001',second='00000000-0000-4000-8000-000000000002';
test('verified devices run independently; unassociated legacy targets obey human and unknown-effect fences',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-p3-control-')),engine=new Operations(root);
  const meta=(r:string)=>{const s=engine.snapshot(r);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
  const a={name:'devices',mode:'write' as const,deviceId:first},b={...a,deviceId:second},legacy={name:'legacy',mode:'write' as const,session:'old'};
  try{
    let release!:()=>void,entered=false,ran=false;
    const gate=new Promise<void>(r=>release=r);
    const pending=engine.execute(a,{},ai,meta('device:'+first),async()=>trackedEffect(async()=>{entered=true;await gate;return {ok:true};}));
    while(!entered)await new Promise(r=>setTimeout(r,2));
    const other=await engine.execute(b,{},ai,meta('device:'+second),async()=>{ran=true;return {ok:true};});assert.equal(other.state,'succeeded');assert.ok(ran);
    engine.control('takeover','target:old',operator,meta('target:old'));
    assert.throws(()=>engine.submit(b,{},ai,meta('device:'+second),async()=>({ok:true})),/operator-held/);
    engine.control('release','target:old',operator,meta('target:old'));release();await pending;
    const unknown=await engine.execute(a,{},ai,meta('device:'+first),async()=>trackedEffect(async()=>{throw Error('synthetic lost reply');}));assert.equal(unknown.state,'unknown');
    const blocked=await engine.execute(legacy,{},ai,meta('target:old'),async()=>assert.fail('legacy association unverified'));assert.equal(blocked.error.code,'UNKNOWN_EXECUTION');
    assert.equal((await engine.execute(b,{},ai,meta('device:'+second),async()=>({ok:true}))).state,'succeeded');
    engine.control('resolve','device:'+first,operator,meta('device:'+first),true);
    assert.equal((await engine.execute(legacy,{},ai,meta('target:old'),async()=>({ok:true}))).state,'succeeded');
  }finally{engine.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p3-control-')));rmSync(root,{recursive:true,force:true});}
});

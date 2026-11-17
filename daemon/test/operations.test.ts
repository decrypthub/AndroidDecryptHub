import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
import { join } from 'node:path';
import { Operations, type Principal } from '../src/operations.ts';
import { trackedEffect, checkpoint, localEffect } from '../src/execution_context.ts';
import { TaskStore } from '../src/task_store.ts';
import { describeTool, describeHttp } from '../src/operation_registry.ts';

const ai:Principal={role:'ai',id:'fixture-ai',source:'test'};
const human:Principal={role:'operator',id:'fixture-human',source:'test'};
const spec={name:'memory_write',mode:'write' as const,session:'one'};
function fixture() {
  const root=mkdtempSync(join(tmpdir(),'adh-p1-'));
  const engine=new Operations(root);
  return {engine,root,close(){engine.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p1-')));rmSync(root,{recursive:true,force:true});}};
}
const metadata=(engine:Operations,resource='target:one')=>{
  const s=engine.snapshot(resource);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};
};
const delay=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function until(fn:()=>boolean) {for(let i=0;i<200&&!fn();i++)await delay(2);assert.ok(fn(),'condition not observed');}

test('read effect classification is exact per tool and unclassified actions fail closed',()=>{
  for(const action of ['diff','stability'])assert.equal(describeTool('oracle',{action}).mode,'write');
  for(const name of ['native_hook_all','syscall_watch'])for(const action of ['status','list','plan'])assert.equal(describeTool(name,{action}).mode,'write');
  assert.equal(describeTool('oracle',{action:'list'}).mode,'read');
  assert.equal(describeTool('java_trace',{action:'digest'}).mode,'read');
  assert.equal(describeHttp('/api/native/future-mutation','POST',{}).mode,'write');
  assert.equal(describeHttp('/api/native/analyze','POST',{}).mode,'analysis');
  assert.equal(describeHttp('/api/data/clear','POST',{}).global,true,'legacy Host cleanup must share the Host control domain');
});

test('writes require current state; idempotency never dispatches a target twice',async()=>{
  const f=fixture();try{
    let hits=0;
    assert.throws(()=>f.engine.submit(spec,{},ai,{},async()=>{}),/snapshot/);
    const meta={...metadata(f.engine),idempotencyKey:'one'};
    const result=await f.engine.execute(spec,{hex:'41'},ai,meta,async()=>trackedEffect(async()=>{hits++;return {ok:true};}));
    assert.equal(result.state,'succeeded');assert.equal(hits,1);
    assert.equal((await f.engine.execute(spec,{hex:'41'},ai,meta,async()=>{hits++;})).id,result.id);
    assert.equal(hits,1);
    assert.throws(()=>f.engine.submit(spec,{hex:'42'},ai,meta,async()=>{}),/different arguments/);
    assert.throws(()=>f.engine.submit(spec,{},ai,{...meta,idempotencyKey:'old'},async()=>{}),/changed/);
  }finally{f.close();}
});

test('operator takeover fences queued AI work and later effects of a running recipe',async()=>{
  const f=fixture();try{
    let release!:()=>void,entered=false,oldWrites=0;
    const gate=new Promise<void>(r=>release=r);
    const first=f.engine.execute(spec,{},ai,metadata(f.engine),async()=>{
      await trackedEffect(async()=>{entered=true;await gate;return true;});
      checkpoint();oldWrites++;return {ok:true};
    });
    await until(()=>entered);
    const queued=f.engine.execute(spec,{next:true},ai,metadata(f.engine),async()=>{oldWrites++;return {ok:true};});
    const s=metadata(f.engine);
    f.engine.control('takeover','target:one',human,s);
    let humanWrites=0;
    const manual=f.engine.execute(spec,{human:true},human,metadata(f.engine),async()=>trackedEffect(async()=>{humanWrites++;return {ok:true};}));
    release();
    assert.equal((await first).state,'failed');
    assert.equal((await queued).error.code,'STALE_CONTROL');
    assert.equal((await manual).state,'succeeded');assert.equal(oldWrites,0);assert.equal(humanWrites,1);
    assert.throws(()=>f.engine.submit(spec,{},ai,metadata(f.engine),async()=>{}),/operator holds/);
    f.engine.control('release','target:one',human,metadata(f.engine));
    assert.equal((await f.engine.execute(spec,{},ai,metadata(f.engine),async()=>({ok:true}))).state,'succeeded');
  }finally{f.close();}
});

test('request metadata cannot forge actor, state, target or owner',async()=>{
  const f=fixture();try{
    const value=await f.engine.execute(spec,{},ai,{...metadata(f.engine),owner:'operator',state:'succeeded',resource:'host'} as any,async()=>({ok:true}));
    assert.equal(value.owner,'ai');assert.equal(value.resource,'target:one');
    assert.throws(()=>f.engine.control('takeover','target:one',ai,metadata(f.engine)),/operator credential/);
    assert.throws(()=>f.engine.snapshot('__proto__'),/invalid control resource/);
  }finally{f.close();}
});

test('queued cancellation confirms no dispatch; running cancellation remains requested until completion',async()=>{
  const f=fixture();try{
    let release!:()=>void,entered=false,hits=0;
    const gate=new Promise<void>(r=>release=r);
    const first=f.engine.submit(spec,{},ai,metadata(f.engine),async()=>trackedEffect(async()=>{entered=true;await gate;return {ok:true};}));
    await until(()=>entered);
    const queued=f.engine.submit(spec,{second:1},ai,metadata(f.engine),async()=>{hits++;return {ok:true};});
    assert.equal(f.engine.cancelOperation(queued.id,ai).state,'cancelled');
    assert.equal(f.engine.cancelOperation(first.id,ai).state,'cancel_requested');
    release();await until(()=>f.engine.getOperation(first.id).settled);
    assert.equal(f.engine.getOperation(first.id).state,'succeeded','actual completed effects are not labelled cancelled');
    assert.equal(f.engine.store.read().tasks[first.taskId].state,'completed');
    assert.equal(f.engine.getOperation(first.id).cancelRequested,true);assert.equal(hits,0);
  }finally{f.close();}
});

test('timeout records unknown, blocks retries and preserves late evidence without pretending to stop the target',async()=>{
  const f=fixture();try{
    let release!:()=>void;
    const gate=new Promise<void>(r=>release=r);
    const result=await f.engine.execute(spec,{},ai,{...metadata(f.engine),timeoutMs:1000},async()=>trackedEffect(async()=>{await gate;return {ok:true,value:'late'};}));
    assert.equal(result.state,'unknown');assert.equal(result.inFlight,1);
    assert.equal(f.engine.taskAction(result.taskId,'cancel',ai).state,'unknown','cancellation cannot turn uncertain execution into confirmed cancellation');
    assert.throws(()=>f.engine.taskAction(result.taskId,'pause',ai),/resolve unknown/);
    assert.throws(()=>f.engine.control('resolve','target:one',human,metadata(f.engine),true),/still awaiting/);
    const retry=await f.engine.execute(spec,{retry:1},ai,metadata(f.engine),async()=>assert.fail('must not replay'));
    assert.equal(retry.state,'failed');assert.equal(retry.error.code,'UNKNOWN_EXECUTION');
    release();await until(()=>f.engine.getOperation(result.id).settled);
    const observed=f.engine.getOperation(result.id,true);
    assert.equal(observed.state,'unknown');assert.equal(observed.lateResult.value,'late');
    assert.equal(observed.effects[0].state,'acknowledged');assert.ok(observed.effects[0].uncertainAt,'late acknowledgement must preserve prior uncertainty');
    f.engine.control('resolve','target:one',human,metadata(f.engine),true);
    assert.equal((await f.engine.execute(spec,{},ai,metadata(f.engine),async()=>({ok:true}))).state,'succeeded');
  }finally{f.close();}
});

test('different targets run concurrently but Host-wide changes serialize with target writes',async()=>{
  const f=fixture();try{
    let release!:()=>void,entered=false,second=false,root=false;
    const gate=new Promise<void>(r=>release=r);
    const first=f.engine.submit(spec,{},ai,metadata(f.engine),async()=>{entered=true;await gate;return {ok:true};});
    await until(()=>entered);
    const other=f.engine.submit({...spec,session:'two'},{},ai,metadata(f.engine,'target:two'),async()=>{second=true;return {ok:true};});
    await until(()=>second);
    const all=f.engine.submit({name:'settings',mode:'write',global:true},{},ai,metadata(f.engine,'host'),async()=>{root=true;return {ok:true};});
    await delay(5);assert.equal(root,false);release();await until(()=>f.engine.getOperation(all.id).settled);
    assert.equal(root,true);assert.equal(f.engine.getOperation(first.id).state,'succeeded');assert.equal(f.engine.getOperation(other.id).state,'succeeded');
  }finally{f.close();}
});

test('restart preserves completed results, cancels unsent work and quarantines in-flight effects without replay',async()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-p1-'));
  let engine=new Operations(root),release!:()=>void;
  try{
    const completed=await engine.execute({name:'offline',mode:'analysis'},{},ai,{},async()=>({ok:true,value:42}));
    const gate=new Promise<void>(r=>release=r);let entered=false;
    const running=engine.submit(spec,{},ai,metadata(engine),async()=>trackedEffect(async()=>{entered=true;await gate;return {ok:true};}));
    await until(()=>entered);
    const queued=engine.submit(spec,{queued:1},ai,metadata(engine),async()=>assert.fail('cannot replay'));
    engine.store.update(data=>{
      data.operations[running.id].host='synthetic-crashed-host';
      data.hosts['synthetic-crashed-host']={pid:2147483647,hostname:hostname(),active:true};
    });
    engine.close();engine=new Operations(root);
    assert.equal(engine.getOperation(completed.id,true).result.value,42);
    assert.equal(engine.getOperation(running.id).state,'unknown');assert.equal(engine.getOperation(queued.id).state,'cancelled');
    assert.equal(engine.snapshot('target:one').uncertain,running.id);
    engine.control('resolve','target:one',human,metadata(engine),true);
    assert.equal(engine.getOperation(running.id).state,'unknown');assert.ok(engine.getOperation(running.id).resolvedAt);
    release();await delay(5);
  }finally{engine.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p1-')));rmSync(root,{recursive:true,force:true});}
});

test('cancelling one operation leaves its named task and siblings active; partial effects stay visible',async()=>{
  const f=fixture();try{
    const task=f.engine.createTask('multi-step analysis',ai);
    let release!:()=>void,entered=false,hits=0;
    const gate=new Promise<void>(r=>release=r);
    const first=f.engine.submit(spec,{},ai,{...metadata(f.engine),taskId:task.id},async()=>{
      localEffect(()=>hits++);entered=true;await gate;checkpoint();hits++;return {ok:true};
    });
    await until(()=>entered);
    f.engine.cancelOperation(first.id,ai);release();await until(()=>f.engine.getOperation(first.id).settled);
    assert.equal(f.engine.getOperation(first.id).state,'cancelled');
    assert.equal(f.engine.getOperation(first.id).partialEffects,true);assert.equal(hits,1);
    assert.equal(f.engine.store.read().tasks[task.id].state,'active');
    const next=await f.engine.execute(spec,{next:true},ai,{...metadata(f.engine),taskId:task.id},async()=>({ok:true}));
    assert.equal(next.state,'succeeded');
    f.engine.taskAction(task.id,'pause',human);
    assert.throws(()=>f.engine.taskAction(task.id,'resume',ai),/operator paused/);
    assert.throws(()=>f.engine.taskAction(task.id,'cancel',ai),/operator paused/);
    assert.equal(f.engine.taskAction(task.id,'resume',human).state,'active');
    let manualEntered=false,manualRelease!:()=>void;
    const manualGate=new Promise<void>(r=>manualRelease=r);
    const manual=f.engine.submit(spec,{manual:true},human,{...metadata(f.engine),taskId:task.id},async()=>{manualEntered=true;await manualGate;return {ok:true};});
    await until(()=>manualEntered);
    assert.throws(()=>f.engine.taskAction(task.id,'cancel',ai),/operator work/);
    assert.throws(()=>f.engine.taskAction(task.id,'pause',ai),/operator work/);
    manualRelease();await until(()=>f.engine.getOperation(manual.id).settled);
    assert.equal(f.engine.taskAction(task.id,'complete',ai).state,'completed');
    assert.equal(f.engine.taskAction(task.id,'cancel',ai).state,'completed');
    assert.throws(()=>f.engine.taskAction(task.id,'resume',ai),/new task/);
  }finally{f.close();}
});

test('target takeover fences later Host-wide local writes even without an agent command',async()=>{
  const f=fixture();try{
    let release!:()=>void,entered=false,writes=0;
    const gate=new Promise<void>(r=>release=r);
    const root=f.engine.execute({name:'settings',mode:'write',global:true},{},ai,metadata(f.engine,'host'),async()=>{
      entered=true;await gate;localEffect(()=>writes++);return {ok:true};
    });
    await until(()=>entered);
    f.engine.control('takeover','target:one',human,metadata(f.engine));release();
    assert.equal((await root).error.code,'STALE_CONTROL');assert.equal(writes,0);
  }finally{f.close();}
});

test('queued deadline expiration confirms nothing was sent, including while the task is paused',async()=>{
  const f=fixture();try{
    const task=f.engine.createTask('queued',ai);
    const op=f.engine.submit(spec,{},ai,{...metadata(f.engine),taskId:task.id,timeoutMs:80},async()=>assert.fail('must not execute'));
    f.engine.taskAction(task.id,'pause',ai);
    await until(()=>f.engine.getOperation(op.id).state==='failed');
    assert.equal(f.engine.getOperation(op.id).error.code,'DEADLINE_EXCEEDED');
    assert.equal(f.engine.getOperation(op.id).mayHaveExecuted,false);
    assert.equal(f.engine.getOperation(op.id).settled,true,'no Host handler was started for queued expiration');
  }finally{f.close();}
});

test('late failure after timeout is retained as evidence without rewriting unknown as success',async()=>{
  const f=fixture();try{
    let release!:(e:Error)=>void;
    const gate=new Promise<void>((_,reject)=>release=reject);
    const op=await f.engine.execute(spec,{},ai,{...metadata(f.engine),timeoutMs:1000},async()=>trackedEffect(()=>gate));
    release(new Error('synthetic disconnected target'));
    await until(()=>f.engine.getOperation(op.id).settled);
    const result=f.engine.getOperation(op.id,true);
    assert.equal(result.state,'unknown');assert.match(result.lateResult.error,/disconnected/);
  }finally{f.close();}
});

test('two coordinators share control and quarantine; opening another live Host never replays or recovers its work',async()=>{
  const f=fixture();let second:Operations|undefined;try{
    let release!:()=>void,entered=false;
    const gate=new Promise<void>(r=>release=r);
    const op=f.engine.submit(spec,{},ai,metadata(f.engine),async()=>{entered=true;await gate;checkpoint();return {ok:true};});
    await until(()=>entered);second=new Operations(f.root);
    assert.equal(second.getOperation(op.id).state,'running');
    second.control('takeover','target:one',human,metadata(second));
    assert.equal(f.engine.snapshot('target:one').owner,'operator');
    release();await until(()=>f.engine.getOperation(op.id).settled);
    assert.equal(second.getOperation(op.id).error.code,'STALE_CONTROL');
  }finally{second?.close();f.close();}
});

test('corrupt authoritative ledger fails closed and is never silently replaced',()=>{
  const root=mkdtempSync(join(tmpdir(),'adh-p1-'));
  const file=join(root,'operations.sqlite'),bytes=Buffer.from('synthetic broken ledger');
  try{
    writeFileSync(file,bytes);assert.throws(()=>new TaskStore(root));
    assert.deepEqual(readFileSync(file),bytes);
  }finally{assert.ok(root.startsWith(join(tmpdir(),'adh-p1-')));rmSync(root,{recursive:true,force:true});}
});

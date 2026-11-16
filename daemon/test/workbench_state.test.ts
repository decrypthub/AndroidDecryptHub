import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Operations,type Principal} from '../src/operations.ts';
import {trackedEffect,localEffect} from '../src/execution_context.ts';

const ai:Principal={role:'ai',id:'fixture-ai',source:'mcp'},human:Principal={role:'operator',id:'fixture-human',source:'panel'};
function fixture(){const root=mkdtempSync(join(tmpdir(),'adh-p2-test-')),engine=new Operations(root);return {engine,close(){engine.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p2-test-')));rmSync(root,{recursive:true,force:true});}};}
const delay=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn:()=>boolean){for(let n=0;n<500&&!fn();n++)await delay(2);assert.ok(fn());}

test('task revisions reject stale human controls without clearing an operator pause',()=>{
  const f=fixture();try{
    const task=f.engine.createTask('analysis',ai),observed=f.engine.getTask(task.id);
    assert.equal(observed.revision,0);assert.equal(observed.source,'mcp');
    f.engine.taskAction(task.id,'pause',human,observed.revision);
    assert.throws(()=>f.engine.taskAction(task.id,'resume',human,observed.revision),(e:any)=>e.code==='STALE_TASK');
    assert.equal(f.engine.getTask(task.id).heldByOperator,true);assert.equal(f.engine.getTask(task.id).state,'paused');
    const fresh=f.engine.getTask(task.id);f.engine.taskAction(task.id,'resume',human,fresh.revision);
    assert.equal(f.engine.getTask(task.id).heldByOperator,false);
    assert.throws(()=>f.engine.taskAction(task.id,'pause',human,-1),(e:any)=>e.code==='INVALID_TASK_VERSION');
  }finally{f.close();}
});

test('legacy tasks expose revision zero; search, task detail and operation pages cover retained records',async()=>{
  const f=fixture();try{
    const first=f.engine.createTask('older task',ai),last=f.engine.createTask('needle task',ai);
    f.engine.store.update(data=>{delete data.tasks[first.id].revision;});
    assert.equal(f.engine.getTask(first.id).revision,0);
    for(let n=0;n<7;n++)await f.engine.execute({name:'analysis '+n,mode:'analysis'},{},ai,{taskId:first.id},async()=>({ok:true,n}));
    const page=f.engine.list(first.id,3,3);assert.equal(page.tasks.length,0);assert.equal(page.totalTasks,1);
    assert.equal(page.operations.length,3);assert.equal(page.nextOperationOffset,6);assert.equal(page.nextTaskOffset,null);
    assert.equal(f.engine.getTask(first.id).totalOperations,7);
    assert.deepEqual(f.engine.getTask(first.id).operationCounts,{succeeded:7});
    assert.deepEqual(f.engine.list(undefined,10,0,{q:'needle'}).tasks.map(t=>t.id),[last.id]);
    assert.equal(f.engine.list(undefined,10,0,{owner:'operator'}).totalTasks,0);
  }finally{f.close();}
});

test('effect acknowledgements match concurrent dispatches and exclude command payloads',async()=>{
  const f=fixture();try{
    const task=f.engine.createTask('parallel reads',ai);let first!:()=>void,second!:()=>void;
    const a=new Promise<void>(r=>first=r),b=new Promise<void>(r=>second=r);
    const op=f.engine.submit({name:'inspect',mode:'analysis'},{privatePayload:'synthetic-private-bytes'},ai,{taskId:task.id},async()=>{
      await Promise.all([trackedEffect(()=>a,undefined,{kind:'agent',action:'maps'}),trackedEffect(()=>b,undefined,{kind:'agent',action:'read'})]);return {ok:true};
    });
    await until(()=>f.engine.getOperation(op.id).inFlight===2);second();await until(()=>f.engine.getOperation(op.id).inFlight===1);
    let effects=f.engine.getOperation(op.id).effects;assert.equal(effects[0].state,'dispatched');assert.equal(effects[1].state,'acknowledged');
    first();await until(()=>f.engine.getOperation(op.id).settled);effects=f.engine.getOperation(op.id).effects;
    assert.equal(effects[0].state,'acknowledged');assert.ok(effects[0].completedAt);
    assert.ok(f.engine.getOperation(op.id).startedAt);assert.ok(f.engine.getOperation(op.id).finishedAt);
    assert.ok(!JSON.stringify(f.engine.store.read()).includes('synthetic-private-bytes'));
  }finally{f.close();}
});

test('effect journal is bounded and reports omitted steps without losing dispatch accounting',async()=>{
  const f=fixture();try{
    const value=await f.engine.execute({name:'bounded local work',mode:'analysis'},{},ai,{},async()=>{
      for(let n=0;n<67;n++)localEffect(()=>{}, {kind:'host',action:'fixture step'});return {ok:true};
    });
    assert.equal(value.effects.length,64);assert.equal(value.effectsDropped,3);assert.equal(value.inFlight,0);assert.equal(value.state,'succeeded');
    assert.ok(value.effects.every(e=>e.state==='acknowledged'));
  }finally{f.close();}
});

test('intent lookup is read-only, uses the original role namespace and never resubmits',async()=>{
  const f=fixture();try{
    const op=await f.engine.execute({name:'saved analysis',mode:'analysis'},{},human,{idempotencyKey:'lost-ack'},async()=>({ok:true,value:42}));
    assert.equal(f.engine.findOperation('lost-ack',human,true).result.value,42);
    assert.equal(f.engine.findOperation('lost-ack',human).id,op.id);
    assert.throws(()=>f.engine.findOperation('lost-ack',ai),(e:any)=>e.code==='OPERATION_NOT_FOUND');
    assert.equal(f.engine.list().totalOperations,1);
  }finally{f.close();}
});

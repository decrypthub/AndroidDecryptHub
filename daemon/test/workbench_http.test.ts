import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';

const oldExec=cp.execFile,oldSpawn=cp.spawn;
cp.execFile=(()=>{throw Error('device subprocess forbidden in P2 HTTP fixture');}) as unknown as typeof cp.execFile;
cp.spawn=(()=>{throw Error('device subprocess forbidden in P2 HTTP fixture');}) as unknown as typeof cp.spawn;syncBuiltinESMExports();
const {handleHttp}=await import('../src/http/router.ts');
const {getOperations,operationsRoot}=await import('../src/operation_host.ts');
const {initializeOperatorAccess}=await import('../src/access_context.ts');
const key=initializeOperatorAccess(operationsRoot),engine=getOperations();
const server=http.createServer((req,res)=>{handleHttp(req,res).catch(e=>{res.writeHead(500);res.end(JSON.stringify({error:String(e)}));});});
let base:string;
before(async()=>{await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));base='http://127.0.0.1:'+(server.address() as any).port;});
after(async()=>{await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));engine.close();cp.execFile=oldExec;cp.spawn=oldSpawn;syncBuiltinESMExports();});
async function call(value:any,operator=false){const response=await fetch(base+'/api/operations',{method:'POST',headers:{'content-type':'application/json',...(operator?{'X-Adh-Operator-Key':key}:{})},body:JSON.stringify(value)});return {status:response.status,body:await response.json() as any};}
const metadata=()=>{const c=engine.snapshot();return {expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch};};

test('workbench assets load from the same isolated router without exposing an operator secret',async()=>{
  for(const path of ['/workbench.css','/operation-client.js','/workbench-model.js','/workbench.js','/operations.js','/algorithm-observations.js']){
    const response=await fetch(base+path);assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-cache');
    const body=await response.text();assert.ok(!body.includes(key));
  }
});

test('browser task history is unmounted and old deep links lead back to the viewer',async()=>{
  const legacy=await fetch(base+'/workbench?taskId=fixture&operationId=fixture',{redirect:'manual'});
  assert.equal(legacy.status,302);
  assert.equal(legacy.headers.get('location'),'/');
  assert.equal(legacy.headers.get('cache-control'),'no-store');
  const landing=await (await fetch(base+'/workbench?taskId=fixture')).text();
  assert.match(landing,/id="setHookControls"/);
  assert.doesNotMatch(landing,/setRecordsTab|setRecordsPage|workbench(?:-model)?\.js/);
});

test('task CAS, pagination and explicit operator resume have the same HTTP contract as MCP',async()=>{
  const created=(await call({action:'create',title:'human workbench'})).body.task;
  let value=await call({action:'get',taskId:created.id,limit:1,offset:0});assert.equal(value.body.task.revision,0);assert.equal(value.body.totalTasks,1);
  value=await call({action:'pause',taskId:created.id,_operation:{expectedTaskRevision:0}},true);assert.equal(value.status,200);assert.equal(value.body.task.revision,1);
  value=await call({action:'resume',taskId:created.id,_operation:{expectedTaskRevision:0}},true);assert.equal(value.status,409);assert.equal(value.body.code,'STALE_TASK');
  value=await call({action:'resume',taskId:created.id,_operation:{expectedTaskRevision:1}});assert.equal(value.body.code,'OPERATOR_REQUIRED');
  value=await call({action:'resume',taskId:created.id,_operation:{expectedTaskRevision:1}},true);assert.equal(value.body.task.state,'active');assert.equal(value.body.task.heldByOperator,false);
  assert.equal((await call({action:'list',q:'human workbench'})).body.totalTasks,1);
});

test('a stale configuration submit is rejected without changing settings; accepted intent can be queried by key',async()=>{
  const old=metadata();
  let response=await fetch(base+'/api/config',{method:'POST',headers:{'content-type':'application/json','X-Adh-Operation':JSON.stringify(old)},body:JSON.stringify({ui:{displayCap:377}})});
  assert.equal(response.status,200);
  let result=await call({action:'submit',tool:'settings',arguments:{action:'patch',patch:{ui:{displayCap:411}}},_operation:old},true);
  assert.equal(result.status,409);assert.equal(result.body.code,'STALE_CONTROL');
  let config=await (await fetch(base+'/api/config')).json() as any;assert.equal(config.settings.ui.displayCap,377);
  result=await call({action:'submit',tool:'settings',arguments:{action:'patch',patch:{ui:{displayCap:411}}},_operation:{...metadata(),idempotencyKey:'reviewed-human-intent'}},true);
  assert.equal(result.status,200);const id=result.body.operation.id;
  for(let n=0;n<100&&!engine.getOperation(id).settled;n++)await new Promise(r=>setTimeout(r,5));
  const found=await call({action:'get',idempotencyKey:'reviewed-human-intent',includeResult:true},true);
  assert.equal(found.body.operation.id,id);assert.equal(found.body.operation.state,'succeeded');
  assert.equal(found.body.operation.effects[0].action,'settings.save');assert.equal(found.body.operation.effects[0].state,'acknowledged');
  assert.equal((await call({action:'get',idempotencyKey:'reviewed-human-intent'})).body.code,'OPERATION_NOT_FOUND');
  config=await (await fetch(base+'/api/config')).json() as any;assert.equal(config.settings.ui.displayCap,411);
});

test('history can hide successful panel settings saves without hiding failures or API tasks',async()=>{
  const panel = {role:'ai' as const, id:'panel-fixture', source:'panel'};
  const settingsOp = {name:'settings', mode:'analysis' as const};
  const saved = await engine.execute(settingsOp, {}, panel, {}, async () => ({ok:true}));
  const failed = await engine.execute(settingsOp, {}, panel, {}, async () => ({ok:false}));
  const ai = await engine.execute(settingsOp, {}, {...panel, source:'mcp'}, {}, async () => ({ok:true}));
  assert.equal(saved.state,'succeeded');
  assert.equal(failed.state,'failed');

  const list = async(taskId:string,hideSettingSaves:boolean) => (await call({
    action:'list', taskId, limit:1, hideSettingSaves,
  })).body;
  assert.equal((await list(saved.taskId,true)).totalTasks,0);
  assert.equal((await list(saved.taskId,false)).tasks[0].id,saved.taskId);
  assert.equal((await list(failed.taskId,true)).tasks[0].id,failed.taskId);
  assert.equal((await list(ai.taskId,true)).tasks[0].id,ai.taskId);
  assert.equal((await call({action:'get',id:saved.id,includeResult:true})).body.operation.result.ok,true);
});

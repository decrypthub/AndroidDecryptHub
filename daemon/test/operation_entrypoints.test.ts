import test, {before,after} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import cp from 'node:child_process';
import {promisify} from 'node:util';
import {syncBuiltinESMExports} from 'node:module';
import {resolve,join} from 'node:path';

const executeChild=promisify(cp.execFile),oldExec=cp.execFile,oldSpawn=cp.spawn;
cp.execFile=(()=>{throw Error('device subprocess forbidden in P1 fixture');}) as unknown as typeof cp.execFile;
cp.spawn=(()=>{throw Error('device subprocess forbidden in P1 fixture');}) as unknown as typeof cp.spawn;
syncBuiltinESMExports();
const {handleHttp}=await import('../src/http/router.ts');
const {sessions,agentSockets,pending,DATA_DIR,failPendingFor,wss}=await import('../src/state.ts');
const {getOperations,operationsRoot,targetResource,automaticSnapshot,runAutomatic}=await import('../src/operation_host.ts');
const {initializeOperatorAccess}=await import('../src/access_context.ts');
const key=initializeOperatorAccess(operationsRoot);
const server=http.createServer((req,res)=>{handleHttp(req,res).catch(e=>{res.writeHead(500);res.end(JSON.stringify({error:String(e)}));});});
let base:string;
before(async()=>{await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${(server.address() as any).port}`;});
after(async()=>{
  for(const value of pending.values())value.resolve({ok:false,error:'fixture closed'});
  sessions.clear();agentSockets.clear();
  cp.execFile=oldExec;cp.spawn=oldSpawn;syncBuiltinESMExports();
  await new Promise<void>((r,j)=>server.close(e=>e?j(e):r()));
});
const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function until(fn:()=>boolean){for(let i=0;i<1000&&!fn();i++)await sleep(3);assert.ok(fn());}
function fakeSession(id:string) {
  const writes:any[]=[],held:string[]=[];
  sessions.set(id,{sessionId:id,package:'com.example.fixture',process:'com.example.fixture',pid:42,uid:10001,starttimeTicks:'1234',online:true} as any);
  agentSockets.set(id,{destroyed:false,write(frame:Buffer){
    const message=JSON.parse(frame.subarray(5).toString());writes.push(message);
    if(message.op==='native_call'){held.push(message.id);return true;}
    queueMicrotask(()=>pending.get(message.id)?.resolve(message.op==='write'?{ok:true,before:'00',beforeReadable:true,wrote:1}:{ok:true}));return true;
  }} as any);
  return {writes,held,reply(){for(const id of held.splice(0))pending.get(id)?.resolve({ok:true,result:'42'});}};
}
function meta(session?:string,keyValue?:string) {
  const s=getOperations().snapshot(session?targetResource(session):'host');
  return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch,...(keyValue?{idempotencyKey:keyValue}:{})};
}
async function rpc(tool:string,args:any,operator=false,id:any=1,client='entry-test') {
  const response=await fetch(base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Client-Id':client,...(operator?{'X-Adh-Operator-Key':key}:{})},
    body:JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name:tool,arguments:args}})});
  const json=await response.json() as any;
  return {body:JSON.parse(json.result.content[0].text),isError:json.result.isError};
}
async function management(args:any,operator=false){return (await rpc('operations',args,operator)).body;}

test('operator panel modification invalidates old AI instructions; forged JSON/headers and legacy routes cannot bypass it',async()=>{
  const session='entry-human',fake=fakeSession(session),old=meta(session);
  const response=await fetch(base+'/api/memory/write',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operator-Key':key,'X-Adh-Operation':JSON.stringify(old)},
    body:JSON.stringify({session,addr:'0x1000',hex:'41'})});
  assert.equal(response.status,200);assert.equal(fake.writes.length,1);
  const stale=await rpc('memory_write',{session,addr:'0x1000',hex:'42',_operation:old});
  assert.equal(stale.isError,true);assert.equal(stale.body.code,'STALE_CONTROL');
  const forged=await rpc('memory_write',{session,addr:'0x1000',hex:'42',actor:'human',_operation:{...meta(session),owner:'operator'}});
  assert.equal(forged.body.code,'CONTROL_HELD');
  const bad=await fetch(base+'/api/memory/write',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operator-Key':'not-the-key'},body:'{}'});
  assert.equal(bad.status,403);
  const missing=await fetch(base+'/api/memory/write',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session,addr:'0x1000',hex:'43'})});
  assert.equal(missing.status,409);
  const activeGet=await fetch(base+'/api/unpack/trigger?session='+session+'&symbol=run');
  assert.equal(activeGet.status,409);assert.equal(fake.writes.length,1);
  const global=await rpc('settings',{action:'patch',patch:{ui:{displayCap:80}},_operation:meta()});
  assert.equal(global.body.code,'CONTROL_HELD','Host-wide AI writes cannot step around an operator-held target');
  await management({action:'release',session,_operation:meta(session)},true);
});

test('the same idempotency key across REST and MCP returns the original result without a second write',async()=>{
  const session='entry-shared',fake=fakeSession(session);
  let control=meta(session,'rest-first');
  const args={session,addr:'0x1000',hex:'41'};
  const first=await fetch(base+'/api/memory/write',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operation':JSON.stringify(control)},body:JSON.stringify(args)});
  const json=await first.json() as any;assert.equal(first.status,200);
  const replay=await rpc('memory_write',{...args,_operation:control});
  assert.equal(replay.body.ok,true);assert.equal(replay.body._operation.id,json._operation.id);assert.equal(fake.writes.length,1);
  control=meta(session,'mcp-first');
  const second=await rpc('memory_write',{...args,hex:'42',_operation:control});
  const again=await fetch(base+'/api/memory/write',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operation':JSON.stringify(control)},body:JSON.stringify({...args,hex:'42'})});
  const body=await again.json() as any;assert.equal(again.status,200);assert.equal(body._operation.id,second.body._operation.id);assert.equal(fake.writes.length,2);
});

test('a status-looking extra field cannot disguise installing hooks or replaying a target as a read',async()=>{
  const session='entry-effects',fake=fakeSession(session);
  for(const args of [
    {tool:'native_hook_all',action:'status',module:'libfixture.so',confirm:true},
    {tool:'syscall_watch',action:'status',module:'libfixture.so'},
    {tool:'oracle',action:'stability',id:1},
  ]) {
    const {tool,...arguments_}=args;
    const result=await rpc(tool,{session,...arguments_});
    assert.equal(result.body.code,'CONTROL_REQUIRED');
  }
  assert.equal(fake.writes.length,0);
});

test('MCP cancellation notification binds to the client request and reports a running call honestly',async()=>{
  const session='entry-cancel',fake=fakeSession(session);
  const promise=rpc('native_call',{session,module:'libfixture.so',symbol:'run',confirm:true,_operation:meta(session)},false,'pending-call','cancel-client');
  await until(()=>fake.held.length===1);
  const notification=await fetch(base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Client-Id':'cancel-client'},body:JSON.stringify({jsonrpc:'2.0',method:'notifications/cancelled',params:{requestId:'pending-call'}})});
  assert.equal(notification.status,202);
  const op=getOperations().list().operations.find(x=>x.name==='native_call'&&x.resource===targetResource(session))!;
  assert.equal(op.state,'cancel_requested');assert.equal(op.inFlight,1);
  fake.reply();const result=await promise;
  assert.equal(result.body._operation.state,'succeeded');assert.equal(result.body._operation.cancelRequested,true);
});

test('public Python CLI submits to this same Host, reads durable results and never upgrades AI using an inherited operator key',async t=>{
  try{await executeChild('python',['--version'],{timeout:5000,windowsHide:true});}catch(error){if((error as any).code==='ENOENT'){t.skip('Python unavailable');return;}throw error;}
  const session='entry-cli',fake=fakeSession(session);
  const env={...process.env,PYTHONPATH:resolve('../..','adh-cli','src'),ADH_CONFIG_PATH:join(DATA_DIR,'cli-fixture.json'),PYTHONIOENCODING:'utf-8',ADH_OPERATOR_TOKEN:key};
  async function cli(args:string[]) {
    const result=await executeChild('python',['-m','adh',...args,'--endpoint',base,'--json'],{env,timeout:15000,windowsHide:true});
    return JSON.parse(String(result.stdout));
  }
  const run=await cli(['run','memory_write','--arguments',JSON.stringify({session,addr:'0x1000',hex:'41'})]);
  const id=run.operation.id;await until(()=>getOperations().getOperation(id).settled);
  const result=await cli(['tasks','get',id,'--include-result']);
  assert.equal(result.operation.state,'succeeded');assert.equal(result.operation.owner,'ai');assert.equal(fake.writes.length,1);
  await cli(['control','takeover','--session',session,'--operator']);
  const blocked=await rpc('memory_write',{session,addr:'0x1000',hex:'42',_operation:meta(session)});
  assert.equal(blocked.body.code,'CONTROL_HELD');
  await cli(['control','release','--session',session,'--operator']);
});

test('developer CLI target checks use the same guarded operation entry point',async()=>{
  const session='entry-node-cli';fakeSession(session);
  const port=new URL(base).port;
  const result=await executeChild(process.execPath,['src/cli.ts','target','--session',session,'--port',port,'--json'],
    {env:{...process.env,ADH_OPERATOR_TOKEN:key},timeout:15000,windowsHide:true});
  const value=JSON.parse(String(result.stdout));assert.equal(value.ok,true);
  const op=getOperations().list().operations.find(op=>op.name==='compat_probe' && op.resource===targetResource(session));
  assert.equal(op?.state,'succeeded');assert.equal(op?.owner,'ai');
});

test('delayed automatic policies cannot refresh themselves across human takeover and release',async()=>{
  const session='entry-automatic';fakeSession(session);
  const epoch=automaticSnapshot(session);let hits=0;
  await management({action:'takeover',session,_operation:meta(session)},true);
  await management({action:'release',session,_operation:meta(session)},true);
  const stale=await runAutomatic(session,'fixture-startup',epoch,async()=>{hits++;return {ok:true};});
  assert.equal(stale.code,'STALE_CONTROL');assert.equal(hits,0);
  const fresh=await runAutomatic(session,'fixture-startup',automaticSnapshot(session),async()=>{hits++;return {ok:true};});
  assert.equal(fresh._operation.state,'succeeded');assert.equal(hits,1);
});

test('agent disconnect reports unknown execution, including command events, without claiming target cancellation',async()=>{
  const session='entry-disconnect',fake=fakeSession(session);
  const seen:any[]=[],client={readyState:1,send:(raw:string)=>seen.push(JSON.parse(raw))};
  wss.clients.add(client as any);
  try {
  const promise=rpc('native_call',{session,module:'libfixture.so',symbol:'run',confirm:true,_operation:meta(session)});
  await until(()=>fake.held.length===1);
  failPendingFor(session,'synthetic disconnect');
  const result=await promise;
  assert.equal(result.body._operation.state,'unknown');assert.equal(result.isError,true);
  const done=seen.findLast(e=>e.event==='cmd.done' && e.data.sessionId===session);
  assert.equal(done?.data.state,'unknown');assert.equal(done?.data.targetStopped,false);
  } finally {wss.clients.delete(client as any);}
});

// Standalone synthetic workbench Host; no index.ts, real ADB, live data or real target.
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {promisify} from 'node:util';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import http from 'node:http';
const appCapture = process.argv.includes('--app-capture');
const alpha = 'com.example.alpha', beta = 'com.example.beta';
process.env.ADH_DATA_DIR=mkdtempSync(join(tmpdir(),'adh-p2-panel-'));
delete process.env.ADH_CAPTURES_DIR;process.env.ADH_SKIP_ARTIFACT_LOAD='1';process.env.ADH_OPERATOR_TOKEN='synthetic-p2-operator-key';
cp.execFile=(()=>{throw Error('real subprocess forbidden in P2 fixture');}) as unknown as typeof cp.execFile;
Object.defineProperty(cp.execFile,promisify.custom,{value:async(file:string,args:string[])=>{
  if(file==='adb'&&args.some(a=>a.includes('cat /data/adb/adh/scope.json')))return {stdout:JSON.stringify({packages:appCapture?[alpha,beta]:[]}),stderr:''};
  throw Error('device subprocess forbidden in P2 fixture');
}});
cp.spawn=(()=>{throw Error('spawn forbidden in P2 fixture');}) as unknown as typeof cp.spawn;syncBuiltinESMExports();
const {handleHttp}=await import('../../src/http/router.ts');
const {sessions,agentSockets,pending,readBody,wss}=await import('../../src/state.ts');
const {getOperations,targetResource}=await import('../../src/operation_host.ts');
const {trackedEffect}=await import('../../src/execution_context.ts');
const {patchSettings}=await import('../../src/settings_service.ts');
const {sendCmd}=await import('../../src/service.ts');
const ai={role:'ai' as const,id:'synthetic-ai',source:'mcp'},human={role:'operator' as const,id:'synthetic-human',source:'panel'};
const captureCommands: Record<string, string[]> = {};
for(const [sid,pid]of [['p2-fixture',42],['p2-uncertain',43]] as const){
  const pkg = appCapture ? (pid === 42 ? alpha : beta) : 'com.example.fixture';
  sessions.set(sid,{sessionId:sid,package:pkg,process:pkg,pid,uid:10001,starttimeTicks:'1',online:true,agentVer:'synthetic',abi:'arm64-v8a',android:'15',sdk:35,entry:'fixture'} as any);
  const commands = captureCommands[pkg] = [];
  agentSockets.set(sid,{destroyed:false,write(frame:Buffer){
    const msg=JSON.parse(frame.subarray(5).toString());
    if(appCapture && ['capture_policy','capture_start','capture_stop'].includes(msg.op)) commands.push(msg.op);
    queueMicrotask(()=>pending.get(msg.id)?.resolve({ok:true,before:'00',beforeReadable:true,wrote:1,regions:[],evp:1}));
    return true;
  }} as any);
}
const engine=getOperations();
const meta=(resource='host')=>{const c=engine.snapshot(resource);return {expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch};};
const task=engine.createTask('请求边界分析 · 合成样本',ai);
await engine.execute({name:'证据一致性检查',mode:'analysis'},{},ai,{taskId:task.id},async()=>({ok:true,matched:3,note:'合成结果，仅用于面板验收',untrustedText:'<img src=x onerror="window.fixtureInjected=true">'}));
await engine.execute({name:'memory_write',mode:'write',session:'p2-fixture'},{},ai,{taskId:task.id,...meta(targetResource('p2-fixture'))},()=>sendCmd('p2-fixture','write',{addr:'1000',hex:'41'}));
engine.taskAction(task.id,'complete',ai);
const paused=engine.createTask('等待下一轮实验',ai);
engine.submit({name:'待执行的合成观察',mode:'write',session:'p2-fixture'},{},ai,{taskId:paused.id,...meta(targetResource('p2-fixture'))},()=>sendCmd('p2-fixture','maps'));
engine.taskAction(paused.id,'pause',human);
let release!:()=>void;const gate=new Promise<void>(r=>release=r);
const unknown=appCapture?undefined:await engine.execute({name:'超时观察 · 合成样本',mode:'write',session:'p2-uncertain'},{},ai,{...meta(targetResource('p2-uncertain')),timeoutMs:1000},()=>trackedEffect(async()=>{await gate;return {ok:true,note:'晚到的合成结果'};},'p2-uncertain',{kind:'agent',action:'fixture observation',session:'p2-uncertain'}));
release();await new Promise(r=>setTimeout(r,20));
const server=http.createServer((req,res)=>{
  const finish=(status:number,value:any)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));};
  (async()=>{
    if(req.url==='/__fixture/state')return finish(200,{task:task.id,paused:paused.id,unknown:unknown?.id,root:process.env.ADH_DATA_DIR});
    if(appCapture&&req.url==='/__fixture/capture-commands')return finish(200,captureCommands);
    if(req.url==='/__fixture/ai-config'&&req.method==='POST'){
      const patch=JSON.parse(await readBody(req)||'{}');const result=await engine.execute({name:'settings',mode:'write',global:true},patch,ai,meta(),()=>patchSettings(patch));return finish(200,result);
    }
    if(req.url==='/__fixture/task-change'&&req.method==='POST')return finish(200,engine.taskAction(paused.id,'pause',human));
    return handleHttp(req,res);
  })().catch(error=>finish(500,{error:String(error)}));
});
if(appCapture) server.on('upgrade', (req, socket, head) => {
  if(req.url!=='/ws'){socket.destroy();return;}
  wss.handleUpgrade(req, socket, head, ws => ws.send(JSON.stringify({event:'snapshot',data:[...sessions.values()]})));
});
server.listen(0,'127.0.0.1',()=>console.log('P2_WORKBENCH_URL=http://127.0.0.1:'+(server.address() as any).port));
const stop=()=>{server.closeAllConnections();server.close();engine.close();process.exit(0);};
process.on('SIGINT',stop);process.stdin.resume();process.stdin.on('data',line=>{if(String(line).trim()==='stop')stop();});

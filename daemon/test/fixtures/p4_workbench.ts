// Browser-only synthetic device evidence. No index.ts, devices, ADB or target process.
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import http from 'node:http';
process.env.ADH_DATA_DIR=mkdtempSync(join(tmpdir(),'adh-p4-panel-'));process.env.ADH_SKIP_ARTIFACT_LOAD='1';delete process.env.ADH_CAPTURES_DIR;
process.env.ADH_OPERATOR_TOKEN='synthetic-p4-operator-key';
cp.execFile=(()=>{throw Error('ADB forbidden in P4 panel fixture');}) as unknown as typeof cp.execFile;
cp.spawn=(()=>{throw Error('device process forbidden in P4 panel fixture');}) as unknown as typeof cp.spawn;syncBuiltinESMExports();
const {getOperations}=await import('../../src/operation_host.ts');
const {handleHttp}=await import('../../src/http/router.ts');
const {trackedEffect}=await import('../../src/execution_context.ts');
const engine=getOperations(),deviceId='00000000-0000-4000-8000-000000000004',resource='device:'+deviceId;
const ai={role:'ai' as const,id:'fixture',source:'mcp'},task=engine.createTask('LAN 断线对账 · 合成设备',ai);
const meta=()=>{const c=engine.snapshot(resource);return {expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch,taskId:task.id};};
const lost=await engine.execute({name:'devices',mode:'write',deviceId},{},ai,meta(),()=>trackedEffect(async()=>{throw Error('synthetic response lost');},undefined,{kind:'device',action:'process.control'}));
engine.recordDeviceReconciliation(lost.id,deviceId,{operationId:lost.id,found:true,state:'succeeded',result:{synthetic:true,calls:1,note:'<img src=x onerror="window.fixtureInjected=true">'},replayed:false});
// A second implicit task demonstrates multiple unknown controls without resuming the held task.
const spec={name:'devices',mode:'write' as const,deviceId,securityOnly:true};const m=meta();delete (m as any).taskId;
const revoked=await engine.execute(spec,{},ai,m,()=>trackedEffect(async()=>{throw Error('synthetic self-revocation closed stream');},undefined,{kind:'device',action:'pairings.revoke'}));
const server=http.createServer((req,res)=>handleHttp(req,res).catch(()=>{res.writeHead(500);res.end('{}');}));
server.listen(0,'127.0.0.1',()=>console.log('P4_WORKBENCH='+JSON.stringify({url:'http://127.0.0.1:'+(server.address() as any).port,taskId:task.id,unknownId:lost.id,revocationId:revoked.id,root:process.env.ADH_DATA_DIR})));
const stop=()=>{server.closeAllConnections();server.close();engine.close();process.exit(0);};
process.stdin.resume();process.stdin.on('data',line=>{if(String(line).trim()==='stop')stop();});process.on('SIGINT',stop);

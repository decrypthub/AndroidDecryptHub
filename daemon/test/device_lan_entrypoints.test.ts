import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import cp from 'node:child_process';
import {promisify} from 'node:util';
import {existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {Devices} from '../src/devices.ts';
import {AdbDeviceTransport} from '../src/transport/adb_device.ts';
import {setDevicesForTests} from '../src/device_host.ts';
import {getOperations,operationsRoot} from '../src/operation_host.ts';
import {initializeOperatorAccess} from '../src/access_context.ts';
import {handleHttp} from '../src/http/router.ts';
import {DATA_DIR} from '../src/state.ts';
import {startDeviceFixture,FakeAdb,jvmManifest,pause} from './device_fixture.ts';

test('public CLI pairing, MCP LAN recovery and REST revocation share durable reconciliation and control fences',async t=>{
  if(!existsSync(jvmManifest)){t.skip('build the offline Kotlin fixture; no real ADB fallback');return;}
  const phone=await startDeviceFixture(),adb=new FakeAdb();adb.add('p4-fixture','1',phone);let available=true,forbidden=0;
  const engine=getOperations(),key=initializeOperatorAccess(operationsRoot);
  const devices=new Devices(join(DATA_DIR,'devices.json'),new AdbDeviceTransport(async(args,o)=>{if(!available){forbidden++;throw Error('ADB removed');}return adb.run(args,o);}),id=>engine.invalidateResource('device:'+id));setDevicesForTests(devices);
  const server=http.createServer((req,res)=>{handleHttp(req,res).catch(()=>{res.writeHead(500);res.end('{}');});});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+(server.address() as any).port;
  const meta=(resource='host')=>{const s=engine.snapshot(resource);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
  async function rpc(name:string,args:any,operator=false){const response=await fetch(base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json',...(operator?{'X-Adh-Operator-Key':key}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})});const json=await response.json() as any;return JSON.parse(json.result.content[0].text);}
  async function rest(args:any,resource:string){const response=await fetch(base+'/api/devices',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operation':JSON.stringify(meta(resource))},body:JSON.stringify(args)});return {status:response.status,body:await response.json() as any};}
  async function state(peer:any){return (await rpc('devices',{action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,method:'device.state'})).result;}
  async function intent(peer:any,method:string,params:any={}){const observed=await state(peer);return {action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:observed.stateRevision,method,params};}
  try{
    const usb=await rpc('devices',{action:'connect',serial:'p4-fixture',transportId:'1',_operation:meta()}),resource='device:'+usb.deviceId;assert.equal(usb._operation.state,'succeeded');
    const configured=await rest(await intent(usb,'lan.configure',{enabled:true,address:'127.0.0.1',port:0}),resource);assert.equal(configured.status,200);const port=configured.body.result.result.port;
    const observed=await state(usb);const pairing={action:'pair',deviceId:usb.deviceId,connectionId:usb.connectionId,bootId:usb.bootId,daemonInstanceId:usb.daemonInstanceId,expectedDeviceRevision:observed.stateRevision,permissions:['read','write','manage']};
    assert.equal((await rpc('devices',pairing)).code,'CONTROL_REQUIRED');
    const cliSource=process.env.ADH_CLI_SOURCE||resolve('../..','adh-cli','src');
    if(existsSync(join(cliSource,'adh','__init__.py'))){
      const output=await promisify(cp.execFile)('python',['-m','adh','run','devices','--arguments',JSON.stringify(pairing),'--endpoint',base,'--json'],{env:{...process.env,PYTHONPATH:cliSource,ADH_CONFIG_PATH:join(DATA_DIR,'p4-cli.json'),ADH_OPERATOR_TOKEN:key,PYTHONIOENCODING:'utf-8'},timeout:15000,windowsHide:true});
      const op=JSON.parse(String(output.stdout)).operation;for(let n=0;n<200&&!engine.getOperation(op.id).settled;n++)await pause(5);assert.equal(engine.getOperation(op.id).state,'succeeded');assert.equal(engine.getOperation(op.id).owner,'ai');
    }else{t.diagnostic('CLI source unavailable; set ADH_CLI_SOURCE for full path');assert.equal((await rpc('devices',{...pairing,_operation:meta(resource)}))._operation.state,'succeeded');}
    const lan=await rpc('devices',{action:'connect',transport:'lan',deviceId:usb.deviceId,address:'127.0.0.1',port,_operation:meta(resource)});assert.equal(lan._operation.state,'succeeded');
    assert.equal((await rest({action:'disconnect',deviceId:usb.deviceId,connectionId:usb.connectionId},resource)).status,200);available=false;
    const work=await rpc('devices',{...await intent(lan,'process.control',{delayMs:500}),budgetMs:50,_operation:meta(resource)});assert.equal(work._operation.state,'unknown');
    const recovered=await rpc('devices',{action:'connect',transport:'lan',deviceId:usb.deviceId,address:'127.0.0.1',port,_operation:meta(resource)});assert.equal(recovered._operation.state,'succeeded');
    const audit=await rpc('devices',{action:'reconcile',deviceId:usb.deviceId,connectionId:recovered.connectionId,operationIds:[work._operation.id]});assert.equal(audit.replayed,false);assert.equal(audit.reconciled[0].deviceEvidence.state,'succeeded');assert.equal(audit.reconciled[0].hostState,'unknown');
    const record=await rpc('operations',{action:'get',id:work._operation.id,includeResult:true});assert.equal(record.operation.reconciliations.length,1);assert.equal(record.operation.reconciliations[0].evidence.result.calls,1);
    assert.equal((await rpc('runtime_diagnostics',{deviceId:usb.deviceId,transport:'lan',session:'unverified-legacy'})).code,'UNSUPPORTED_DEVICE_ROUTING');
    assert.equal((await (await fetch(base+'/api/agents?deviceId='+usb.deviceId)).json() as any).code,'UNSUPPORTED_DEVICE_ROUTING');
    const mismatch=await rpc('devices',{action:'reconcile',deviceId:'00000000-0000-4000-8000-000000000009',operationIds:[work._operation.id]});assert.equal(mismatch.code,'TARGET_CHANGED');
    await rpc('operations',{action:'resolve',resource,acknowledge:true,_operation:meta(resource)},true);
    await rpc('operations',{action:'takeover',resource,_operation:meta(resource)},true);
    const blocked=await rpc('devices',{...await intent(recovered,'host.set',{endpoint:'192.0.2.2:8761'}),_operation:meta(resource)});assert.equal(blocked.code,'CONTROL_HELD');
    await rpc('operations',{action:'release',resource,_operation:meta(resource)},true);
    const grant=devices.list().devices.find(device=>device.deviceId===usb.deviceId)?.pairing;
    assert.ok(grant,'the explicitly paired fixture must retain its enrollment');
    const revoked=await rest(await intent(recovered,'pairings.revoke',{grantId:grant.grantId}),resource);assert.equal(revoked.status,504);assert.equal(revoked.body._operation.state,'unknown');
    const denied=await rpc('devices',{action:'connect',transport:'lan',deviceId:usb.deviceId,address:'127.0.0.1',port,_operation:meta(resource)});assert.equal(denied.code,'AUTH_FAILED');assert.equal(forbidden,0);
  }finally{devices.close();await new Promise<void>(r=>server.close(()=>r()));engine.close();await adb.close();await phone.close();}
});

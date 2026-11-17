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

test('MCP, REST and published CLI use the same device resource, CAS and operator fence',async t=>{
  if(!existsSync(jvmManifest)){t.skip('offline Kotlin fixture classpath unavailable; no real ADB fallback');return;}
  const phone=await startDeviceFixture(),adb=new FakeAdb();adb.add('fixture-usb','11',phone);
  const engine=getOperations(),key=initializeOperatorAccess(operationsRoot),devices=new Devices(join(DATA_DIR,'devices.json'),new AdbDeviceTransport(adb.run));setDevicesForTests(devices);
  const server=http.createServer((req,res)=>{handleHttp(req,res).catch(()=>{res.writeHead(500);res.end('{}');});});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+(server.address() as any).port;
  const meta=(resource='host')=>{const s=engine.snapshot(resource);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
  const rpc=async(name:string,args:any,operator=false)=>{
    const response=await fetch(base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json',...(operator?{'X-Adh-Operator-Key':key}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}})});
    const value=await response.json() as any;return JSON.parse(value.result.content[0].text);
  };
  try{
    const list=await (await fetch(base+'/api/devices')).json() as any;assert.equal(list.devices.length,0);assert.equal(adb.commands.length,0);
    assert.equal((await rpc('devices',{action:'connect',serial:'fixture-usb'})).code,'CONTROL_REQUIRED');assert.equal(adb.commands.length,0);
    const connected=await rpc('devices',{action:'connect',serial:'fixture-usb',transportId:'11',_operation:meta()});assert.equal(connected._operation.state,'succeeded');
    const resource='device:'+connected.deviceId;
    const read=await rpc('devices',{action:'call',deviceId:connected.deviceId,method:'scope.get'});
    const args={action:'call',deviceId:connected.deviceId,bootId:connected.bootId,daemonInstanceId:connected.daemonInstanceId,expectedDeviceRevision:read.result.stateRevision,method:'scope.patch',params:{scopeRevision:read.result.scopeRevision,add:['com.fixture.one']}};
    const intent={...meta(resource),idempotencyKey:'cross-entry-device-intent'};
    const changed=await fetch(base+'/api/devices',{method:'POST',headers:{'Content-Type':'application/json','X-Adh-Operation':JSON.stringify(intent)},body:JSON.stringify(args)});
    const body=await changed.json() as any;assert.equal(changed.status,200);assert.equal(body._operation.resource,resource);
    const again=await rpc('devices',{...args,_operation:intent});assert.equal(again._operation.id,body._operation.id);assert.equal(again.result.stateRevision,1);
    const old=meta(resource);
    await rpc('operations',{action:'takeover',resource,_operation:meta(resource)},true);
    assert.equal((await rpc('devices',{...args,_operation:old})).code,'STALE_CONTROL');
    assert.equal((await rpc('devices',{...args,_operation:meta(resource)})).code,'CONTROL_HELD');
    await rpc('operations',{action:'release',resource,_operation:meta(resource)},true);
    const cliSource=process.env.ADH_CLI_SOURCE||resolve('../..','adh-cli','src');
    if(!existsSync(join(cliSource,'adh','__init__.py'))){t.diagnostic('CLI source unavailable; MCP/REST assertions passed, set ADH_CLI_SOURCE for CLI path');return;}
    try{await promisify(cp.execFile)('python',['--version'],{windowsHide:true,timeout:5000});}catch(e){if((e as any).code==='ENOENT'){t.diagnostic('Python unavailable; CLI portion not run');return;}throw e;}
    const execute=promisify(cp.execFile),env={...process.env,PYTHONPATH:cliSource,ADH_CONFIG_PATH:join(DATA_DIR,'device-cli-fixture.json'),ADH_OPERATOR_TOKEN:key,PYTHONIOENCODING:'utf-8'};
    const state=await rpc('devices',{action:'call',deviceId:connected.deviceId,method:'device.state'});
    const cliArgs={...args,expectedDeviceRevision:state.result.stateRevision,params:{scopeRevision:state.result.scopeRevision}};
    const latest=await rpc('devices',{action:'call',deviceId:connected.deviceId,method:'scope.get'});cliArgs.params={scopeRevision:latest.result.scopeRevision,add:['com.fixture.two']} as any;
    const output=await execute('python',['-m','adh','run','devices','--arguments',JSON.stringify(cliArgs),'--endpoint',base,'--json'],{env,timeout:15000,windowsHide:true});
    const submitted=JSON.parse(String(output.stdout)).operation;
    for(let n=0;n<100&&!engine.getOperation(submitted.id).settled;n++)await pause(10);
    const op=engine.getOperation(submitted.id,true);assert.equal(op.state,'succeeded');assert.equal(op.owner,'ai');assert.equal(op.resource,resource);
    assert.deepEqual((await rpc('devices',{action:'call',deviceId:connected.deviceId,method:'scope.get'})).result.document.packages,['com.fixture.one','com.fixture.two']);
  }finally{devices.close();await new Promise<void>(r=>server.close(()=>r()));engine.close();await adb.close();await phone.close();}
});

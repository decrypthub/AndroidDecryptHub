import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {Devices} from '../src/devices.ts';
import {AdbDeviceTransport} from '../src/transport/adb_device.ts';
import {Operations,type Principal} from '../src/operations.ts';
import {describeTool} from '../src/operation_registry.ts';
import {startDeviceFixture,FakeAdb,jvmManifest,pause} from './device_fixture.ts';

const ai:Principal={role:'ai',id:'fixture-ai',source:'test'},human:Principal={role:'operator',id:'fixture-human',source:'test'};
const reason=existsSync(jvmManifest)?false:'build the offline JVM fixture with :daemon:writeDeviceRpcFixtureClasspath; no real device fallback';
const metadata=(engine:Operations,resource:string)=>{const s=engine.snapshot(resource);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
async function fixture(){
  const a=await startDeviceFixture(),b=await startDeviceFixture(),adb=new FakeAdb();adb.add('usb-A','1',a);adb.add('usb-B','2',b);
  const root=mkdtempSync(join(tmpdir(),'adh-p3-host-')),engine=new Operations(join(root,'operations'));
  const devices=new Devices(join(root,'devices.json'),new AdbDeviceTransport(adb.run),id=>engine.invalidateResource('device:'+id));
  async function execute(args:any,principal=ai,extra:any={}){const spec=describeTool('devices',args);return engine.execute(spec,args,principal,{...metadata(engine,engine.resource(spec)),...extra},async()=>{
    if(args.action==='connect')return devices.connect(args.serial,args.transportId,args.expectedDeviceId);
    if(args.action==='disconnect')return devices.disconnect(args.deviceId,args.connectionId);
    return devices.call(args);
  });}
  async function connect(serial='usb-A',transportId='1'){
    const operation=await execute({action:'connect',serial,transportId});assert.equal(operation.state,'succeeded');return engine.getOperation(operation.id,true).result;
  }
  const read=(deviceId:string,method:string,params:any={},connectionId?:string)=>devices.call({deviceId,method,params,connectionId});
  async function write(peer:any,method:string,params:any={},extra:any={},principal=ai){
    const state=await read(peer.deviceId,'device.state',{},peer.connectionId);
    return execute({action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,method,params,...extra},principal);
  }
  return {a,b,adb,root,engine,devices,execute,connect,read,write,async close(){devices.close();engine.close();await adb.close();await a.close();await b.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p3-host-')));rmSync(root,{recursive:true,force:true});}};
}

test('production Kotlin/Node protocol keeps two devices isolated and preserves scope policy', {skip:reason},async()=>{
  const f=await fixture();try{
    assert.equal(f.adb.commands.length,0,'constructors and cached list never discover devices');
    assert.equal(f.devices.list().devices.length,0);
    const a=await f.connect(),b=await f.connect('usb-B','2');assert.notEqual(a.deviceId,b.deviceId);
    assert.equal(a.identity.capabilities.methods['scope.patch'],'write');assert.equal(f.devices.list().devices.length,2);
    writeFileSync(join(f.a.root,'scope.json'),JSON.stringify({version:19,mode:'allowlist',packages:['com.fixture.old'],policy:{'com.fixture.old':{c:{h:true,future:7},future:'kept'}},future:{nested:true}}));
    const before=await f.read(a.deviceId,'scope.get'),unchanged=await f.read(b.deviceId,'scope.get');
    const done=await f.write(a,'scope.patch',{scopeRevision:before.result.scopeRevision,add:['com.fixture.new']});
    assert.equal(done.state,'succeeded');assert.equal(done.resource,'device:'+a.deviceId);
    const after=await f.read(a.deviceId,'scope.get');assert.deepEqual(after.result.document.packages,['com.fixture.new','com.fixture.old']);
    assert.deepEqual(after.result.document.policy,before.result.document.policy);assert.deepEqual(after.result.document.future,{nested:true});
    assert.equal((await f.read(b.deviceId,'scope.get')).result.scopeRevision,unchanged.result.scopeRevision);
    const wrongResource=await f.engine.execute(describeTool('devices',{action:'call',deviceId:b.deviceId,method:'scope.patch'}),{},ai,metadata(f.engine,'device:'+b.deviceId),()=>f.devices.call({deviceId:a.deviceId,method:'scope.patch',params:{},bootId:a.bootId,daemonInstanceId:a.daemonInstanceId,expectedDeviceRevision:1}));
    assert.equal(wrongResource.state,'failed');assert.equal(wrongResource.error.code,'TARGET_CHANGED');
    const stale=await f.write(a,'scope.patch',{scopeRevision:before.result.scopeRevision,set:[]});
    assert.equal(stale.state,'failed');assert.equal(f.engine.getOperation(stale.id,true).result.result.code,'STALE_SCOPE');
    const args={action:'call',deviceId:a.deviceId,connectionId:a.connectionId,bootId:a.bootId,daemonInstanceId:a.daemonInstanceId,expectedDeviceRevision:0,method:'host.set',params:{endpoint:'fixture:123'}};
    const badVersion=await f.execute(args);assert.equal(badVersion.state,'failed');assert.equal(badVersion.error.code,'STALE_DEVICE_STATE');
    assert.equal((await f.read(a.deviceId,'scope.get')).result.scopeRevision,after.result.scopeRevision);
    const cached=readFileSync(join(f.root,'devices.json'),'utf8');assert.ok(!cached.includes('"token"'));assert.ok(!cached.includes('privateKey'));
    const commands=f.adb.commands.length,reopened=new Devices(join(f.root,'devices.json'),new AdbDeviceTransport(f.adb.run));
    assert.equal(reopened.list().devices.length,2);assert.ok(reopened.list().devices.every(d=>!d.online));assert.equal(f.adb.commands.length,commands);
  }finally{await f.close();}
});

test('USB aliases retain installation identity, require explicit connections and remove only owned forwards',{skip:reason},async()=>{
  const f=await fixture();try{
    const a=await f.connect();f.adb.add('usb-replugged','3',f.a);
    const alias=await f.connect('usb-replugged','3');assert.equal(alias.deviceId,a.deviceId);assert.equal(f.devices.list().devices.length,1);
    await assert.rejects(()=>f.read(a.deviceId,'device.info'),(e:any)=>e.code==='CONNECTION_AMBIGUOUS');
    assert.equal((await f.read(a.deviceId,'device.info',{},alias.connectionId)).result.deviceId,a.deviceId);
    const b=await f.connect('usb-B','2');const bPort=[...f.adb.forwards.entries()].find(([,m])=>m.serial==='usb-B')![0];
    assert.equal((await f.execute({action:'disconnect',deviceId:a.deviceId,connectionId:a.connectionId})).state,'succeeded');
    assert.ok(f.adb.forwards.has(bPort));assert.equal(f.adb.forwards.size,2);
    // A disconnected channel remains inspectable/cleanable; it never silently fails over.
    const aliasPort=[...f.adb.forwards.entries()].find(([,m])=>m.serial==='usb-replugged')![0];f.adb.forwards.get(aliasPort)!.sockets.forEach(s=>s.destroy());await pause(40);
    await assert.rejects(()=>f.read(a.deviceId,'scope.get'),(e:any)=>e.code==='DEVICE_OFFLINE');
    assert.equal((await f.execute({action:'disconnect',deviceId:a.deviceId,connectionId:alias.connectionId})).state,'succeeded');
    assert.equal((await f.read(b.deviceId,'module.status')).result.calls,0);
    assert.ok(f.adb.commands.every(c=>!c.includes('reverse')&&!c.includes('--remove-all')&&!c.includes('install')&&!c.includes('kill-server')));
    assert.ok(f.adb.commands.filter(c=>c[0]!=='devices').every(c=>c[0]==='-t'),'every selected USB operation pins transport_id');
  }finally{await f.close();}
});

test('wrong USB credentials and identity never publish a device and clean only the created mapping',{skip:reason},async()=>{
  const f=await fixture();try{
    const b=await f.connect('usb-B','2'),count=f.adb.forwards.size;
    const accessFile=join(f.a.root,'usb-access.json'),access=readFileSync(accessFile,'utf8');
    writeFileSync(accessFile,JSON.stringify({...JSON.parse(access),token:'0'.repeat(64)}));
    const rejected=await f.execute({action:'connect',serial:'usb-A',transportId:'1'});assert.equal(rejected.state,'failed');assert.equal(rejected.error.code,'AUTH_FAILED');
    assert.equal(f.devices.list().devices.length,1);assert.equal(f.adb.forwards.size,count);writeFileSync(accessFile,access);
    const mismatch=await f.execute({action:'connect',serial:'usb-A',transportId:'1',expectedDeviceId:b.deviceId});
    assert.equal(mismatch.state,'failed');assert.equal(mismatch.error.code,'DEVICE_MISMATCH');assert.equal(f.adb.forwards.size,count);
    assert.equal((await f.read(b.deviceId,'device.state')).result.stateRevision,0);
  }finally{await f.close();}
});

test('replaced forwards are never removed and cleanup uncertainty remains visible',{skip:reason},async()=>{
  const f=await fixture();try{
    const a=await f.connect(),mapping=[...f.adb.forwards.values()][0];mapping.target='localabstract:another-owner';
    const before=f.adb.commands.filter(c=>c.includes('--remove')).length;
    const disconnected=await f.execute({action:'disconnect',deviceId:a.deviceId,connectionId:a.connectionId});
    assert.equal(disconnected.state,'unknown');assert.equal(disconnected.error.code,'FORWARD_CLEANUP_UNCONFIRMED');
    assert.equal(f.adb.commands.filter(c=>c.includes('--remove')).length,before);assert.equal(f.adb.forwards.size,1);
    assert.equal(f.devices.list().devices[0].connections[0].online,false,'retain the handle and honest closed state for inspection');
  }finally{await f.close();}
});

test('deadline after dispatch is unknown, device operation can be queried, and nothing is replayed',{skip:reason},async()=>{
  const f=await fixture();try{
    const a=await f.connect();
    const expired=await f.write(a,'process.control',{delayMs:1600},{budgetMs:300});
    assert.equal(expired.state,'unknown');assert.equal(expired.error.code,'DEVICE_RPC_TIMEOUT');
    const denied=await f.write(a,'process.control',{delayMs:0});assert.equal(denied.state,'failed');assert.equal(denied.error.code,'UNKNOWN_EXECUTION');
    const recorded=await f.read(a.deviceId,'operations.get',{operationId:expired.id});assert.equal(recorded.result.state,'succeeded');assert.equal(recorded.result.result.calls,1);
    assert.equal((await f.read(a.deviceId,'module.status')).result.calls,1);
    const observed=f.engine.getOperation(expired.id,true);assert.equal(observed.state,'unknown');assert.ok(observed.effects[0].uncertainAt);
    f.engine.control('resolve','device:'+a.deviceId,human,metadata(f.engine,'device:'+a.deviceId),true);
    assert.equal((await f.write(a,'process.control',{delayMs:0})).state,'succeeded');assert.equal((await f.read(a.deviceId,'module.status')).result.calls,2);
  }finally{await f.close();}
});

test('boot and daemon changes preserve identity and invalidate Host versions without binding legacy sessions',{skip:reason},async()=>{
  const f=await fixture();try{
    const a=await f.connect(),oldSnapshot=f.engine.snapshot('device:'+a.deviceId),key=a.identity.identityFingerprint;
    await f.a.stop();await pause(60);writeFileSync(join(f.a.root,'boot.txt'),randomUUID());
    const restarted=await startDeviceFixture(f.a.root);f.a.port=restarted.port;f.a.child=restarted.child;f.a.stop=restarted.stop;f.a.close=restarted.close;
    const current=await f.connect();assert.equal(current.deviceId,a.deviceId);assert.equal(current.identity.identityFingerprint,key);assert.notEqual(current.bootId,a.bootId);
    assert.ok(f.engine.snapshot('device:'+a.deviceId).epoch>oldSnapshot.epoch);
    const stale=await f.write(current,'process.control',{delayMs:0},{bootId:a.bootId,daemonInstanceId:a.daemonInstanceId});assert.equal(stale.state,'failed');assert.equal(stale.error.code,'TARGET_CHANGED');
    assert.equal((await f.read(current.deviceId,'module.status',{},current.connectionId)).result.calls,0);
    assert.match(f.devices.list().legacyAgentAssociation,/unverified/);
    await assert.rejects(()=>f.read('usb-A','scope.get'),(e:any)=>e.code==='DEVICE_REQUIRED');
  }finally{await f.close();}
});

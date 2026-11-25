import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,randomBytes,sign} from 'node:crypto';
import tls from 'node:tls';
import {Devices} from '../src/devices.ts';
import {AdbDeviceTransport} from '../src/transport/adb_device.ts';
import {Operations,type Principal} from '../src/operations.ts';
import {describeTool} from '../src/operation_registry.ts';
import {DeviceRpcClient,DEVICE_PROTOCOL} from '../src/device_protocol.ts';
import {startDeviceFixture,FakeAdb,jvmManifest,pause} from './device_fixture.ts';
import {canonical,digest,FAMILY_KEYS} from '../src/hook_plans.ts';

const ai:Principal={role:'ai',id:'lan-fixture',source:'test'},human:Principal={role:'operator',id:'human',source:'test'};
const skip=existsSync(jvmManifest)?false:'offline Kotlin fixture unavailable; never use a real device';

test('LAN early cache carries its grant and stops future delivery after USB authorization revocation',{skip},async()=>{
  const f=await fixture();try{const {usb,lan,grant}=await f.setup(),pkg='com.fixture.early';
    const scope=await f.one.read(usb,'scope.get');assert.equal((await f.one.write(usb,'scope.patch',{scopeRevision:scope.result.scopeRevision,add:[pkg]})).state,'succeeded');
    const plan={schemaVersion:1,id:'lan-early',title:'LAN early fixture',package:pkg,families:Object.fromEntries(FAMILY_KEYS.map(k=>[k,k==='digest'])),steps:[{id:'got',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libfixture.so',symbol:'read'}}]};
    const preview=await f.one.read(usb,'hooks.migration.preview',{package:pkg});const migration=await f.one.write(usb,'hooks.migration.apply',{package:pkg,scopeRevision:preview.result.scopeRevision,planDigest:digest(plan)});assert.equal(migration.state,'succeeded');
    const prepared=(await f.one.read(lan,'early.prepare',{package:pkg})).result;
    const staged=await f.one.write(lan,'early.stage',{plan,canonicalPlan:canonical(plan),digest:digest(plan),binding:prepared.binding,expectedCacheRevision:prepared.cacheRevision,expiresAt:Math.floor(Date.now()/1000)+3600,offline:'keep-until-expiry'});assert.equal(staged.state,'succeeded',JSON.stringify(staged));
    assert.equal(staged.result.result.result.entry.sourceGrant,grant.grantId);
    const eligible=async()=>(await f.one.read(usb,'module.status',{package:pkg,uid:prepared.binding.uid})).result.earlyEligible;assert.equal(await eligible(),true);
    assert.equal((await f.one.write(usb,'pairings.revoke',{grantId:grant.grantId})).state,'succeeded');assert.equal(await eligible(),false);
    assert.equal((await f.one.read(usb,'early.status',{package:pkg})).result.entry.state,'validated-cache','historical staging state must not claim runtime installation or renewed authorization');
  }finally{await f.close();}
});
const meta=(engine:Operations,resource:string)=>{const s=engine.snapshot(resource);return {expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch};};
async function fixture(){
  const phone=await startDeviceFixture(),adb=new FakeAdb();adb.add('usb-TLS','1',phone);
  const root=mkdtempSync(join(tmpdir(),'adh-p4-lan-'));let adbEnabled=true,forbiddenAdb=0;
  const hosts:{devices:Devices;engine:Operations}[]=[];
  function host(name='one'){
    const engine=new Operations(join(root,name,'operations'));
    const devices=new Devices(join(root,name,'devices.json'),new AdbDeviceTransport(async(args,o)=>{if(!adbEnabled){forbiddenAdb++;throw Error('ADB REMOVED');}return adb.run(args,o);}),id=>engine.invalidateResource('device:'+id));
    hosts.push({devices,engine});
    const read=(peer:any,method:string,params:any={})=>devices.call({deviceId:peer.deviceId,connectionId:peer.connectionId,method,params});
    async function execute(args:any,principal=ai,extra:any={}){const spec=describeTool('devices',args);return engine.execute(spec,args,principal,{...meta(engine,engine.resource(spec)),...extra},async()=>{
      if(args.action==='connect')return args.transport==='lan'?devices.connectLan(args.deviceId,args.address,args.port):devices.connect('usb-TLS','1');
      if(args.action==='disconnect')return devices.disconnect(args.deviceId,args.connectionId);
      if(args.action==='pair')return devices.pair(args);return devices.call(args);
    });}
    async function connect(deviceId?:string,port?:number){const op=await execute(deviceId?{action:'connect',transport:'lan',deviceId,address:'127.0.0.1',port}:{action:'connect',transport:'adb',serial:'usb-TLS',transportId:'1'});assert.equal(op.state,'succeeded',JSON.stringify(op.error));return op.result;}
    async function write(peer:any,method:string,params:any={},options:any={},principal=ai){const state=await read(peer,'device.state');return execute({action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,method,params,...options},principal);}
    async function pair(peer:any,permissions=['read','write','manage']){const state=await read(peer,'device.state');const op=await execute({action:'pair',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,permissions});assert.equal(op.state,'succeeded',JSON.stringify(op));return op.result.result.result;}
    return {devices,engine,read,write,connect,execute,pair};
  }
  const one=host();
  async function setup(){const usb=await one.connect();const configured=await one.write(usb,'lan.configure',{enabled:true,address:'127.0.0.1',port:0});assert.equal(configured.state,'succeeded',JSON.stringify(configured));const port=configured.result.result.result.port;const grant=await one.pair(usb);const lan=await one.connect(usb.deviceId,port);return {usb,lan,port,grant};}
  async function restart(){await phone.stop();await pause(50);const next=await startDeviceFixture(phone.root);Object.assign(phone,next);return next;}
  return {root,phone,adb,one,host,setup,restart,disableAdb(){adbEnabled=false;},get forbiddenAdb(){return forbiddenAdb;},async close(){for(const h of hosts){h.devices.close();h.engine.close();}await adb.close();await phone.close();assert.ok(root.startsWith(join(tmpdir(),'adh-p4-lan-')));rmSync(root,{recursive:true,force:true});}};
}

test('real Kotlin TLS and USB share identity, capabilities, scope/process/certificate/host methods without ADB fallback',{skip},async()=>{
  const f=await fixture();try{
    const {usb,lan}=await f.setup();assert.equal(lan.deviceId,usb.deviceId);assert.equal(lan.bootId,usb.bootId);assert.match(lan.tlsVersion,/^TLSv1\.[23]$/);
    assert.deepEqual(lan.identity.capabilities.methods,usb.identity.capabilities.methods);assert.equal(f.one.devices.list().devices.length,1);
    await assert.rejects(()=>f.one.devices.call({deviceId:usb.deviceId,method:'scope.get'}),(e:any)=>e.code==='CONNECTION_AMBIGUOUS');
    assert.equal((await f.one.execute({action:'disconnect',deviceId:usb.deviceId,connectionId:usb.connectionId})).state,'succeeded');
    f.disableAdb();
    for(const method of ['device.info','device.capabilities','module.status','applications.list','applications.icon','processes.list','certificates.list','host.get','lan.status'])assert.equal((await f.one.read(lan,method)).ok,true);
    const scope=await f.one.read(lan,'scope.get');assert.equal((await f.one.write(lan,'scope.patch',{scopeRevision:scope.result.scopeRevision,add:['com.fixture.lan']})).state,'succeeded');
    assert.equal((await f.one.write(lan,'host.set',{endpoint:'192.0.2.1:8761'})).state,'succeeded');assert.equal((await f.one.read(lan,'host.get')).result.endpoint,'192.0.2.1:8761');
    assert.equal((await f.one.write(lan,'certificates.put',{base64:'fixture'})).state,'succeeded');assert.equal((await f.one.read(lan,'certificates.list')).result.certificates.length,1);
    assert.equal((await f.one.write(lan,'certificates.delete',{fileName:'00000000.0'})).state,'succeeded');
    assert.equal((await f.one.write(lan,'process.control',{delayMs:0})).state,'succeeded');assert.equal((await f.one.read(lan,'module.status')).result.calls,1);
    for(const method of ['agent.hook','fs.read','diagnostics','root.helper','bulk.read'])await assert.rejects(()=>f.one.devices.call({deviceId:lan.deviceId,connectionId:lan.connectionId,method}),(e:any)=>e.code==='UNSUPPORTED_METHOD');
    assert.equal(f.forbiddenAdb,0);assert.ok(!JSON.stringify(f.one.devices.list()).includes('privateKey'));
    const credentials=JSON.parse(readFileSync(f.one.devices.clientIdentity.file,'utf8'));assert.ok(!JSON.stringify(f.one.engine.list()).includes(credentials.privateKey));
    const restored=f.host('one');assert.equal(restored.devices.list().devices[0].online,false);assert.ok(restored.devices.list().devices[0].lanEndpoint);assert.equal(restored.devices.clientIdentity.read().clientId,credentials.clientId);
    assert.equal((await restored.connect(lan.deviceId)).deviceId,lan.deviceId);assert.equal(f.forbiddenAdb,0);
  }finally{await f.close();}
});

test('lost TLS response is reconciled on a new channel, remains unknown and never executes twice',{skip},async()=>{
  const f=await fixture();try{
    const {usb,lan,port}=await f.setup();await f.one.execute({action:'disconnect',deviceId:usb.deviceId,connectionId:usb.connectionId});f.disableAdb();
    const state=await f.one.read(lan,'device.state');
    const running=f.one.execute({action:'call',deviceId:lan.deviceId,connectionId:lan.connectionId,bootId:lan.bootId,daemonInstanceId:lan.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,method:'process.control',params:{delayMs:900}});
    for(let n=0;n<200&&!existsSync(join(f.phone.root,'dispatch-count.txt'));n++)await pause(5);assert.ok(existsSync(join(f.phone.root,'dispatch-count.txt')));
    (f.one.devices as any).connections.get(lan.connectionId).rpc.stream.destroy();const unknown=await running;assert.equal(unknown.state,'unknown');
    const next=await f.one.connect(lan.deviceId,port); // recovery is allowed while this device is quarantined
    const observed=await f.one.devices.reconcile(next.deviceId,[unknown.id,'not-recorded'],next.connectionId);
    assert.equal(observed.result.operations[0].state,'succeeded');assert.equal(observed.result.operations[0].result.calls,1);assert.equal(observed.result.operations[1].found,false);assert.equal(observed.result.notFoundDoesNotProveUnsent,true);
    const updated=f.one.engine.recordDeviceReconciliation(unknown.id,next.deviceId,observed.result.operations[0]);assert.equal(updated.state,'unknown');assert.equal(updated.reconciliations.length,1);assert.ok(f.one.engine.snapshot('device:'+next.deviceId).uncertain);
    const blocked=await f.one.write(next,'process.control',{delayMs:0});assert.equal(blocked.error.code,'UNKNOWN_EXECUTION');assert.equal(readFileSync(join(f.phone.root,'dispatch-count.txt'),'utf8'),'1');
    assert.equal(f.forbiddenAdb,0);
  }finally{await f.close();}
});

test('read-only grants deny writes; revocation closes established streams and survives daemon restart',{skip},async()=>{
  const f=await fixture();try{
    const {usb,port}=await f.setup(),two=f.host('two'),usb2=await two.connect(),grant2=await two.pair(usb2,['read']),lan2=await two.connect(usb2.deviceId,port);
    assert.equal((await two.read(lan2,'scope.get')).ok,true);const denied=await two.write(lan2,'process.control',{delayMs:0});assert.equal(denied.error.code,'PERMISSION_DENIED');
    const revoked=await f.one.write(usb,'pairings.revoke',{grantId:grant2.grantId});assert.equal(revoked.state,'succeeded');await pause(50);
    await assert.rejects(()=>two.read(lan2,'scope.get'),(e:any)=>e.code==='DEVICE_OFFLINE');
    const reconnect=await two.execute({action:'connect',transport:'lan',deviceId:usb2.deviceId,address:'127.0.0.1',port});assert.equal(reconnect.state,'failed');assert.equal(reconnect.error.code,'AUTH_FAILED');
    const next=await f.restart();const after=await two.execute({action:'connect',transport:'lan',deviceId:usb2.deviceId,address:'127.0.0.1',port:next.lanPort});assert.equal(after.state,'failed');assert.equal(after.error.code,'AUTH_FAILED');
  }finally{await f.close();}
});

test('TLS pins reject another device and plaintext; a client proof cannot be replayed on a fresh TLS challenge',{skip},async()=>{
  const f=await fixture(),other=await fixture();try{
    const {usb,port,grant}=await f.setup(),second=await other.setup();
    const wrong=await f.one.execute({action:'connect',transport:'lan',deviceId:usb.deviceId,address:'127.0.0.1',port:second.port});assert.equal(wrong.error.code,'TLS_IDENTITY_MISMATCH');
    const plain=await f.one.execute({action:'connect',transport:'lan',deviceId:usb.deviceId,address:'127.0.0.1',port:f.phone.port});assert.equal(plain.error.code,'TLS_FAILED');
    const identity=f.one.devices.clientIdentity.read();
    async function raw(){const socket=await new Promise<tls.TLSSocket>((resolve,reject)=>{const s=tls.connect({host:'127.0.0.1',port,rejectUnauthorized:false,minVersion:'TLSv1.2',maxVersion:'TLSv1.2'},()=>resolve(s));s.once('error',reject);});return new DeviceRpcClient(socket);}
    const first=await raw(),challenge=await first.request('device.challenge',{}),id=randomUUID(),nonce=randomBytes(32).toString('hex');
    const payload=JSON.stringify([DEVICE_PROTOCOL,'lan-auth/1',challenge.deviceId,challenge.bootId,challenge.daemonInstanceId,challenge.challenge,nonce,id,identity.clientId,grant.grantId]);
    const authentication={type:'client-signature',clientId:identity.clientId,grantId:grant.grantId,signature:sign('sha256',Buffer.from(payload),identity.privateKey).toString('base64')};
    await first.request('device.hello',{clientNonce:nonce,authentication},undefined,undefined,5000,id);first.close();
    const replay=await raw();await replay.request('device.challenge',{});
    await assert.rejects(()=>replay.request('device.hello',{clientNonce:nonce,authentication},undefined,undefined,5000,id),(e:any)=>e.code==='AUTH_FAILED');replay.close();
    const usbToken=JSON.parse(readFileSync(join(f.phone.root,'usb-access.json'),'utf8')).token;
    const wrongAuth=await raw();await wrongAuth.request('device.challenge',{});
    await assert.rejects(()=>wrongAuth.request('device.hello',{clientNonce:nonce,authentication:{type:'usb-token',credential:usbToken}}),(e:any)=>e.code==='AUTH_FAILED');wrongAuth.close();
  }finally{await f.close();await other.close();}
});

test('device crash leaves a durable unknown reservation; LAN restart and repeated reads do not replay effects',{skip},async()=>{
  const f=await fixture();try{
    const {usb,lan}=await f.setup();await f.one.execute({action:'disconnect',deviceId:usb.deviceId,connectionId:usb.connectionId});f.disableAdb();
    const state=await f.one.read(lan,'device.state');const work=f.one.execute({action:'call',deviceId:lan.deviceId,connectionId:lan.connectionId,bootId:lan.bootId,daemonInstanceId:lan.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,method:'process.control',params:{delayMs:5000}});
    for(let n=0;n<200&&!existsSync(join(f.phone.root,'dispatch-count.txt'));n++)await pause(5);assert.ok(existsSync(join(f.phone.root,'dispatch-count.txt')));
    await f.phone.stop();const unknown=await work;assert.equal(unknown.state,'unknown');const next=await f.restart();const restored=await f.one.connect(lan.deviceId,next.lanPort);
    for(let n=0;n<2;n++){const facts=await f.one.devices.reconcile(restored.deviceId,[unknown.id],restored.connectionId);assert.equal(facts.result.operations[0].state,'unknown');assert.equal(facts.result.operations[0].code,'DAEMON_RESTARTED');}
    assert.equal(readFileSync(join(f.phone.root,'dispatch-count.txt'),'utf8'),'1');assert.equal(f.forbiddenAdb,0);
    // Revocation is a security reduction, so it is still possible under both quarantines.
    const grant=f.one.devices.list().devices[0].pairing!;
    const old=meta(f.one.engine,'device:'+restored.deviceId);
    const revoked=await f.one.write(restored,'pairings.revoke',{grantId:grant.grantId});assert.equal(revoked.state,'unknown','self-revocation closes the response stream; never fabricate an ack');
    const controls=f.one.engine.snapshot('device:'+restored.deviceId);assert.equal(controls.uncertainOperations.length,2);
    assert.throws(()=>f.one.engine.control('resolve','device:'+restored.deviceId,human,old,true),/changed/);
    f.one.engine.control('resolve','device:'+restored.deviceId,human,meta(f.one.engine,'device:'+restored.deviceId),true);
    assert.ok(f.one.engine.getOperation(unknown.id).resolvedAt);assert.ok(f.one.engine.getOperation(revoked.id).resolvedAt);assert.equal(f.one.engine.getOperation(unknown.id).state,'unknown');
  }finally{await f.close();}
});

test('explicit human resolution on LAN preserves both unknown histories and permits only a fresh later intent',{skip},async()=>{
  const f=await fixture();try{
    const {usb,lan}=await f.setup();await f.one.execute({action:'disconnect',deviceId:usb.deviceId,connectionId:usb.connectionId});f.disableAdb();
    const state=await f.one.read(lan,'device.state');const work=f.one.execute({action:'call',deviceId:lan.deviceId,connectionId:lan.connectionId,bootId:lan.bootId,daemonInstanceId:lan.daemonInstanceId,expectedDeviceRevision:state.result.stateRevision,method:'process.control',params:{delayMs:5000}});
    for(let n=0;n<200&&!existsSync(join(f.phone.root,'dispatch-count.txt'));n++)await pause(5);assert.ok(existsSync(join(f.phone.root,'dispatch-count.txt')));
    await f.phone.stop();const unknown=await work,next=await f.restart(),restored=await f.one.connect(lan.deviceId,next.lanPort),resource='device:'+lan.deviceId;
    const evidence=await f.one.devices.reconcile(restored.deviceId,[unknown.id],restored.connectionId);assert.equal(evidence.result.operations[0].state,'unknown');
    f.one.engine.control('resolve',resource,human,meta(f.one.engine,resource),true);
    const aiResolve=await f.one.write(restored,'operations.resolve',{operationId:unknown.id,acknowledge:true});assert.equal(aiResolve.error.code,'OPERATOR_REQUIRED');
    const manual=await f.one.write(restored,'operations.resolve',{operationId:unknown.id,acknowledge:true},{},human);assert.equal(manual.state,'succeeded');
    const held=await f.one.write(restored,'process.control',{delayMs:0}).catch((error:any)=>({error}));assert.equal(held.error.code,'CONTROL_HELD');
    f.one.engine.control('release',resource,human,meta(f.one.engine,resource));
    assert.equal((await f.one.write(restored,'process.control',{delayMs:0})).state,'succeeded');assert.equal(readFileSync(join(f.phone.root,'dispatch-count.txt'),'utf8'),'2');
    const original=await f.one.read(restored,'operations.get',{operationId:unknown.id});assert.equal(original.result.state,'unknown');assert.ok(original.result.resolvedAt);
    assert.equal(f.one.engine.getOperation(unknown.id).state,'unknown');assert.ok(f.one.engine.getOperation(unknown.id).resolvedAt);assert.equal(f.forbiddenAdb,0);
  }finally{await f.close();}
});

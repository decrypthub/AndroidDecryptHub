import test from 'node:test';
import assert from 'node:assert/strict';
import {Duplex} from 'node:stream';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {parseAdbDevices} from '../src/transport/adb_device.ts';
import {DEVICE_PROTOCOL,DeviceRpcClient,deviceFrame,parseBootstrap,verifyHello,deviceMethodMode} from '../src/device_protocol.ts';
import {describeTool} from '../src/operation_registry.ts';

test('discovery retains offline/unauthorized states and transport identity without guessing a device id',()=>{
  const values=parseAdbDevices('List of devices attached\nusb-A device usb:1-1 model:Phone transport_id:9\n192.0.2.1:5555 device model:Phone transport_id:10\nusb-B unauthorized transport_id:11\nusb-C offline transport_id:12');
  assert.equal(values.length,4);assert.equal(values[0].transportId,'9');assert.equal(values[1].link,'adb-tcp');assert.equal(values[2].state,'unauthorized');assert.equal(values[3].state,'offline');assert.ok(values.every(v=>!('deviceId' in v)));
});

test('signed hello binds the root bootstrap key, device, nonce and capability effects',()=>{
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048}),der=publicKey.export({format:'der',type:'spki'}) as Buffer;
  const bootstrap={schemaVersion:1 as const,deviceId:'00000000-0000-4000-8000-000000000001',identityFingerprint:createHash('sha256').update(der).digest('hex'),token:'a'.repeat(64)};
  const peer={protocol:DEVICE_PROTOCOL,requestId:'hello',clientNonce:'b'.repeat(64),deviceId:bootstrap.deviceId,bootId:'00000000-0000-4000-8000-000000000002',daemonInstanceId:'00000000-0000-4000-8000-000000000003',identityFingerprint:bootstrap.identityFingerprint,capabilities:{methods:{'scope.get':'read'}},info:{}};
  const payload=Buffer.from(JSON.stringify(peer)),reply={publicKey:der.toString('base64'),payload:payload.toString('base64'),signature:sign('sha256',payload,privateKey).toString('base64')};
  assert.equal(verifyHello(reply,bootstrap,'hello','b'.repeat(64)).deviceId,bootstrap.deviceId);
  assert.throws(()=>verifyHello(reply,bootstrap,'hello','c'.repeat(64)),(e:any)=>e.code==='IDENTITY_UNVERIFIED');
  assert.throws(()=>verifyHello({...reply,payload:Buffer.from('{}').toString('base64')},bootstrap,'hello','b'.repeat(64)));
  assert.throws(()=>parseBootstrap('{"token":"synthetic-private-value"}'),e=>!String(e).includes('synthetic-private-value'));
  assert.throws(()=>parseBootstrap('null'),(e:any)=>e.code==='INVALID_BOOTSTRAP');
});

test('device methods are exact effect capabilities; arbitrary shell and disguised writes are rejected',()=>{
  assert.equal(deviceMethodMode('scope.get'),'read');assert.equal(deviceMethodMode('scope.patch'),'write');
  assert.equal(describeTool('devices',{action:'call',deviceId:'d',method:'process.control'}).mode,'write');
  assert.throws(()=>deviceMethodMode('shell'),(e:any)=>e.code==='UNSUPPORTED_METHOD');
  assert.throws(()=>describeTool('devices',{action:'call',method:'native_hook_all',status:'read'}));
});

function wire(){let stream:Duplex;const frames:any[]=[];stream=new Duplex({read(){},write(data,_,done){frames.push(JSON.parse(data.subarray(4).toString()));done();}});return {stream,frames};}
test('fragmented replies and out-of-order ids are decoded once without replaying writes',async()=>{
  const w=wire(),rpc=new DeviceRpcClient(w.stream);
  await assert.rejects(()=>rpc.request('device.info',{},undefined,undefined,NaN),(e:any)=>e.code==='INVALID_ARGUMENT');assert.equal(w.frames.length,0);
  const a=rpc.request('device.info',{},undefined,undefined,1000,'one'),b=rpc.request('scope.get',{},undefined,undefined,1000,'two');
  const frame=deviceFrame({protocol:DEVICE_PROTOCOL,id:'two',ok:true,result:{value:2}});w.stream.push(frame.subarray(0,2));w.stream.push(frame.subarray(2));
  w.stream.push(deviceFrame({protocol:DEVICE_PROTOCOL,id:'one',ok:true,result:{value:1}}));
  assert.equal((await a).value,1);assert.equal((await b).value,2);assert.equal(w.frames.length,2);rpc.close();
});
test('post-dispatch deadline is uncertain; oversized frames close pending calls instead of fabricating cancellation',async()=>{
  const w=wire(),rpc=new DeviceRpcClient(w.stream);
  await assert.rejects(()=>rpc.request('process.control',{},undefined,{},30,'write'),(e:any)=>e.uncertain===true&&e.code==='DEVICE_RPC_TIMEOUT');
  assert.equal(w.frames.length,1);
  const pending=rpc.request('device.info',{},undefined,undefined,1000,'read');const header=Buffer.alloc(4);header.writeUInt32BE(1024*1024+1);w.stream.push(header);
  await assert.rejects(()=>pending,(e:any)=>e.code==='FRAME_LIMIT');rpc.close();
});

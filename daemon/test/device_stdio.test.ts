import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {Duplex,Transform} from 'node:stream';
import {existsSync,readFileSync,writeFileSync} from 'node:fs';
import {join,delimiter} from 'node:path';
import {AdbDeviceTransport} from '../src/transport/adb_device.ts';
import {startDeviceFixture,FakeAdb,jvmManifest} from './device_fixture.ts';

test('USB stdio authenticates the production Kotlin dispatcher and carries large binary-framed replies without forwards',{skip:existsSync(jvmManifest)?false:'build offline JVM fixture; no real device fallback'},async()=>{
  const phone=await startDeviceFixture(),adb=new FakeAdb();adb.add('stdio-fixture','77',phone);const opens:string[][]=[];let connection:any;
  const runner=async(args:string[])=>args.slice(2).join(' ')==='exec-out su --help'?'KernelSU --no-wrapper':adb.run(args);
  const adapter=new AdbDeviceTransport(runner,async()=>{throw Error('stdio must never dial a forward');},args=>{
    opens.push(args);const cp=JSON.parse(readFileSync(jvmManifest,'utf8'));
    const child=spawn(process.env.JAVA_HOME?join(process.env.JAVA_HOME,'bin','java.exe'):'java',['-cp',cp.join(delimiter),'com.adh.daemon.device.DeviceStdioFixture',String(phone.port)],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    // Reproduce the measured Windows adb stdout LF expansion, including split byte streams.
    const output=new Transform({transform(chunk,_encoding,done){this.push(Buffer.from(chunk.toString('ascii').replaceAll('\n','\r\n')));done();}});child.stdout.pipe(output);child.stderr.resume();
    const stream=Duplex.from({readable:output,writable:child.stdin});child.on('error',e=>stream.destroy(e));child.on('close',()=>stream.destroy());stream.on('close',()=>{if(child.exitCode===null)child.kill();});return stream;
  });
  try{
    connection=await adapter.connect('stdio-fixture','77',undefined,'stdio');assert.equal(connection.usbMode,'stdio');assert.equal(connection.peer.deviceId,phone.deviceId);assert.ok(opens[0].includes('-W'));assert.ok(opens[0].includes('-T'));assert.ok(opens[0].at(-1)!.includes('com.adh.daemon.device.DeviceRpcRelay --base64'));
    writeFileSync(join(phone.root,'scope.json'),JSON.stringify({version:19,mode:'allowlist',packages:[],future:'\r\n\u0003'.repeat(12000)}));
    const peer=connection.peer;const reply=await connection.rpc.request('scope.get',{},{deviceId:peer.deviceId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId});assert.equal(reply.future,undefined);assert.equal(reply.document.future.length,36000);assert.equal(adb.forwards.size,0);assert.ok(!adb.commands.some(c=>c.includes('forward')));
    assert.equal((await connection.close()).confirmed,true);connection=undefined;
    const file=join(phone.root,'usb-access.json'),legacy=JSON.parse(readFileSync(file,'utf8'));legacy.stdioVersion=1;writeFileSync(file,JSON.stringify(legacy));
    await assert.rejects(()=>adapter.connect('stdio-fixture','77',undefined,'stdio'),(e:any)=>e.code==='UNSUPPORTED_TRANSPORT');assert.equal(opens.length,1,'legacy devices never silently fall back or start a relay');
  }finally{if(connection)await connection.close();await adb.close();await phone.close();}
});

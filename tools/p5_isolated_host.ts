// Private test Host. The adapter translates only bootstrap/socket names into its own namespace.
import {execFile,spawn} from 'node:child_process';
import {Duplex} from 'node:stream';
import {promisify} from 'node:util';
import {join} from 'node:path';
const [serial,transport,remote,socket,root]=process.argv.slice(2);
if(!serial||!/^\d+$/.test(transport)||!/^\/data\/local\/tmp\/adh-p5-[a-f0-9]{12}$/.test(remote)||!/^adh_p5_[a-f0-9]{12}$/.test(socket)||!root)throw Error('explicit isolated Host arguments required');
process.env.ADH_DATA_DIR=root;process.env.ADH_SKIP_ARTIFACT_LOAD='1';process.env.ANDROID_SERIAL=serial;process.env.ADH_HTTP_PORT='18088';process.env.ADH_AGENT_PORT='18761';delete process.env.ADH_CAPTURES_DIR;
const {Devices}=await import('../daemon/src/devices.ts');const {AdbDeviceTransport}=await import('../daemon/src/transport/adb_device.ts');const {setDevicesForTests}=await import('../daemon/src/device_host.ts');const {DEVICE_BOOTSTRAP,DEVICE_SOCKET}=await import('../daemon/src/device_protocol.ts');
const exec=promisify(execFile),adb=process.env.ADH_ADB_PATH||'adb';
const run=async(args:string[])=>{
  if(args.join(' ')==='devices -l')return (await exec(adb,args,{windowsHide:true})).stdout;
  if(args[0]!=='-t'||args[1]!==transport)throw Error('unselected device command rejected');
  if(args.slice(2).join(' ')==='exec-out su --help')return (await exec(adb,args,{windowsHide:true})).stdout;
  if(args[2]==='exec-out'&&args[3]==='su'&&args[4]==='-c'&&args[5]==='cat '+DEVICE_BOOTSTRAP)args=[...args.slice(0,5),'cat '+remote+'/domain/usb-access.json'];
  else if(args[2]==='forward'&&args.includes('localabstract:'+DEVICE_SOCKET))args=args.map(a=>a==='localabstract:'+DEVICE_SOCKET?'localabstract:'+socket:a);
  else if(args[2]!=='forward'||!['--list','--remove'].includes(args[3]))throw Error('fixture allows only owned forwarding and bootstrap reads');
  const output=(await exec(adb,args,{windowsHide:true,timeout:10000})).stdout;return output.replaceAll('localabstract:'+socket,'localabstract:'+DEVICE_SOCKET);
};
const stdio=(args:string[])=>{if(args[0]!=='-t'||args[1]!==transport||args[2]!=='shell'||args[3]!=='-T'||args[4]!=='su')throw Error('invalid stdio request');const command=`CLASSPATH=${remote}/daemon.apk app_process /system/bin --nice-name=adh-p5-usb-relay com.adh.daemon.device.DeviceRpcRelay --base64 ${socket}`;const child=spawn(adb,[...args.slice(0,-1),"'"+command+"'"],{windowsHide:true,stdio:['pipe','pipe','pipe']});const stream=Duplex.from({readable:child.stdout,writable:child.stdin});child.stderr.resume();child.on('error',error=>stream.destroy(error));child.on('close',()=>stream.destroy());stream.on('close',()=>{if(child.exitCode===null)child.kill();});return stream;};
setDevicesForTests(new Devices(join(root,'devices.json'),new AdbDeviceTransport(run,undefined,stdio)));
await import('../daemon/src/index.ts');

// Read-only cumulative ring metadata for the opt-in acceptance runner, never capture payloads.
const {capStats}=await import('../daemon/src/state.ts');
const {writeFileSync,renameSync}=await import('node:fs');
setInterval(()=>{const path=join(root,'p5-capture-health.json');writeFileSync(path+'.tmp',JSON.stringify({at:Date.now(),sessions:Object.fromEntries(capStats)}));renameSync(path+'.tmp',path);},300).unref();

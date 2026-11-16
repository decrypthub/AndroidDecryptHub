import {spawn} from 'node:child_process';
import {mkdtempSync,readFileSync,existsSync,unlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,delimiter,resolve,dirname,basename} from 'node:path';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import {DeviceError,DEVICE_BOOTSTRAP,DEVICE_SOCKET} from '../src/device_protocol.ts';
import type {AdbRunner} from '../src/transport/adb_device.ts';

export const jvmManifest=process.env.ADH_DEVICE_JVM_FIXTURE||fileURLToPath(new URL('../../device/daemon/build/device-rpc-fixture-classpath.json',import.meta.url));
export const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
function checkedRoot(root:string){const path=resolve(root);if(dirname(path)!==resolve(tmpdir())||!basename(path).startsWith('adh-p3-jvm-'))throw Error('unsafe fixture directory');return path;}
export async function startDeviceFixture(existingRoot?:string){
  const root=checkedRoot(existingRoot||mkdtempSync(join(tmpdir(),'adh-p3-jvm-')));
  const ready=join(root,'ready.json');if(existsSync(ready))unlinkSync(ready);
  const cp=JSON.parse(readFileSync(jvmManifest,'utf8')) as string[];
  const child=spawn(process.env.JAVA_HOME?join(process.env.JAVA_HOME,'bin','java.exe'):'java',['-cp',cp.join(delimiter),'com.adh.daemon.device.DeviceRpcFixture',root],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  let failure='';child.stderr?.on('data',chunk=>{failure=(failure+chunk).slice(-4000);});child.on('error',e=>{failure=e.message;});
  let metadata:any;
  for(let n=0;n<300;n++){if(child.exitCode!==null)throw Error('JVM fixture exited: '+failure);if(existsSync(ready)){try{metadata=JSON.parse(readFileSync(ready,'utf8'));break;}catch{}}await pause(50);}
  if(!metadata){child.kill();throw Error('JVM fixture did not become ready: '+failure);}
  const stop=async()=>{if(child.exitCode===null){const done=new Promise<void>(r=>child.once('exit',()=>r()));child.kill();await done;}};
  return {root,port:metadata.port as number,deviceId:metadata.deviceId as string,child,stop,async close(){await stop();rmSync(checkedRoot(root),{recursive:true,force:true});}};
}
type Fixture=Awaited<ReturnType<typeof startDeviceFixture>>;
export class FakeAdb {
  endpoints=new Map<string,{serial:string;transportId:string;fixture:Fixture;state:string}>();
  forwards=new Map<number,{serial:string;target:string;server:net.Server;sockets:Set<net.Socket>}>();
  commands:string[][]=[];
  add(serial:string,transportId:string,fixture:Fixture,state='device'){this.endpoints.set(transportId,{serial,transportId,fixture,state});}
  run:AdbRunner=async(args)=>{
    this.commands.push([...args]);
    if(args.join(' ')==='devices -l')return 'List of devices attached\n'+[...this.endpoints.values()].map(e=>`${e.serial}\t${e.state} usb:1-${e.transportId} model:Fixture transport_id:${e.transportId}`).join('\n');
    const entry=args[0]==='-t'?this.endpoints.get(args[1]):[...this.endpoints.values()].find(e=>e.serial===args[1]);
    if(!entry||entry.state!=='device')throw new DeviceError('ADB_FAILED','synthetic stale/offline transport');
    const rest=args.slice(2);
    if(rest.join(' ')==='exec-out su -c cat '+DEVICE_BOOTSTRAP)return readFileSync(join(entry.fixture.root,'usb-access.json'),'utf8');
    if(rest.join(' ')==='forward --no-rebind tcp:0 localabstract:'+DEVICE_SOCKET){
      const sockets=new Set<net.Socket>();
      const server=net.createServer(local=>{const remote=net.connect(entry.fixture.port,'127.0.0.1');sockets.add(local);sockets.add(remote);local.pipe(remote).pipe(local);local.on('close',()=>{remote.destroy();sockets.delete(local);sockets.delete(remote);});local.on('error',()=>remote.destroy());remote.on('error',()=>local.destroy());});
      await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as net.AddressInfo).port;
      this.forwards.set(port,{serial:entry.serial,target:'localabstract:'+DEVICE_SOCKET,server,sockets});return String(port);
    }
    if(rest.join(' ')==='forward --list')return [...this.forwards.entries()].map(([p,f])=>`${f.serial} tcp:${p} ${f.target}`).join('\n');
    if(rest[0]==='forward'&&rest[1]==='--remove'){
      const port=Number(rest[2].slice(4)),mapping=this.forwards.get(port);if(!mapping||mapping.serial!==entry.serial)throw Error('wrong synthetic forward removal');
      mapping.sockets.forEach(s=>s.destroy());await new Promise<void>(r=>mapping.server.close(()=>r()));this.forwards.delete(port);return '';
    }
    throw Error('FORBIDDEN device command in fixture: '+args.join(' '));
  };
  async close(){for(const mapping of this.forwards.values()){mapping.sockets.forEach(s=>s.destroy());await new Promise<void>(r=>mapping.server.close(()=>r()));}this.forwards.clear();}
}

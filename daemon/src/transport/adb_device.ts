import { execFile,spawn } from 'node:child_process';
import { Duplex } from 'node:stream';
import { promisify } from 'node:util';
import net from 'node:net';
import { randomBytes,randomUUID } from 'node:crypto';
import { DEVICE_BOOTSTRAP,DEVICE_SOCKET,DEVICE_STDIO_COMMAND,DeviceRpcClient,parseBootstrap,verifyHello,deviceFail,DeviceError,type DevicePeer } from '../device_protocol.ts';
import { checkpoint,executionContext } from '../execution_context.ts';
import type {DeviceConnection} from './device_transport.ts';

export interface AdbDevice {serial:string;state:string;transportId?:string;model?:string;link:'usb'|'adb-tcp'|'unknown'}
export type AdbRunner=(args:string[],options?:{timeout?:number;maxBuffer?:number})=>Promise<string>;
export type AdbStdio=(args:string[])=>Duplex;
export const realAdbStdio:AdbStdio=args=>{
  if(process.env.ADH_SKIP_ARTIFACT_LOAD==='1')deviceFail('TEST_ADAPTER_REQUIRED','tests must inject a stdio adapter');
  const child=spawn(process.env.ADH_ADB_PATH||'adb',args,{windowsHide:true,stdio:['pipe','pipe','pipe']});
  const stream=Duplex.from({readable:child.stdout,writable:child.stdin});child.stderr.resume();child.on('error',()=>stream.destroy(new DeviceError('ADB_FAILED','USB stdio relay failed')));child.on('close',()=>stream.destroy());stream.on('close',()=>{if(child.exitCode===null)child.kill();});return stream;
};
const exec=promisify(execFile);
export const realAdbRunner:AdbRunner=async(args,options={})=>{
  if(process.env.ADH_SKIP_ARTIFACT_LOAD==='1')deviceFail('TEST_ADAPTER_REQUIRED','tests must inject an ADB adapter; real devices are forbidden');
  try{return (await exec(process.env.ADH_ADB_PATH||'adb',args,{timeout:options.timeout||10000,maxBuffer:options.maxBuffer||65536,windowsHide:true})).stdout;}
  catch(error){throw new DeviceError('ADB_FAILED','ADB request failed; command output and credentials are not logged',(error as any).killed===true);}
};
export function parseAdbDevices(raw:string):AdbDevice[]{
  const rows:AdbDevice[]=[];
  for(const line of raw.split(/\r?\n/)){const parts=line.trim().split(/\s+/);if(parts.length<2||line.startsWith('List of devices')||line.startsWith('*'))continue;
    const [serial,state,...values]=parts;if(!/^[A-Za-z0-9_.:[\]-]{1,200}$/.test(serial))continue;
    const props=Object.fromEntries(values.map(p=>{const i=p.indexOf(':');return [p.slice(0,i),p.slice(i+1)];}));
    rows.push({serial,state,transportId:/^\d+$/.test(props.transport_id||'')?props.transport_id:undefined,model:props.model,link:props.usb?'usb':serial.includes(':')?'adb-tcp':'unknown'});
  }return rows;
}
export interface AdbConnection extends DeviceConnection {transport:'adb';serial:string}
export class AdbDeviceTransport {
  readonly run:AdbRunner;private dial:(port:number)=>Promise<net.Socket>;private stdio:AdbStdio;
  constructor(run:AdbRunner=realAdbRunner,dial:(port:number)=>Promise<net.Socket>=port=>new Promise((resolve,reject)=>{
    const socket=net.connect({host:'127.0.0.1',port});const timer=setTimeout(()=>socket.destroy(new Error('connect timeout')),5000);socket.once('connect',()=>{clearTimeout(timer);resolve(socket);});socket.once('error',error=>{clearTimeout(timer);reject(error);});
  }),stdio:AdbStdio=realAdbStdio){this.run=run;this.dial=dial;this.stdio=stdio;}
  async discover(){checkpoint();return parseAdbDevices(await this.run(['devices','-l']));}
  async connect(serial:string,transportId?:string,onClose:()=>void=()=>{},usbMode:'forward'|'stdio'='forward'):Promise<AdbConnection>{
    if(!['forward','stdio'].includes(usbMode))deviceFail('UNSUPPORTED_TRANSPORT','choose an explicit USB mode');
    const devices=await this.discover(),matches=devices.filter(d=>d.serial===serial&&(!transportId||d.transportId===transportId));
    if(matches.length!==1)deviceFail('DEVICE_AMBIGUOUS','select one exact serial/transportId from discovery');const selected=matches[0];
    if(selected.state!=='device')deviceFail('DEVICE_NOT_READY','ADB transport is '+selected.state+'; no device RPC was attempted');
    const prefix=selected.transportId?['-t',selected.transportId]:['-s',selected.serial];
    checkpoint();const bootstrap=parseBootstrap(await this.run([...prefix,'exec-out','su','-c',`cat ${DEVICE_BOOTSTRAP}`],{maxBuffer:8192}));
    if(usbMode==='stdio'){
      if(bootstrap.stdioVersion!==1)deviceFail('UNSUPPORTED_TRANSPORT','device does not advertise USB stdio/1; no fallback attempted');
      // KernelSU's fd wrapper can transform binary control bytes. Negotiate before any RPC.
      const help=await this.run([...prefix,'exec-out','su','--help']);const suFlags=help.includes('--no-wrapper')?['-W']:[];
      const ctx=executionContext.getStore();checkpoint();const effect=ctx?.dispatched({kind:'adb',action:'device.stdio.connect'});let rpc:DeviceRpcClient|undefined;
      try{rpc=new DeviceRpcClient(this.stdio([...prefix,'shell','-T','su',...suFlags,'-c',"'"+DEVICE_STDIO_COMMAND+"'"]),onClose);const id=randomUUID(),nonce=randomBytes(32).toString('hex');const reply=await rpc.request('device.hello',{clientNonce:nonce,authentication:{type:'usb-token',credential:bootstrap.token}},undefined,undefined,5000,id);const peer=verifyHello(reply,bootstrap,id,nonce);ctx?.acknowledged(false,effect);
        return {id:randomUUID(),transport:'adb',usbMode,serial:selected.serial,transportId:selected.transportId,port:0,peer,rpc,close:async()=>{rpc!.close();return {removed:true,confirmed:true,reason:'owned stdio stream closed; no forward created'};}};
      }catch(error){rpc?.close();ctx?.acknowledged(false,effect,true);throw error;}
    }
    const ctx=executionContext.getStore();checkpoint();const effect=ctx?.dispatched({kind:'adb',action:'device.forward.create'});
    let port:number;
    try{const raw=await this.run([...prefix,'forward','--no-rebind','tcp:0','localabstract:'+DEVICE_SOCKET]);port=Number(raw.trim());if(!Number.isInteger(port)||port<1||port>65535)deviceFail('FORWARD_UNCONFIRMED','ADB did not confirm an owned forward',true);ctx?.acknowledged(false,effect);}
    catch(error){ctx?.acknowledged(true,effect,true);throw new DeviceError('FORWARD_UNCONFIRMED','forward creation was not confirmed; no automatic retry',true);}
    const remove=async()=>{
      // Verify exactly our mapping and still-current transport. Never remove-all or touch reverse.
      const current=(await this.discover()).find(d=>d.serial===selected.serial&&d.transportId===selected.transportId&&d.state==='device');
      if(!current)return {removed:false,confirmed:false,reason:'original ADB transport is no longer present'};
      const rows=(await this.run([...prefix,'forward','--list'])).split(/\r?\n/).map(line=>line.trim().split(/\s+/));
      const mapping=rows.find(([s,l])=>s===selected.serial&&l===`tcp:${port}`);
      if(!mapping)return {removed:false,confirmed:true,reason:'owned mapping already absent'};
      if(mapping[2]!=='localabstract:'+DEVICE_SOCKET)return {removed:false,confirmed:false,reason:'mapping was replaced; left untouched'};
      checkpoint();await this.run([...prefix,'forward','--remove',`tcp:${port}`]);return {removed:true,confirmed:true};
    };
    let rpc:DeviceRpcClient|undefined;
    try{
      checkpoint();rpc=new DeviceRpcClient(await this.dial(port),onClose);
      const id=randomUUID(),nonce=randomBytes(32).toString('hex');
      const reply=await rpc.request('device.hello',{clientNonce:nonce,authentication:{type:'usb-token',credential:bootstrap.token}},undefined,undefined,5000,id);
      const peer=verifyHello(reply,bootstrap,id,nonce);
      return {id:randomUUID(),transport:'adb',usbMode,serial:selected.serial,transportId:selected.transportId,port,peer,rpc,close:async()=>{rpc!.close();return remove();}};
    }catch(error){rpc?.close();try{if(!(await remove()).confirmed)throw Error();}catch{throw new DeviceError('FORWARD_CLEANUP_UNCONFIRMED','handshake failed and the owned forward cleanup was not confirmed',true);}throw error;}
  }
}

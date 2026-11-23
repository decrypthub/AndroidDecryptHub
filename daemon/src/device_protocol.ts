// Shared device-domain wire contract. Mirrors device/core DeviceRpc; conformance tests pin both.
import { createHash, createPublicKey, verify } from 'node:crypto';
import type { Duplex } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { OperationError } from './execution_context.ts';

export const DEVICE_PROTOCOL='adh.device/1', DEVICE_SOCKET='adh_device_rpc_v1';
export const DEVICE_BOOTSTRAP='/data/adb/adh/device-rpc/usb-access.json';
export const DEVICE_FRAME_MAX=1024*1024;
export const DEVICE_READ_METHODS=new Set(['device.info','device.capabilities','device.state','module.status','scope.get','applications.list','processes.list','certificates.list','host.get','operations.get','operations.reconcile','lan.status','pairings.list','early.prepare','early.status','hooks.migration.preview','legacy.icon']);
export const DEVICE_WRITE_METHODS=new Set(['scope.patch','scope.replace','process.control','certificates.put','certificates.delete','host.set','operations.resolve','lan.configure','pairings.grant','pairings.revoke','early.stage','early.revoke','hooks.migration.apply','hooks.migration.rollback']);
export const uuid=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
export class DeviceError extends OperationError {}
export function deviceFail(code:string,message:string,uncertain=false):never{throw new DeviceError(code,message,uncertain);}
export function deviceMethodMode(method:string){if(DEVICE_READ_METHODS.has(method))return 'read';if(DEVICE_WRITE_METHODS.has(method))return 'write';return deviceFail('UNSUPPORTED_METHOD','device method is not supported; no shell/ADB fallback was attempted');}
export const DEVICE_STDIO_COMMAND='CLASSPATH=/data/adb/modules/adh/daemon.apk app_process /system/bin com.adh.daemon.device.DeviceRpcRelay --base64';
export interface Bootstrap {schemaVersion:1;deviceId:string;identityFingerprint:string;token:string;stdioVersion?:number}
export interface DevicePeer {deviceId:string;bootId:string;daemonInstanceId:string;identityFingerprint:string;info:any;capabilities:{methods:Record<string,string>;[key:string]:any};protocol:string}
export function parseBootstrap(raw:string):Bootstrap {
  let value:any;try{if(Buffer.byteLength(raw)>8192)throw Error();value=JSON.parse(raw);}catch{deviceFail('INVALID_BOOTSTRAP','USB bootstrap could not be parsed; credential content is never logged');}
  if(!value||value.schemaVersion!==1||!uuid(value.deviceId)||!/^[a-f0-9]{64}$/.test(value.identityFingerprint)||!/^[a-f0-9]{64}$/.test(value.token))deviceFail('INVALID_BOOTSTRAP','invalid USB bootstrap metadata');
  return value;
}
export function verifyHello(reply:any,bootstrap:Bootstrap,id:string,nonce:string):DevicePeer {
  try{
    for(const key of ['publicKey','payload','signature'])if(typeof reply[key]!=='string'||reply[key].length>65536||Buffer.from(reply[key],'base64').toString('base64')!==reply[key])throw Error();
    const der=Buffer.from(reply.publicKey,'base64');if(createHash('sha256').update(der).digest('hex')!==bootstrap.identityFingerprint)throw Error();
    const key=createPublicKey({key:der,type:'spki',format:'der'});if(key.asymmetricKeyType!=='rsa')throw Error();
    const payload=Buffer.from(reply.payload,'base64');if(!verify('sha256',payload,key,Buffer.from(reply.signature,'base64')))throw Error();
    const peer=JSON.parse(payload.toString('utf8'));
    if(peer.protocol!==DEVICE_PROTOCOL||peer.requestId!==id||peer.clientNonce!==nonce||peer.deviceId!==bootstrap.deviceId||peer.identityFingerprint!==bootstrap.identityFingerprint||!uuid(peer.bootId)||!uuid(peer.daemonInstanceId))throw Error();
    if(!peer.capabilities?.methods||typeof peer.capabilities.methods!=='object')throw Error();
    for(const [method,mode]of Object.entries(peer.capabilities.methods))if(deviceMethodMode(method)!==mode)throw Error();
    return peer;
  }catch{deviceFail('IDENTITY_UNVERIFIED','device hello signature, challenge or capability contract did not match the USB bootstrap');}
}
export function deviceFrame(value:unknown):Buffer {const data=Buffer.from(JSON.stringify(value));if(!data.length||data.length>DEVICE_FRAME_MAX)deviceFail('FRAME_LIMIT','device request exceeds frame limit');const header=Buffer.alloc(4);header.writeUInt32BE(data.length);return Buffer.concat([header,data]);}

/** Stream-only RPC; never reconnects or replays. Authentication is negotiated by the adapter. */
export class DeviceRpcClient {
  readonly stream:Duplex;
  private pending=new Map<string,{resolve:(value:any)=>void;reject:(error:Error)=>void;timer:ReturnType<typeof setTimeout>;write:boolean}>();
  private buffer=Buffer.alloc(0);private dead=false;
  constructor(stream:Duplex,onClose:()=>void=()=>{}) {
    this.stream=stream;
    stream.on('data',(chunk:Buffer)=>{
      this.buffer=Buffer.concat([this.buffer,chunk]);
      while(this.buffer.length>=4){const size=this.buffer.readUInt32BE();if(size<1||size>DEVICE_FRAME_MAX){this.fail('FRAME_LIMIT');return;}if(this.buffer.length<size+4)return;
        let value:any;try{value=JSON.parse(this.buffer.subarray(4,size+4).toString('utf8'));}catch{this.fail('INVALID_FRAME');return;}this.buffer=this.buffer.subarray(4+size);
        if(value.protocol!==DEVICE_PROTOCOL||typeof value.id!=='string'||typeof value.ok!=='boolean'){this.fail('INVALID_FRAME');return;}
        const entry=this.pending.get(value.id);if(!entry)continue;this.pending.delete(value.id);clearTimeout(entry.timer);
        if(value.ok)entry.resolve(value.result);else entry.reject(new DeviceError(String(value.error?.code||'DEVICE_ERROR'),String(value.error?.message||'device rejected request'),value.error?.uncertain===true));
      }
    });
    stream.on('error',()=>this.fail('DEVICE_DISCONNECTED'));stream.on('close',()=>{this.fail('DEVICE_DISCONNECTED');onClose();});
  }
  request(method:string,params:any,target?:any,meta?:any,budgetMs=15000,id:string=randomUUID()):Promise<any>{
    if(this.dead||this.stream.destroyed)return Promise.reject(new DeviceError('DEVICE_DISCONNECTED','device channel is closed'));
    if(!Number.isInteger(budgetMs)||budgetMs<1||budgetMs>60000)return Promise.reject(new DeviceError('INVALID_ARGUMENT','device request budget must be 1..60000 ms'));
    if(this.pending.has(id))return Promise.reject(new DeviceError('DUPLICATE_REQUEST','request id is already in flight'));
    if(this.pending.size>=32)return Promise.reject(new DeviceError('RPC_BUSY','too many pending device requests'));
    const write=DEVICE_WRITE_METHODS.has(method),frame=deviceFrame({protocol:DEVICE_PROTOCOL,id,method,params,...(target?{target}:{}),...(meta?{meta}:{})});
    return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new DeviceError('DEVICE_RPC_TIMEOUT','device reply deadline expired; execution was not stopped or replayed',write));},budgetMs);
      this.pending.set(id,{resolve,reject,timer,write});this.stream.write(frame,error=>{if(error)this.fail('DEVICE_DISCONNECTED');});
    });
  }
  private fail(code:string){if(this.dead)return;this.dead=true;for(const entry of this.pending.values()){clearTimeout(entry.timer);entry.reject(new DeviceError(code,'device stream closed; no requests were replayed',entry.write));}this.pending.clear();this.stream.destroy();}
  close(){this.fail('DEVICE_DISCONNECTED');}
}

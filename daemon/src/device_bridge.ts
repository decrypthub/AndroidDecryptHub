// Persistent adh.device/1 channel (Frida-style): one authenticated USB connection
// per serial, reused by panel read paths (icons, app list, scope). When the
// device daemon is absent or the stream dies, callers fall back to adb.
import {AdbDeviceTransport} from './transport/adb_device.ts';
import type {DeviceConnection} from './transport/device_transport.ts';

const transport=new AdbDeviceTransport();
const pending=new Map<string,Promise<DeviceConnection|null>>();

// The panel's device management can re-point every read/write path at another
// USB serial; env is only the boot default.
let activeSerial=process.env.ANDROID_SERIAL||process.env.ADH_SERIAL||'';
export function deviceSerial():string{return activeSerial;}
export function setDeviceSerial(serial:string){activeSerial=serial;}

// Explicit connect for the panel's device manager: surfaces the real
// DeviceError (DEVICE_NOT_READY, missing bootstrap, ...) instead of the lazy
// pool's silent null.
export function connectDevice(serial:string):Promise<DeviceConnection>{
  const job=transport.connect(serial,undefined,()=>pending.delete(serial));
  pending.set(serial,job.catch(()=>null));
  return job;
}

export function deviceRpcLive(serial:string):boolean{
  const job=pending.get(serial);
  return !!job; // presence means a live or in-flight channel; destroyed conns delete themselves
}

// Explicit disconnect: close the pooled channel (its owned forward included).
export async function dropDevice(serial:string):Promise<boolean>{
  const job=pending.get(serial);
  if(!job)return false;
  pending.delete(serial);
  const c=await job.catch(()=>null);
  if(!c)return false;
  await c.close();
  return true;
}

export function deviceRpc(serial:string):Promise<DeviceConnection|null>{
  let job=pending.get(serial);
  if(!job){
    job=connectDevice(serial).catch(()=>null);
    pending.set(serial,job);
  }
  return job.then(c=>{
    if(c&&!c.rpc.stream.destroyed)return c;
    if(c)pending.delete(serial);
    return null;
  });
}

import {randomUUID} from 'node:crypto';

function peerTarget(c:DeviceConnection){return {deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId};}

// 'none' = channel answered and the package has no renderable icon;
// null = channel unavailable (caller falls back to host APK parsing).
export async function deviceIcon(serial:string,pkg:string):Promise<Buffer|'none'|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const reply=await c.rpc.request('legacy.icon',{package:pkg},peerTarget(c));
  const b64=typeof reply?.base64==='string'?reply.base64:'';
  return b64?Buffer.from(b64,'base64'):'none';
}

export async function deviceApplications(serial:string):Promise<any[]|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const target=peerTarget(c);
  const all:any[]=[];let offset=0;
  for(;;){
    const reply=await c.rpc.request('applications.list',{offset,limit:200},target);
    const page=Array.isArray(reply?.applications)?reply.applications:[];
    all.push(...page);
    const next=typeof reply?.nextOffset==='number'?reply.nextOffset:null;
    if(next===null||page.length===0)break;
    offset=next;
  }
  return all;
}

export async function deviceScopeGet(serial:string):Promise<any|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  return c.rpc.request('scope.get',{},peerTarget(c));
}

// CAS'd by scopeRevision (document generation) and expectedRevision (device state).
// Failure replies reject with DeviceError carrying the device-side code (STALE_SCOPE, ...).
export async function deviceScopeReplace(serial:string,document:unknown,scopeRevision:string,expectedRevision:number):Promise<any|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const meta={operationId:randomUUID(),expectedRevision,actor:'panel',budgetMs:15000};
  return c.rpc.request('scope.replace',{document,scopeRevision},peerTarget(c),meta);
}

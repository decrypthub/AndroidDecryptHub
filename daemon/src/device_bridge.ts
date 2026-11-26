// Persistent adh.device/1 channels (Frida-style): one control connection and
// one catalog/icon data connection per serial. When the device daemon is absent
// or a stream dies, callers fall back to adb only where that fallback is explicit.
import {AdbDeviceTransport} from './transport/adb_device.ts';
import type {DeviceConnection} from './transport/device_transport.ts';

const transport=new AdbDeviceTransport();
const pending=new Map<string,Promise<DeviceConnection|null>>();
const dataPending=new Map<string,Promise<DeviceConnection|null>>();

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
  return !!pending.get(serial)||!!dataPending.get(serial); // presence means a live or in-flight channel; destroyed conns delete themselves
}

// Explicit disconnect: close the pooled channels (their owned forwards included).
export async function dropDevice(serial:string):Promise<boolean>{
  const jobs=[pending.get(serial),dataPending.get(serial)].filter(Boolean) as Promise<DeviceConnection|null>[];
  if(!jobs.length)return false;
  pending.delete(serial);dataPending.delete(serial);
  let closed=false;
  for(const job of jobs){
    const c=await job.catch(()=>null);
    if(c){await c.close();closed=true;}
  }
  return closed;
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

function connectDataDevice(serial:string):Promise<DeviceConnection>{
  const job=transport.connect(serial,undefined,()=>dataPending.delete(serial));
  dataPending.set(serial,job.catch(()=>null));
  return job;
}

function deviceDataRpc(serial:string):Promise<DeviceConnection|null>{
  let job=dataPending.get(serial);
  if(!job){
    job=connectDataDevice(serial).catch(()=>null);
    dataPending.set(serial,job);
  }
  return job.then(c=>{
    if(c&&!c.rpc.stream.destroyed)return c;
    if(c)dataPending.delete(serial);
    return null;
  });
}

import {createHash, randomUUID} from 'node:crypto';

function peerTarget(c:DeviceConnection){return {deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId};}

// 'none' = channel answered and the package has no renderable icon;
// null = channel unavailable (caller falls back to host APK parsing).
export async function deviceIcon(serial:string,pkg:string):Promise<Buffer|'none'|null>{
  const c=await deviceDataRpc(serial);
  if(!c)return null;
  let reply:any;
  try{
    reply=await c.rpc.request('applications.icon',{package:pkg,size:96,format:'png'},peerTarget(c));
  }catch(error){
    if((error as {code?:string}).code!=='UNSUPPORTED_METHOD')throw error;
    reply=await c.rpc.request('legacy.icon',{package:pkg},peerTarget(c));
    const legacy=typeof reply?.base64==='string'?reply.base64:'';
    return legacy?Buffer.from(legacy,'base64'):'none';
  }
  if(reply?.missing===true)return 'none';
  if(reply?.missing!==false||reply.format!=='png'||typeof reply.base64!=='string')throw new Error('device returned an invalid applications.icon reply');
  const body=Buffer.from(reply.base64,'base64');
  const sha=createHash('sha256').update(body).digest('hex');
  if(reply.sha256!==sha)throw new Error('device icon hash did not match the applications.icon payload');
  return body;
}

export async function deviceApplications(serial:string):Promise<any[]|null>{
  const c=await deviceDataRpc(serial);
  if(!c)return null;
  const target=peerTarget(c);
  const all:any[]=[];let offset=0;let revision=0;
  for(;;){
    const reply=await c.rpc.request('applications.list',{offset,limit:500,...(revision?{revision}:{})},target);
    const page=Array.isArray(reply?.applications)?reply.applications:[];
    if(!revision&&typeof reply?.revision==='number')revision=reply.revision;
    if(typeof reply?.revision==='number'&&reply.revision!==revision)throw new Error('device application catalog revision changed during pagination');
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

// Device state generation. A write whose expectedRevision is not this value is refused
// device-side (STALE_DEVICE_STATE), so control calls re-read it instead of retrying blindly.
export async function deviceState(serial:string):Promise<any|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  return c.rpc.request('device.state',{},peerTarget(c));
}

// One package can legitimately own several processes (:core, :player). Pagination is the
// device's, so a partial page is a partial answer: `complete` says whether /proc was readable.
// The page count is bounded: a peer that keeps returning a page must not spin the Host forever.
const PROCESS_PAGE_LIMIT = 50;
export async function deviceProcesses(serial:string,pkg:string):Promise<{rows:any[];complete:boolean;total:number}|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const target=peerTarget(c);const rows:any[]=[];let offset=0;let complete=true;let total=0;
  for(let page=0;;page++){
    if(page>=PROCESS_PAGE_LIMIT)throw new Error(`processes.list did not finish after ${PROCESS_PAGE_LIMIT} pages`);
    const reply=await c.rpc.request('processes.list',{package:pkg,offset,limit:200},target);
    const page_rows=Array.isArray(reply?.processes)?reply.processes:[];
    rows.push(...page_rows);
    if(typeof reply?.total==='number')total=reply.total;
    if(reply?.complete===false)complete=false;
    const next=typeof reply?.nextOffset==='number'?reply.nextOffset:null;
    if(next===null||page_rows.length===0)break;
    offset=next;
  }
  return {rows,complete,total:total||rows.length};
}

// Two fences, both device-side: expectedProcesses must still be the live
// (pid,uid,starttimeTicks) set (TARGET_CHANGED) and expectedRevision the current state
// generation. The reply is the operation record; the verdict lives in .result.
export async function deviceProcessControl(serial:string,pkg:string,action:'open'|'stop'|'restart',expected:unknown[],expectedRevision:number):Promise<any|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const meta={operationId:randomUUID(),expectedRevision,actor:'panel',budgetMs:20000};
  return c.rpc.request('process.control',{package:pkg,action,expectedProcesses:expected},peerTarget(c),meta,20000);
}

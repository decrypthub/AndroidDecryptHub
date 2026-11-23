// Persistent adh.device/1 channel (Frida-style): one authenticated USB connection
// per serial, reused by panel read paths (icons, app list, scope). When the
// device daemon is absent or the stream dies, callers fall back to adb.
import {AdbDeviceTransport} from './transport/adb_device.ts';
import type {DeviceConnection} from './transport/device_transport.ts';

const transport=new AdbDeviceTransport();
const pending=new Map<string,Promise<DeviceConnection|null>>();

export function deviceSerial():string{return process.env.ANDROID_SERIAL||process.env.ADH_SERIAL||'';}

export function deviceRpc(serial:string):Promise<DeviceConnection|null>{
  let job=pending.get(serial);
  if(!job){
    job=transport.connect(serial,undefined,()=>pending.delete(serial)).catch(()=>null);
    pending.set(serial,job);
  }
  return job.then(c=>{
    if(c&&!c.rpc.stream.destroyed)return c;
    if(c)pending.delete(serial);
    return null;
  });
}

// 'none' = channel answered and the package has no renderable icon;
// null = channel unavailable (caller falls back to host APK parsing).
export async function deviceIcon(serial:string,pkg:string):Promise<Buffer|'none'|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const target={deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId};
  const reply=await c.rpc.request('legacy.icon',{package:pkg},target);
  const b64=typeof reply?.base64==='string'?reply.base64:'';
  return b64?Buffer.from(b64,'base64'):'none';
}

export async function deviceApplications(serial:string):Promise<any[]|null>{
  const c=await deviceRpc(serial);
  if(!c)return null;
  const target={deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId};
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

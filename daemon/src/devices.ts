import {existsSync,readFileSync} from 'node:fs';
import {atomicWriteJson} from './storage.ts';
import {AdbDeviceTransport,type AdbConnection} from './transport/adb_device.ts';
import {DeviceError,deviceFail,deviceMethodMode,uuid,type DevicePeer} from './device_protocol.ts';
import {checkpoint,executionContext} from './execution_context.ts';

interface DeviceRecord {deviceId:string;identityFingerprint:string;lastPeer:DevicePeer;lastSeen:number}
/** Device identity is persistent; transport connections are deliberately ephemeral and replaceable. */
export class Devices {
  private file:string;readonly adapter:AdbDeviceTransport;private generationChanged:(deviceId:string)=>void;
  private records:Record<string,DeviceRecord>={};
  private connections=new Map<string,AdbConnection>();
  constructor(file:string,adapter=new AdbDeviceTransport(),generationChanged:(deviceId:string)=>void=()=>{}) {
    this.file=file;this.adapter=adapter;this.generationChanged=generationChanged;
    if(existsSync(file)){
      const value=JSON.parse(readFileSync(file,'utf8'));if(!value||value.schemaVersion!==1||!value.devices||Array.isArray(value.devices)||typeof value.devices!=='object')deviceFail('DEVICE_REGISTRY_CORRUPT','authoritative device registry cannot be rebuilt automatically');
      for(const [id,record]of Object.entries(value.devices) as [string,DeviceRecord][]){if(!uuid(id)||id!==record.deviceId||!/^[a-f0-9]{64}$/.test(record.identityFingerprint))deviceFail('DEVICE_REGISTRY_CORRUPT','invalid saved device identity');}
      this.records=value.devices;
    }
  }
  list(){return {devices:Object.values(this.records).map(record=>({deviceId:record.deviceId,identityFingerprint:record.identityFingerprint,lastSeen:record.lastSeen,lastKnown:record.lastPeer,
    online:[...this.connections.values()].some(c=>c.peer.deviceId===record.deviceId&&!c.rpc.stream.destroyed),connections:[...this.connections.values()].filter(c=>c.peer.deviceId===record.deviceId).map(c=>this.connectionView(c))})),
    legacyAgentAssociation:'unverified; no session is assigned by ADB serial',discoveryIsExplicit:true};}
  private connectionView(c:AdbConnection){return {connectionId:c.id,transport:c.transport,serial:c.serial,transportId:c.transportId,deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId,identityVerified:true,online:!c.rpc.stream.destroyed};}
  async discover(){return {transports:await this.adapter.discover(),...this.list()};}
  async connect(serial:string,transportId?:string,expectedDeviceId?:string){
    let connection:AdbConnection|undefined;
    // Keep closed handles for explicit, verified forward cleanup; never silently reconnect.
    connection=await this.adapter.connect(serial,transportId);
    try{
      if(expectedDeviceId&&connection.peer.deviceId!==expectedDeviceId)deviceFail('DEVICE_MISMATCH','USB endpoint is another device; no target operations were attempted');
      const id=connection.peer.deviceId,previous=this.records[id];
      if(previous&&previous.identityFingerprint!==connection.peer.identityFingerprint)deviceFail('IDENTITY_COLLISION','saved device id has a different installation key; refusing silent replacement');
      const live=[...this.connections.values()].filter(c=>c.peer.deviceId===id&&!c.rpc.stream.destroyed);
      if(live.some(c=>c.peer.bootId!==connection!.peer.bootId||c.peer.daemonInstanceId!==connection!.peer.daemonInstanceId))deviceFail('IDENTITY_COLLISION','same device id claims two live boot/daemon generations');
      checkpoint();
      if(previous&&(previous.lastPeer.bootId!==connection.peer.bootId||previous.lastPeer.daemonInstanceId!==connection.peer.daemonInstanceId))this.generationChanged(id);
      const candidate={...this.records,[id]:{deviceId:id,identityFingerprint:connection.peer.identityFingerprint,lastPeer:connection.peer,lastSeen:Date.now()}};
      atomicWriteJson(this.file,{schemaVersion:1,devices:candidate});this.records=candidate;this.connections.set(connection.id,connection);
      return {ok:true,...this.connectionView(connection),identity:connection.peer};
    }catch(error){try{if(!(await connection.close()).confirmed)throw Error();}catch{throw new DeviceError('FORWARD_CLEANUP_UNCONFIRMED','device registration failed and owned forward cleanup is unconfirmed',true);}throw error;}
  }
  private connection(deviceId:string,connectionId?:string,includeClosed=false){
    if(!uuid(deviceId))deviceFail('DEVICE_REQUIRED','select a verified deviceId, not an ADB serial');
    const matches=[...this.connections.values()].filter(c=>c.peer.deviceId===deviceId&&(includeClosed||!c.rpc.stream.destroyed)&&(!connectionId||c.id===connectionId));
    if(!matches.length)deviceFail('DEVICE_OFFLINE','device has no verified active connection; no ADB fallback was attempted');
    if(matches.length!==1)deviceFail('CONNECTION_AMBIGUOUS','select connectionId explicitly; writes never fail over or replay');return matches[0];
  }
  async disconnect(deviceId:string,connectionId?:string){
    const c=this.connection(deviceId,connectionId,true),ctx=executionContext.getStore();checkpoint();const effect=ctx?.dispatched({kind:'device',action:'connection.close'});
    try{const cleanup=await c.close();if(!cleanup.confirmed)throw Error();this.connections.delete(c.id);ctx?.acknowledged(false,effect);return {ok:true,connectionId:c.id,cleanup};}
    catch{ctx?.acknowledged(true,effect,true);throw new DeviceError('FORWARD_CLEANUP_UNCONFIRMED','device connection closed but its owned forward cleanup is unconfirmed',true);}
  }
  async call(args:{deviceId:string;connectionId?:string;method:string;params?:any;bootId?:string;daemonInstanceId?:string;expectedDeviceRevision?:number;budgetMs?:number}){
    const c=this.connection(args.deviceId,args.connectionId),mode=deviceMethodMode(args.method);
    if(args.budgetMs!==undefined&&(!Number.isInteger(args.budgetMs)||args.budgetMs<1||args.budgetMs>60000))deviceFail('INVALID_ARGUMENT','device budget must be an integer in 1..60000 ms');
    if(args.params!==undefined&&(!args.params||Array.isArray(args.params)||typeof args.params!=='object'))deviceFail('INVALID_ARGUMENT','device params must be an object');
    if(c.peer.capabilities.methods[args.method]!==mode)deviceFail('CAPABILITY_UNSUPPORTED','connected device does not advertise this capability');
    const ctx=executionContext.getStore();checkpoint();
    if(mode==='write'){
      if(!ctx?.operationId)deviceFail('OPERATION_REQUIRED','device mutations must enter the shared Host operation coordinator');
      if(ctx.resource!=='device:'+args.deviceId)deviceFail('TARGET_CHANGED','Host operation is bound to another resource; no cross-device dispatch');
      if(args.bootId!==c.peer.bootId||args.daemonInstanceId!==c.peer.daemonInstanceId)deviceFail('TARGET_CHANGED','send the observed device bootId and daemonInstanceId; no automatic rebinding');
      if(!Number.isSafeInteger(args.expectedDeviceRevision)||args.expectedDeviceRevision < 0)deviceFail('DEVICE_VERSION_REQUIRED','send the observed device stateRevision');
      if(args.method==='operations.resolve'&&ctx.principalRole!=='operator')deviceFail('OPERATOR_REQUIRED','only an authenticated operator can reconcile unknown device effects');
    }
    const budget=Math.min(60000,Math.max(1,Math.floor(args.budgetMs||15000)),ctx?.remainingMs?.()??60000);
    const target={deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId};
    const meta=mode==='write'?{operationId:ctx!.operationId,expectedRevision:args.expectedDeviceRevision,actor:ctx!.principalRole,budgetMs:budget}:undefined;
    const effect=mode==='write'?ctx?.dispatched({kind:'device',action:args.method}):undefined;
    try{
      const result=await c.rpc.request(args.method,args.params||{},target,meta,budget);
      const uncertain=result.state==='unknown'||result.uncertain===true;
      if(mode==='write')ctx?.acknowledged(uncertain,effect,result.state==='failed');
      return {ok:!uncertain&&result.state!=='failed'&&result.ok!==false,deviceId:c.peer.deviceId,bootId:c.peer.bootId,connectionId:c.id,result,
        ...(uncertain?{code:'UNKNOWN_EXECUTION',uncertain:true}:{}),...(result.state==='failed'?{code:result.code||'DEVICE_OPERATION_FAILED'}:{})};
    }catch(error){if(mode==='write')ctx?.acknowledged((error as any).uncertain===true,effect,true);throw error;}
  }
  close(){for(const c of this.connections.values())c.rpc.close();this.connections.clear();}
}

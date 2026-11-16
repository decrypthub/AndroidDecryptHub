import {existsSync,readFileSync} from 'node:fs';
import {atomicWriteJson} from './storage.ts';
import {dirname,join} from 'node:path';
import {AdbDeviceTransport} from './transport/adb_device.ts';
import {LanDeviceTransport,type LanEnrollment} from './transport/lan_device.ts';
import type {DeviceConnection} from './transport/device_transport.ts';
import {DeviceClientIdentity} from './device_client_identity.ts';
import {DeviceError,deviceFail,deviceMethodMode,uuid,type DevicePeer} from './device_protocol.ts';
import {checkpoint,executionContext} from './execution_context.ts';

interface DeviceRecord {deviceId:string;identityFingerprint:string;lastPeer:DevicePeer;lastSeen:number;pairing?:LanEnrollment;lanEndpoint?:{address:string;port:number}}
/** Device identity is persistent; transport connections are deliberately ephemeral and replaceable. */
export class Devices {
  private file:string;readonly adapter:AdbDeviceTransport;private generationChanged:(deviceId:string)=>void;
  readonly clientIdentity:DeviceClientIdentity;readonly lan:LanDeviceTransport;
  private records:Record<string,DeviceRecord>={};
  private connections=new Map<string,DeviceConnection>();
  constructor(file:string,adapter=new AdbDeviceTransport(),generationChanged:(deviceId:string)=>void=()=>{},lan=new LanDeviceTransport()) {
    this.file=file;this.adapter=adapter;this.generationChanged=generationChanged;
    this.clientIdentity=new DeviceClientIdentity(join(dirname(file),'device-client.json'));this.lan=lan;
    if(existsSync(file)){
      const value=JSON.parse(readFileSync(file,'utf8'));if(!value||value.schemaVersion!==1||!value.devices||Array.isArray(value.devices)||typeof value.devices!=='object')deviceFail('DEVICE_REGISTRY_CORRUPT','authoritative device registry cannot be rebuilt automatically');
      for(const [id,record]of Object.entries(value.devices) as [string,DeviceRecord][]){if(!uuid(id)||id!==record.deviceId||!/^[a-f0-9]{64}$/.test(record.identityFingerprint))deviceFail('DEVICE_REGISTRY_CORRUPT','invalid saved device identity');}
      this.records=value.devices;
    }
  }
  list(){return {devices:Object.values(this.records).map(record=>({deviceId:record.deviceId,identityFingerprint:record.identityFingerprint,lastSeen:record.lastSeen,lastKnown:record.lastPeer,pairing:record.pairing?{...record.pairing,authorization:'cached enrollment; device rechecks every LAN request'}:undefined,lanEndpoint:record.lanEndpoint,
    online:[...this.connections.values()].some(c=>c.peer.deviceId===record.deviceId&&!c.rpc.stream.destroyed),connections:[...this.connections.values()].filter(c=>c.peer.deviceId===record.deviceId).map(c=>this.connectionView(c))})),
    legacyAgentAssociation:'unverified; no session is assigned by ADB serial',discoveryIsExplicit:true};}
  private connectionView(c:DeviceConnection){return {connectionId:c.id,transport:c.transport,serial:c.serial,transportId:c.transportId,address:c.address,port:c.transport==='lan'?c.port:undefined,grantId:c.grantId,tlsVersion:c.tlsVersion,deviceId:c.peer.deviceId,bootId:c.peer.bootId,daemonInstanceId:c.peer.daemonInstanceId,identityVerified:true,online:!c.rpc.stream.destroyed};}
  async discover(transport='adb'){
    if(transport==='lan')return {transports:Object.values(this.records).filter(r=>r.lanEndpoint).map(r=>({transport:'lan',deviceId:r.deviceId,...r.lanEndpoint,state:'last-known; not probed'})),...this.list()};
    if(transport!=='adb')deviceFail('UNSUPPORTED_TRANSPORT','only adb and paired LAN are implemented');return {transports:await this.adapter.discover(),...this.list()};
  }
  async connect(serial:string,transportId?:string,expectedDeviceId?:string){
    const connection=await this.adapter.connect(serial,transportId);
    return this.register(connection,expectedDeviceId);
  }
  async connectLan(deviceId:string,address?:string,port?:number){
    const record=this.records[deviceId];if(!record?.pairing)deviceFail('DEVICE_NOT_PAIRED','enroll this Host key over trusted USB before LAN; no ADB fallback');
    const endpoint={address:address??record.lanEndpoint?.address,port:port??record.lanEndpoint?.port};
    const identity=this.clientIdentity.read(),ctx=executionContext.getStore();checkpoint();const effect=ctx?.dispatched({kind:'lan',action:'TLS connection.authenticate'});
    try{const result=await this.register(await this.lan.connect(record.lastPeer,record.pairing,identity,endpoint.address!,endpoint.port!),deviceId);ctx?.acknowledged(false,effect);return result;}
    catch(error){ctx?.acknowledged((error as any).uncertain===true,effect,true);throw error;}
  }
  private async register(connection:DeviceConnection,expectedDeviceId?:string){
    // Keep closed handles for explicit, verified forward cleanup; never silently reconnect.
    try{
      if(expectedDeviceId&&connection.peer.deviceId!==expectedDeviceId)deviceFail('DEVICE_MISMATCH','USB endpoint is another device; no target operations were attempted');
      const id=connection.peer.deviceId,previous=this.records[id];
      if(previous&&previous.identityFingerprint!==connection.peer.identityFingerprint)deviceFail('IDENTITY_COLLISION','saved device id has a different installation key; refusing silent replacement');
      const live=[...this.connections.values()].filter(c=>c.peer.deviceId===id&&!c.rpc.stream.destroyed);
      if(live.some(c=>c.peer.bootId!==connection!.peer.bootId||c.peer.daemonInstanceId!==connection!.peer.daemonInstanceId))deviceFail('IDENTITY_COLLISION','same device id claims two live boot/daemon generations');
      checkpoint();
      if(previous&&(previous.lastPeer.bootId!==connection.peer.bootId||previous.lastPeer.daemonInstanceId!==connection.peer.daemonInstanceId))this.generationChanged(id);
      const candidate={...this.records,[id]:{...previous,deviceId:id,identityFingerprint:connection.peer.identityFingerprint,lastPeer:connection.peer,lastSeen:Date.now(),...(connection.transport==='lan'?{lanEndpoint:{address:connection.address!,port:connection.port}}:{})}};
      atomicWriteJson(this.file,{schemaVersion:1,devices:candidate});this.records=candidate;this.connections.set(connection.id,connection);
      return {ok:true,...this.connectionView(connection),identity:connection.peer};
    }catch(error){try{if(!(await connection.close()).confirmed)throw Error();}catch{throw new DeviceError('FORWARD_CLEANUP_UNCONFIRMED','device registration failed and owned forward cleanup is unconfirmed',true);}throw error;}
  }
  async pair(args:any){
    const c=this.connection(args.deviceId,args.connectionId);
    if(c.transport!=='adb')deviceFail('TRUSTED_USB_REQUIRED','Host key enrollment requires a verified USB bootstrap');
    const ctx=executionContext.getStore();checkpoint();
    if(!ctx?.operationId||ctx.resource!=='device:'+args.deviceId||ctx.connectionOnly)deviceFail('OPERATION_REQUIRED','pairing must use a device mutation operation');
    const effect=ctx.dispatched({kind:'host',action:'device.client.identity'});
    let identity;try{identity=this.clientIdentity.ensure();ctx.acknowledged(false,effect);}catch(error){ctx.acknowledged(false,effect,true);throw error;}
    let result:any;
    if(args.grantId){
      const observed=await this.call({...args,method:'pairings.list'});
      const grant=observed.result.grants.find((g:any)=>g.grantId===args.grantId&&g.clientId===identity.clientId&&!g.revokedAt);
      if(!grant)deviceFail('PAIRING_NOT_FOUND','USB did not confirm this Host key and active grant');
      result={ok:true,deviceId:args.deviceId,result:{result:grant},adopted:true};
    }else result=await this.call({...args,method:'pairings.grant',params:{publicKey:identity.publicKey,label:args.label||'ADH Host',permissions:args.permissions||['read','write']}});
    if(result.ok){
      const effect=ctx.dispatched({kind:'host',action:'device.enrollment.persist'});
      try{
        const grant=result.result.result;if(!grant?.grantId||grant.clientId!==identity.clientId)throw Error();
        const candidate={...this.records,[args.deviceId]:{...this.records[args.deviceId],pairing:{grantId:grant.grantId,clientId:grant.clientId,permissions:grant.permissions}}};
        atomicWriteJson(this.file,{schemaVersion:1,devices:candidate});this.records=candidate;ctx.acknowledged(false,effect);
      }catch{ctx.acknowledged(true,effect,true);deviceFail('PAIRING_UNCONFIRMED','device granted access but Host enrollment persistence is unconfirmed; inspect pairings.list over USB',true);}
    }
    return result;
  }
  async reconcile(deviceId:string,operationIds:string[],connectionId?:string){
    if(!Array.isArray(operationIds)||operationIds.length<1||operationIds.length>100||operationIds.some(id=>typeof id!=='string'||!/^[\w-]{1,128}$/.test(id)))deviceFail('INVALID_ARGUMENT','select 1..100 recorded Host operation ids');
    return this.call({deviceId,connectionId,method:'operations.reconcile',params:{operationIds}});
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
    if(c.peer.capabilities.deniedMethods?.includes(args.method))deviceFail('PERMISSION_DENIED','paired client is not authorized for this capability');
    if(c.peer.capabilities.methods[args.method]!==mode)deviceFail('CAPABILITY_UNSUPPORTED','connected device does not advertise this capability; no fallback');
    const ctx=executionContext.getStore();checkpoint();
    if(mode==='write'){
      if(!ctx?.operationId)deviceFail('OPERATION_REQUIRED','device mutations must enter the shared Host operation coordinator');
      if(ctx.connectionOnly)deviceFail('OPERATION_REQUIRED','connection recovery cannot dispatch device mutations');
      if(ctx.securityOnly&&!(args.method==='early.revoke'||args.method==='pairings.revoke'||args.method==='lan.configure'&&args.params?.enabled===false))deviceFail('OPERATION_REQUIRED','quarantined security control can only revoke grants/cache or disable LAN');
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

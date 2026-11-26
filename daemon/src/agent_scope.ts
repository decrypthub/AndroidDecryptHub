import {AsyncLocalStorage} from 'node:async_hooks';

export class AgentScopeError extends Error {
  status=409;
  code:string;
  constructor(code:string,message:string){super(message);this.code=code;}
}
export interface AgentDeviceBinding {
  kind:'usb-route';
  package:string;
  serial:string;transportId:string;leaseId:string;bootId:string;
  deviceAgentPort:number;hostAgentPort:number;verifiedAt:number;
  // Explicit trusted-host USB routing + procfs proof, NOT DeviceRpc key authentication.
  assurance:'explicit-usb-route';
  linkEvidence?:'usb-devpath'|'windows-adb-roster';
  process:Readonly<{pid:number;uid:number;starttimeTicks:string;name:string}>;
}
export interface DeviceRequestScope {serial?:string;package?:string;session?:string}
const scopeStorage=new AsyncLocalStorage<Readonly<DeviceRequestScope>>();
export const deviceRequestScope=()=>scopeStorage.getStore();
export function validDeviceSerial(value:string){return /^[A-Za-z0-9_.:[\]-]{1,200}$/.test(value);}
export function validPackage(value:string){return /^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$/.test(value);}
export function withDeviceScope<T>(scope:DeviceRequestScope,fn:()=>T):T {
  if(scope.serial!==undefined&&!validDeviceSerial(scope.serial))throw new AgentScopeError('INVALID_DEVICE_SCOPE','无效的设备串号');
  if(scope.package!==undefined&&!validPackage(scope.package))throw new AgentScopeError('INVALID_PACKAGE_SCOPE','无效的应用包名');
  const parent=deviceRequestScope();
  for(const key of ['serial','package','session'] as const)
    if(parent?.[key]&&scope[key]&&parent[key]!==scope[key])throw new AgentScopeError('TARGET_SCOPE_CONFLICT',`请求的 ${key} 与已固定目标不一致`);
  return scopeStorage.run(Object.freeze({...parent,...scope}),fn);
}
export function httpDeviceScope(headers:Record<string,unknown>):DeviceRequestScope {
  const scope:DeviceRequestScope={};
  for(const [header,key] of [['x-adh-device-serial','serial'],['x-adh-package','package']] as const){
    const value=headers[header];if(value===undefined||value==='')continue;
    if(typeof value!=='string')throw new AgentScopeError('INVALID_DEVICE_SCOPE','目标标头必须只有一个值');
    scope[key]=value;
  }
  return scope;
}
/** Host-created sockets/timers take their own verified target, not the browser that happened
 * to create the listener. This is not exposed as a client-supplied authorization bypass. */
export function independentDeviceScope<T>(scope:DeviceRequestScope,fn:()=>T):T{return scopeStorage.exit(()=>withDeviceScope(scope,fn));}
export interface ScopedSession {
  sessionId:string;package:string;process:string;pid:number;uid:number;starttimeTicks?:string;
  online:boolean;connectedAt:number;deviceBinding?:Readonly<AgentDeviceBinding>;
}
export function assertSessionScope(target:ScopedSession,scope=deviceRequestScope()):void {
  if(scope?.session&&scope.session!==target.sessionId)throw new AgentScopeError('TARGET_SCOPE_CONFLICT','会话已改变');
  if(scope?.package&&scope.package!==target.package)throw new AgentScopeError('TARGET_SCOPE_CONFLICT','应用与当前请求不一致');
  if(scope?.serial&&(!target.deviceBinding||target.deviceBinding.serial!==scope.serial))
    throw new AgentScopeError('DEVICE_SESSION_UNVERIFIED','此会话没有绑定到请求中的设备，请重新连接或明确选择旧会话');
  const proof=target.deviceBinding?.process;
  if(target.deviceBinding&&target.deviceBinding.package!==target.package)throw new AgentScopeError('TARGET_SCOPE_CONFLICT','进程验证与应用包名不一致');
  if(proof&&(target.pid!==proof.pid||target.uid!==proof.uid||target.starttimeTicks!==proof.starttimeTicks||target.process!==proof.name))
    throw new AgentScopeError('PROCESS_GENERATION_CHANGED','会话进程身份与验证时不一致');
}
export function selectAgentSession<T extends ScopedSession>(rows:T[],options:{package?:string;serial?:string}={}):T|undefined {
  const scope=deviceRequestScope();const serial=options.serial??scope?.serial,pkg=options.package??scope?.package;
  let online=rows.filter(s=>s.online&&(!pkg||s.package===pkg)&&(!serial||s.deviceBinding?.serial===serial));
  if(!online.length)return undefined;
  const devices=new Set(online.map(s=>s.deviceBinding?`usb:${s.deviceBinding.serial}`:'legacy-unverified'));
  if(devices.size>1)throw new AgentScopeError('AMBIGUOUS_DEVICE','同名应用来自多个设备，请先选择设备或会话');
  if(new Set(online.map(s=>s.package)).size>1)throw new AgentScopeError('AMBIGUOUS_APP','有多个在线应用，请指定应用或会话');
  const main=online.filter(s=>s.process===s.package);if(main.length)online=main;
  if(new Set(online.map(s=>`${s.pid}:${s.uid}:${s.starttimeTicks??'legacy'}`)).size>1)
    throw new AgentScopeError('AMBIGUOUS_PROCESS','此应用有多个进程，请指定会话');
  const selected=online.sort((a,b)=>b.connectedAt-a.connectedAt)[0];assertSessionScope(selected,scope);return selected;
}
export function freezeDeviceBinding(binding:AgentDeviceBinding):Readonly<AgentDeviceBinding>{
  return Object.freeze({...binding,process:Object.freeze({...binding.process})});
}
export function captureMatchesDevice(entry:{deviceBinding?:Readonly<AgentDeviceBinding>},serial=deviceRequestScope()?.serial):boolean {
  return !serial||entry.deviceBinding?.serial===serial;
}
const validators=new Map<string,(binding:Readonly<AgentDeviceBinding>)=>Promise<void>>();
export function registerAgentRouteValidator(leaseId:string,validate:(binding:Readonly<AgentDeviceBinding>)=>Promise<void>){
  if(validators.has(leaseId))throw new AgentScopeError('ROUTE_COLLISION','设备路由标识已存在');
  validators.set(leaseId,validate);return ()=>validators.delete(leaseId);
}
export async function verifyAgentBinding(target:ScopedSession):Promise<void>{
  assertSessionScope(target);const binding=target.deviceBinding;if(!binding)return;
  const validate=validators.get(binding.leaseId);if(!validate)throw new AgentScopeError('DEVICE_ROUTE_EXPIRED','设备路由已失效，请重新连接');
  await validate(binding);assertSessionScope(target);
}

export function captureMatchesScope(entry:{package?:string;deviceBinding?:Readonly<AgentDeviceBinding>}):boolean {
  const scope=deviceRequestScope();return captureMatchesDevice(entry)&&(!scope?.package||entry.package===scope.package);
}
export function assertRequestedTarget(serial?:string,pkg?:string):void{
  const scope=deviceRequestScope();
  if(serial&&scope?.serial&&serial!==scope.serial)throw new AgentScopeError('TARGET_SCOPE_CONFLICT','操作设备与当前请求不一致');
  if(pkg&&scope?.package&&pkg!==scope.package)throw new AgentScopeError('TARGET_SCOPE_CONFLICT','操作应用与当前请求不一致');
}

export function scopeSessionRows<T extends ScopedSession>(rows:T[]):T[]{
  const scope=deviceRequestScope();const result=rows.filter(s=>(!scope?.serial||s.deviceBinding?.serial===scope.serial)&&(!scope?.package||s.package===scope.package));
  const domains=new Set(result.map(s=>s.deviceBinding?.serial??'legacy-unverified'));
  if(domains.size>1)throw new AgentScopeError('AMBIGUOUS_DEVICE','操作包含多个设备，请指定设备或会话');
  return result;
}

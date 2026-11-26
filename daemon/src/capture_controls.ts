import {existsSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {atomicWriteJson} from './storage.ts';
import {localEffect,OperationError} from './execution_context.ts';
import {assertRequestedTarget,assertSessionScope,verifyAgentBinding,validDeviceSerial,validPackage} from './agent_scope.ts';
import {DATA_DIR,sessions} from './state.ts';
import {sendCmd,drainSession,startCaptureLoop,pauseCaptureDrains,resumeCaptureDrains,clearCaptureEchoMemo} from './service.ts';
import {getHookPlans} from './hook_plan_host.ts';

export const CAPTURE_FEATURES=[['digest','摘要',1],['hmac','HMAC',2],['symmetric','对称加密',4],['asymmetric','非对称签名',8],['tls','TLS 明文',16],['aead','AEAD',32],['system','系统检测',64],['file','文件访问',128]] as const;
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
const canonical=(x:any):string=>Array.isArray(x)?'['+x.map(canonical).join(',')+']':x&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}':JSON.stringify(x);
function fail(code:string,message:string):never{throw new OperationError(code,message);}
export function emptyCaptureConfig(){return {schemaVersion:1,features:Object.fromEntries(CAPTURE_FEATURES.map(([key])=>[key,{enabled:false,methods:[] as string[]}])),modules:{crypto:'',file:'',system:''}};}
function exact(value:any,keys:string[]){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.includes(k)))fail('INVALID_CAPTURE_CONFIG','配置包含未知字段或不是对象');}
export function validateCaptureConfig(value:any,methods:any[]){
 exact(value,['schemaVersion','features','modules']);if(value.schemaVersion!==1)fail('INVALID_CAPTURE_CONFIG','配置版本不支持');
 exact(value.features,CAPTURE_FEATURES.map(([k])=>k));exact(value.modules,['crypto','file','system']);
 const byId=new Map(methods.map(m=>[m.id,m]));const config=emptyCaptureConfig();
 for(const [key,,bit]of CAPTURE_FEATURES){const f=value.features[key];exact(f,['enabled','methods']);if(typeof f.enabled!=='boolean'||!Array.isArray(f.methods)||f.methods.length>128||f.methods.some((id:any)=>typeof id!=='string'||!byId.has(id)||!(byId.get(id).families&bit)))fail('INVALID_CAPTURE_SELECTION',`功能 ${key} 含有不属于当前目录的方法`);config.features[key]={enabled:f.enabled,methods:[...new Set(f.methods)] as string[]};}
 for(const key of ['crypto','file','system']as const){const v=value.modules[key];if(typeof v!=='string'||v.length>(key==='system'?500:63)||v&&!/^[A-Za-z0-9_.,+@/:-]+$/.test(v))fail('INVALID_CAPTURE_MODULE','模块名无效或过长');config.modules[key]=v;}
 return config;
}
export function desiredCaptureMethods(config:ReturnType<typeof emptyCaptureConfig>,methods:any[]){
 const chosen=new Set<string>();for(const [key]of CAPTURE_FEATURES)if(config.features[key].enabled)for(const id of config.features[key].methods)chosen.add(id);
 const by=new Map(methods.map(m=>[m.id,m]));const effective=new Set(chosen),dependencies=new Map<string,string[]>();
 for(let pass=0;pass<methods.length;pass++){let changed=false;for(const id of [...effective])for(const dep of by.get(id)?.requires??[]){if(!by.has(dep))fail('DEPENDENCY_UNAVAILABLE',`缺少必要方法 ${dep}`);if(!effective.has(dep)){effective.add(dep);changed=true;}const parents=dependencies.get(dep)??[];if(!parents.includes(id))parents.push(id);dependencies.set(dep,parents);}if(!changed)break;}
 return {chosen,effective,dependencies};
}
interface Dependencies {
 target:(session:string)=>any;
 command:(session:string,op:string,args?:any)=>Promise<any>;
 verify:(target:any)=>Promise<void>;
 held:(session:string)=>boolean;
 drain:(session:string)=>Promise<any>;
 pause:(session:string)=>void;resume:(session:string)=>void;ensureDrain:(session:string)=>void;
 clearMemo?:(session:string)=>void;
}
export class CaptureControls {
 root:string;deps:Dependencies;private jobs=new Set<string>();
 constructor(root:string,deps:Dependencies){this.root=root;this.deps=deps;}
 private identity(a:any){assertRequestedTarget(a.serial,a.package);if(!validDeviceSerial(a.serial??'')||!validPackage(a.package??''))fail('TARGET_REQUIRED','需要明确设备串号和应用');return {serial:a.serial as string,package:a.package as string};}
 private file(a:any){const id=this.identity(a);return join(this.root,hash(id.serial+'\n'+id.package)+'.json');}
 private read(a:any){const file=this.file(a);if(!existsSync(file))return {schemaVersion:1,...this.identity(a),revision:0,config:emptyCaptureConfig(),catalogs:null,lastApplied:null,history:[],pending:true};const r=JSON.parse(readFileSync(file,'utf8'));if(r.schemaVersion!==1||r.serial!==a.serial||r.package!==a.package||!Number.isSafeInteger(r.revision)||r.revision<1)fail('CAPTURE_STORE_CORRUPT','配置文件损坏；未覆盖已有记录');return r;}
 private write(a:any,value:any){localEffect(()=>atomicWriteJson(this.file(a),value));}
 private target(a:any){if(!a.session)return null;const target=this.deps.target(a.session);if(!target?.online)fail('TARGET_OFFLINE','所选进程已离线，未执行');assertSessionScope(target);if(target.package!==a.package||target.deviceBinding?.serial!==a.serial)fail('TARGET_SCOPE_CONFLICT','会话不属于所选设备和应用');return target;}
 private async runtime(a:any,target:any){
  if(!target)return null;await this.deps.verify(target);const ops=target.caps?.ops??[];
  const domain=async(op:string)=>{if(!ops.includes(op))return {supported:false,methods:[],error:'当前 Agent 未声明此能力'};const r=await this.deps.command(a.session,op,{action:'status'});if(r.ok!==true)return {supported:false,methods:[],error:r.error??'状态读取失败'};return {supported:true,...r};};
  const [native,java,policy]=await Promise.all([domain('capture_methods'),domain('java_capture'),ops.includes('capture_policy')?this.deps.command(a.session,'capture_policy',{action:'status'}):Promise.resolve({ok:false})]);
  const methods=[...native.methods.map((m:any)=>({...m,backend:'native'})),...java.methods.map((m:any)=>({...m,backend:'java'}))];
  const identity={session:a.session,pid:target.pid,uid:target.uid,starttimeTicks:target.starttimeTicks,serial:a.serial};
  const stamp=(d:any)=>({supported:d.supported,catalog:d.catalog,revision:d.revision,on:d.on,settling:d.settling,methods:d.methods.map((m:any)=>({id:m.id,requested:m.requested,active:m.active,ownedSlots:m.ownedSlots,changedSlots:m.changedSlots,unreadableSlots:m.unreadableSlots,state:m.state}))});
  return {identity,native,java,policy:policy.policy??'',methods,token:hash(canonical({identity,native:stamp(native),java:stamp(java),policy:policy.policy??''}))};
 }
 async status(a:any){const record=this.read(a),target=this.target(a),runtime=await this.runtime(a,target);return {ok:true,...this.identity(a),session:a.session??null,revision:record.revision,config:record.config,history:record.history,lastApplied:record.lastApplied,lastIntent:record.intent??null,pending:record.pending||!target||record.lastApplied?.session!==a.session||record.lastApplied?.runtimeToken!==runtime?.token,automaticApply:false,foreignOwner:target?this.deps.held(a.session):false,runtime,catalogs:runtime?{native:runtime.native,java:runtime.java,methods:runtime.methods,historical:false}:record.catalogs?{...record.catalogs,historical:true}:null};}
 async discover(a:any){const target=this.target(a);if(!target)fail('TARGET_REQUIRED','读取 Java 目录需要明确在线进程');await this.deps.verify(target);if(!(target.caps?.ops??[]).includes('java_capture'))fail('UNSUPPORTED_CAPTURE_CONTROL','当前 Agent 不支持 Java 方法目录');if(this.deps.held(a.session))fail('CAPTURE_OWNER_CONFLICT','此进程由已有 Hook 计划持有，请先结束该计划');const r=await this.deps.command(a.session,'java_capture',{action:'discover'});if(r.ok!==true)fail('CAPTURE_DISCOVERY_FAILED',r.error??'目录读取失败');await this.waitSettled(a);return this.status(a);}
 private async waitSettled(a:any){for(let i=0;i<80;i++){const r=await this.deps.command(a.session,'java_capture',{action:'status'});if(!r.ok)fail('CAPTURE_READBACK_FAILED',r.error??'Java 状态读取失败');if(!r.settling)return r;await new Promise(r=>setTimeout(r,75));}throw Object.assign(new Error('Java 状态仍在变更，结果未确认；请只读刷新'),{uncertain:true,code:'CAPTURE_SETTLING_TIMEOUT'});}
 async change(a:any,apply:boolean){
  const id=this.identity(a),key=id.serial+'\n'+id.package;if(this.jobs.has(key))fail('CAPTURE_CONTROL_BUSY','此应用正在应用配置，请勿重复提交');this.jobs.add(key);
  let record:any,target:any,stage='preflight',paused=false,wrote=false;const receipts:any[]=[];
  const command=async(op:string,args?:any)=>{await this.deps.verify(target);const r=await this.deps.command(a.session,op,args);receipts.push({op,args,result:r});if(r.ok!==true)fail('CAPTURE_APPLY_FAILED',`${op}: ${r.error??'目标拒绝操作'}`);return r;};
  try{
   record=this.read(a);if(a.expectedRevision!==record.revision)fail('STALE_CAPTURE_CONFIG','配置已被其他页面修改，请保留草稿后刷新');target=this.target(a);
   if(apply&&!target)fail('TARGET_REQUIRED','应用配置必须选择明确的在线进程');
   const before=await this.runtime(a,target),catalogs=before?{native:before.native,java:before.java,methods:before.methods,historical:false}:record.catalogs;
   const config=validateCaptureConfig(a.config,catalogs?.methods??[]),desired=desiredCaptureMethods(config,catalogs?.methods??[]);
   if(apply){
    if(!before||a.runtimeToken!==before.token)fail('STALE_CAPTURE_RUNTIME','进程或运行时版本已改变，未执行；请刷新后核对草稿');
    if(this.deps.held(a.session))fail('CAPTURE_OWNER_CONFLICT','此进程由已有 Hook 计划持有，不能覆盖其他计划');
    if(!before.native.supported||!(target.caps?.ops??[]).includes('capture_stop')||!(target.caps?.ops??[]).includes('capture_policy'))fail('UNSUPPORTED_CAPTURE_CONTROL','Agent 缺少安全停止/方法配置能力，请升级后重试');
    if([...desired.chosen].some(x=>x.startsWith('java.'))&&(!before.java.supported||!before.java.discovered||before.java.truncated))fail('JAVA_CATALOG_REQUIRED','请先读取完整 Java 方法目录');
    if([...desired.chosen].some(x=>x.startsWith('native.'))&&a.confirmRisk!==true)fail('CAPTURE_CONFIRM_REQUIRED','Native Hook 会改变目标进程，请确认模块范围及开销');
   }
   record={...record,revision:record.revision+1,config,catalogs,pending:true,history:record.revision?[{revision:record.revision,config:record.config,at:Date.now()},...(record.history??[])].slice(0,10):[],intent:apply?{id:randomUUID(),session:a.session,state:'applying',at:Date.now()}:null};this.write(a,record);wrote=true;
   if(!apply)return {ok:true,state:'saved-pending',persisted:true,applied:false,revision:record.revision,automaticApply:false};
   this.deps.ensureDrain(a.session);this.deps.pause(a.session);paused=true;stage='drain';const drain=await this.deps.drain(a.session);if(!drain?.ok)fail('CAPTURE_DRAIN_FAILED',drain?.error??'未能确认旧记录已排空');receipts.push({op:'host-drain',result:drain});
   stage='stop';await command('capture_stop');this.deps.clearMemo?.(a.session);if(before.java.supported)await this.waitSettled(a);
   const stopped=await this.runtime(a,target);for(const name of ['native','java']as const)if(before[name].supported&&(stopped![name].catalog!==before[name].catalog||stopped![name].revision!==before[name].revision))fail('STALE_CAPTURE_RUNTIME','停止期间方法目录或选项被其他控制方修改，未继续覆盖');
   stage='select';const selected=(methods:any[])=>methods.map((m:any)=>desired.chosen.has(m.id)?'1':'0').join('');
   const ns=await command('capture_methods',{action:'set',catalog:before.native.catalog,revision:before.native.revision,selection:selected(before.native.methods)});
   const js=before.java.supported&&before.java.discovered?await command('java_capture',{action:'set',catalog:before.java.catalog,revision:before.java.revision,selection:selected(before.java.methods)}):null;
   stage='policy';const flags=CAPTURE_FEATURES.slice(0,7).map(([key],i)=>'dhsatey'[i]+'='+(config.features[key].enabled?'1':'0')).join(',');
   await command('capture_policy',{families:flags});const changed=before.policy!==flags?1:0;
   const policyState=await this.runtime(a,target);if(policyState!.policy!==flags||String(Number(ns.revision)+changed)!==policyState!.native.revision||(js&&String(Number(js.revision)+changed)!==policyState!.java.revision))fail('CAPTURE_READBACK_CONFLICT','策略或版本读回不一致，未继续启动');
   stage='start';if([...desired.effective].some(id=>id.startsWith('native.')))await command('capture_start',{cryptoModule:config.modules.crypto,fileModule:config.features.file.enabled?config.modules.file:'',sysModule:config.features.system.enabled?config.modules.system:''});
   if([...desired.effective].some(id=>id.startsWith('java.'))){await command('java_capture',{action:'start'});await this.waitSettled(a);}
   stage='readback';const after=await this.runtime(a,target);if(after!.native.revision!==policyState!.native.revision||after!.java.revision!==policyState!.java.revision)fail('CAPTURE_READBACK_CONFLICT','启动期间运行时选项改变，请只读核查');
   const results=after!.methods.map((m:any)=>{const expected=desired.effective.has(m.id),active=m.backend==='java'?m.active===true:Number(m.ownedSlots)>0;const conflict=Number(m.changedSlots)>0||Number(m.unreadableSlots)>0;return {id:m.id,expected,active,dependency:desired.dependencies.has(m.id),state:m.state,ok:expected?active&&!conflict:!active&&!conflict,error:m.error||null,retainedPatch:m.patched===true};});
   const complete=results.every(r=>r.ok);record.pending=!complete;record.intent={...record.intent,state:complete?'applied':'partial',stage,results,receipts,at:Date.now()};
   if(complete)record.lastApplied={session:a.session,identity:after!.identity,config,revision:record.revision,runtimeToken:after!.token,at:Date.now()};this.write(a,record);
   return {ok:complete,state:complete?'applied':'partial',persisted:true,applied:complete,revision:record.revision,results,receipts,runtime:after,automaticApply:false,...(!complete?{error:'部分方法未获得实际安装回执，请查看逐项状态；未自动重试'}:{})};
  }catch(e){if(!wrote)throw e;const error=e as any,unknown=error.uncertain===true||['COMMAND_TIMEOUT','TARGET_OFFLINE','DEVICE_ROUTE_EXPIRED'].includes(error.code);record.pending=true;record.intent={...record.intent,state:unknown?'unknown':'failed',stage,receipts,error:error.message,code:error.code,at:Date.now()};this.write(a,record);return {ok:false,state:record.intent.state,persisted:true,applied:false,revision:record.revision,stage,receipts,error:error.message,code:error.code,automaticRetry:false};}
  finally{if(paused)this.deps.resume(a.session);this.jobs.delete(key);}
 }
 has(serial:string,pkg:string){return existsSync(this.file({serial,package:pkg}));}
}
let controller:CaptureControls|undefined;
export function getCaptureControls(){return controller??=new CaptureControls(join(DATA_DIR,'capture-controls'),{target:id=>sessions.get(id),command:sendCmd,verify:verifyAgentBinding,held:id=>getHookPlans().heldSessions().has(id),drain:drainSession,pause:pauseCaptureDrains,resume:resumeCaptureDrains,ensureDrain:id=>startCaptureLoop(id,{skipArm:true}),clearMemo:clearCaptureEchoMemo});}
export async function captureControlAction(a:any){const c=getCaptureControls();switch(a.action??'get'){case'get':return c.status(a);case'discover':return c.discover(a);case'save':return c.change(a,false);case'apply':return c.change(a,true);default:return fail('INVALID_ACTION','未知的 Hook 管理动作');}}

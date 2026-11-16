import {existsSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {atomicWriteJson} from './storage.ts';
import {checkpoint,executionContext,localEffect,OperationError} from './execution_context.ts';
import {sessions} from './state.ts';
import {agentCmd} from './service.ts';

export const FAMILY_KEYS=['digest','hmac','symmetric','asymmetric','tls','aead','system'] as const;
const SHORT=['d','h','s','a','t','e','y'];
const TOOLS=new Set(['native_hook','java_hook','jni_onload','module_watch','capture_start']);
export const canonical=(value:any):string=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
export const digest=(value:any)=>createHash('sha256').update(canonical(value)).digest('hex');
const fail=(code:string,message:string):never=>{throw new OperationError(code,message);};
function object(value:any,keys:string[]){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.includes(k)))fail('INVALID_PLAN','invalid or unknown plan fields');}
export interface HookPlan {schemaVersion:1;id:string;title:string;package:string;families:Record<string,boolean>;steps:{id:string;tool:string;arguments:any;waitMs?:number}[];metadata?:any}
export interface PlanTool {inputSchema:any;handler:(args:any)=>Promise<any>}
type Lookup=(name:string)=>PlanTool|undefined;
export function validatePlan(value:any,lookup?:Lookup):HookPlan {
  object(value,['schemaVersion','id','title','package','families','steps','metadata']);
  if(value.schemaVersion!==1||!/^[a-z][a-z0-9_-]{0,63}$/.test(value.id)||typeof value.title!=='string'||value.title.length>160||!/^[A-Za-z][\w]*(\.[\w]+)+$/.test(value.package)||['com.adh.manager','com.adh.daemon'].includes(value.package))fail('INVALID_PLAN','schema/id/title/package invalid');
  object(value.families,[...FAMILY_KEYS]);if(!FAMILY_KEYS.every(k=>typeof value.families[k]==='boolean'))fail('INVALID_PLAN','all seven family decisions must be explicit');
  if(!Array.isArray(value.steps)||!value.steps.length||value.steps.length>32||Buffer.byteLength(canonical(value))>128*1024)fail('INVALID_PLAN','plan must have 1..32 steps and fit 128 KiB');
  const ids=new Set();for(const step of value.steps){
    object(step,['id','tool','arguments','waitMs']);if(!/^[a-z][\w-]{0,63}$/.test(step.id)||ids.has(step.id)||!TOOLS.has(step.tool))fail('INVALID_PLAN','step id/tool invalid');ids.add(step.id);
    if(step.waitMs!==undefined&&(!Number.isInteger(step.waitMs)||step.waitMs<0||step.waitMs>600000))fail('INVALID_PLAN','step wait must be 0..600000 ms');
    if(!step.arguments||Array.isArray(step.arguments)||typeof step.arguments!=='object'||['session','deviceId','connectionId','_operation','transport','__proto__','constructor','prototype'].some(k=>Object.hasOwn(step.arguments,k)))fail('INVALID_PLAN','step arguments cannot replace scope or authorization');
    if(step.tool==='capture_start'&&!['cryptoModule','fileModule','sysModule'].every(k=>typeof step.arguments[k]==='string'))fail('INVALID_PLAN','capture modules must all be explicit; empty cryptoModule deliberately scans all');
    if(step.tool!=='capture_start'&&!['hook','hookAll','start'].includes(step.arguments.action))fail('INVALID_PLAN','plan steps install only; observe and undo are separate actions');
    if(step.tool==='native_hook'&&step.arguments.action!=='hook'||step.tool==='java_hook'&&!['hook','hookAll'].includes(step.arguments.action)||step.tool==='jni_onload'&&step.arguments.action!=='hook'||step.tool==='module_watch'&&step.arguments.action!=='start')fail('INVALID_PLAN','tool action not supported by this plan version');
    const schema=lookup?.(step.tool)?.inputSchema;if(lookup&&!schema)fail('UNSUPPORTED_PLAN_TOOL','plan tool is unavailable');
    if(schema){for(const [key,arg]of Object.entries(step.arguments)){const spec=schema.properties[key];if(!spec)fail('INVALID_PLAN','unknown argument '+key+' for '+step.tool);
      if(spec.type==='string'&&typeof arg!=='string'||spec.type==='boolean'&&typeof arg!=='boolean'||spec.type==='number'&&typeof arg!=='number'||spec.type==='integer'&&!Number.isInteger(arg)||spec.enum&&!spec.enum.includes(arg))fail('INVALID_PLAN','argument type/enum invalid: '+key);}
      for(const key of schema.required||[])if(key!=='session'&&!Object.hasOwn(step.arguments,key))fail('INVALID_PLAN','missing argument '+key);
    }
  }return structuredClone(value);
}
export function familyFlags(families:Record<string,boolean>){return SHORT.map((key,n)=>key+'='+(families[FAMILY_KEYS[n]]?'1':'0')).join(',');}

/** Immutable bodies + CAS heads; no import/startup I/O or automatic application. */
export class HookPlans {
  readonly root:string;
  constructor(root:string){this.root=root;}
  private index(){const file=join(this.root,'library.json');if(!existsSync(file))return {schemaVersion:1,revision:0,heads:{}} as any;const data=JSON.parse(readFileSync(file,'utf8'));if(data.schemaVersion!==1||!Number.isSafeInteger(data.revision)||!data.heads||Array.isArray(data.heads))fail('PLAN_LIBRARY_CORRUPT','plan index cannot be rebuilt automatically');return data;}
  list(){const index=this.index();return {ok:true,revision:index.revision,plans:Object.entries(index.heads).map(([id,entry]:any)=>({id,...entry})),automaticApply:false};}
  get(hash:string){if(!/^[a-f0-9]{64}$/.test(hash||''))fail('PLAN_VERSION_REQUIRED','select an immutable plan digest');const value=JSON.parse(readFileSync(join(this.root,'versions',hash+'.json'),'utf8'));if(digest(value)!==hash)fail('PLAN_LIBRARY_CORRUPT','plan body digest differs');return {ok:true,digest:hash,plan:validatePlan(value)};}
  put(value:any,expectedRevision:number,lookup?:Lookup){const plan=validatePlan(value,lookup),index=this.index();if(expectedRevision!==index.revision)fail('STALE_PLAN_LIBRARY','library changed; preserve draft and re-plan');
    const hash=digest(plan),file=join(this.root,'versions',hash+'.json');
    localEffect(()=>{if(existsSync(file)){if(digest(JSON.parse(readFileSync(file,'utf8')))!==hash)fail('PLAN_LIBRARY_CORRUPT','immutable body differs');}else atomicWriteJson(file,plan);
      index.heads[plan.id]={digest:hash,title:plan.title,package:plan.package,updatedAt:Date.now()};index.revision++;atomicWriteJson(join(this.root,'library.json'),index);},{kind:'host',action:'hook-plan.version.save'});
    return {ok:true,digest:hash,revision:index.revision,applied:false};
  }
  preflight(hash:string,sid:string,lookup:Lookup){const {plan}=this.get(hash);validatePlan(plan,lookup);const s=sessions.get(sid);if(!s?.online||s.package!==plan.package)fail('PLAN_TARGET_MISMATCH','select an explicit online generation of the plan package');
    const required=['capture_policy',...plan.steps.map(x=>x.tool)];const absent=[...new Set(required)].filter(op=>!s.caps?.ops?.includes(op));return {ok:!absent.length,digest:hash,session:sid,package:s.package,process:s.process,pid:s.pid,uid:s.uid,starttimeTicks:s.starttimeTicks,missingCapabilities:absent,willApply:false,steps:plan.steps.map(x=>({id:x.id,tool:x.tool,waitMs:x.waitMs||0})),sideEffects:['changes future capture-family eligibility',...plan.steps.filter(x=>x.tool==='capture_start').map(()=>'replaces the session persistent capture set')]};}
  async apply(hash:string,sid:string,lookup:Lookup){const preflight=this.preflight(hash,sid,lookup);if(!preflight.ok)fail('UNSUPPORTED_AGENT','required agent operations missing: '+preflight.missingCapabilities.join(','));
    const {plan}=this.get(hash),ctx=executionContext.getStore();if(!ctx?.operationId)fail('OPERATION_REQUIRED','plan execution needs the shared coordinator');checkpoint(sid);
    const run:any={id:ctx.operationId,digest:hash,session:sid,generation:preflight,state:'running',receipts:[],createdAt:Date.now(),previousPolicy:sessions.get(sid)?.policy};const file=join(this.root,'runs',run.id+'.json');
    const persist=()=>atomicWriteJson(file,run);localEffect(persist,{kind:'host',action:'hook-plan.run.reserve'});
    try{
      const before=await agentCmd(sid,'capture_policy',{action:'status'});if(before.ok!==true||!/^d=[01],h=[01],s=[01],a=[01],t=[01],e=[01],y=[01]$/.test(before.policy))fail('UNSUPPORTED_AGENT','agent did not confirm the previous family policy');run.previousPolicy=before.policy;persist();
      const flags=familyFlags(plan.families),reply=await agentCmd(sid,'capture_policy',{families:flags});run.receipts.push({id:'families',tool:'capture_policy',reply});persist();if(reply.ok!==true)fail('PLAN_STEP_FAILED','agent refused explicit family policy');sessions.get(sid)!.policy=flags;
      for(const step of plan.steps){checkpoint(sid);if(step.waitMs){if(step.waitMs>=(ctx.remainingMs?.()||0))fail('PLAN_BUDGET','wait exceeds remaining operation budget');await new Promise(r=>setTimeout(r,step.waitMs));checkpoint(sid);}
        const reply=await lookup(step.tool)!.handler({...step.arguments,session:sid});run.receipts.push({id:step.id,tool:step.tool,arguments:step.arguments,reply});if(step.tool==='capture_start')run.captureFingerprint=digest(sessions.get(sid)?.captureHooks||{});persist();if(reply.ok!==true||reply.partial===true&&step.tool!=='capture_start')fail('PLAN_STEP_FAILED','step '+step.id+' did not confirm the requested installation');
      }
      run.captureFingerprint=digest(sessions.get(sid)?.captureHooks||{});run.state='applied';run.finishedAt=Date.now();persist();return {ok:true,run,applied:true};
    }catch(error){run.state=(error as any).uncertain?'unknown':'partial-or-failed';run.error={code:(error as any).code||'PLAN_FAILED',message:(error as Error).message};persist();throw error;}
  }
  run(id:string){if(!/^[\w-]{1,128}$/.test(id||''))fail('INVALID_ARGUMENT','invalid run id');return JSON.parse(readFileSync(join(this.root,'runs',id+'.json'),'utf8'));}
  async observe(id:string,lookup:Lookup){const run=this.run(id),s=sessions.get(run.session);if(!s?.online||s.pid!==run.generation.pid||s.uid!==run.generation.uid||s.starttimeTicks!==run.generation.starttimeTicks)fail('PLAN_TARGET_MISMATCH','run belongs to another or offline process generation');
    const observed:any={};for(const tool of new Set(run.receipts.map((r:any)=>r.tool))){if(tool==='native_hook'||tool==='java_hook')observed[String(tool)]=await lookup(String(tool))!.handler({action:'status',session:run.session});}
    const policy=await agentCmd(run.session,'capture_policy',{action:'status'});
    return {ok:true,run,observed,policy,appliedIsHistorical:true,earlyReport:s.earlyPlan||null};
  }
  async undo(id:string,lookup:Lookup){const recorded=this.run(id);if(!['applied','undone'].includes(recorded.state))fail('UNSUPPORTED_UNDO','partial/unknown run can contain unacknowledged effects; inspect and remove explicitly');if(recorded.state!=='undone'&&recorded.receipts.some((r:any)=>r.tool==='capture_start'))fail('UNSUPPORTED_UNDO','persistent capture ownership cannot be verified from a historical Host reply; inspect and explicitly capture_stop');const {run,observed,policy}=await this.observe(id,lookup);checkpoint(run.session);if(run.state==='undone')return {ok:true,alreadyUndone:true,run};
    if(policy.policy!==familyFlags(this.get(run.digest).plan.families))fail('STALE_RUNTIME','agent family policy changed; re-plan undo explicitly');
    // Only owned, verifiable single hooks can be removed; never remove all hooks after an ambiguous batch.
    for(const r of run.receipts){if(r.tool==='capture_policy')continue;
      if(!['native_hook','java_hook'].includes(r.tool)||!Number.isInteger(r.reply.hookId))fail('UNSUPPORTED_UNDO','step lacks an individually owned hook id; inspect and remove explicitly');
      const reply=observed[r.tool],rows=reply?.status?.hooks||reply?.hooks||reply?.status;
      if(!Array.isArray(rows)||!rows.some((h:any)=>Number(h.id??h.hookId)===r.reply.hookId&&(r.tool!=='native_hook'||h.module===r.arguments.module&&h.symbol===r.arguments.symbol)))fail('STALE_RUNTIME','hook ownership is not verified');
    }
    run.undoReceipts=[];for(const r of [...run.receipts].reverse()){checkpoint(run.session);if(r.tool==='capture_policy')continue;const reply=await lookup(r.tool)!.handler({action:'unhook',hookId:r.reply.hookId,session:run.session});run.undoReceipts.push({id:r.id,reply});atomicWriteJson(join(this.root,'runs',id+'.json'),run);if(reply.ok!==true)fail('PLAN_UNDO_UNCONFIRMED','undo step did not confirm');}
    // Do not silently overwrite a family policy changed after this plan.
    if(sessions.get(run.session)?.policy!==familyFlags(this.get(run.digest).plan.families))fail('STALE_RUNTIME','family policy changed; old policy not restored');
    const previous=run.previousPolicy&&run.previousPolicy!=='default'?run.previousPolicy:'d=1,h=1,s=1,a=1,t=1,e=1,y=0';const reply=await agentCmd(run.session,'capture_policy',{families:previous});if(reply.ok!==true)fail('PLAN_UNDO_UNCONFIRMED','family restore unconfirmed');sessions.get(run.session)!.policy=previous;
    run.state='undone';atomicWriteJson(join(this.root,'runs',id+'.json'),run);return {ok:true,run};
  }
}

export function legacyPlan(scope:any,settings:any,pkg:string,id:string):HookPlan {
  if(!scope?.packages?.includes(pkg))fail('INVALID_PLAN','legacy package is not in scope');const c=scope.policy?.[pkg]?.c||{},families=Object.fromEntries(FAMILY_KEYS.map((k,n)=>[k,typeof c[SHORT[n]]==='boolean'?c[SHORT[n]]:k!=='system']));
  const capture=settings?.capture||{},steps:any[]=[];const startup=settings?.startup||{};
  if(startup.antiDebug&&(!startup.packages?.length||startup.packages.includes(pkg)))for(const symbol of ['ptrace',...(startup.extraTargets||[])])steps.push({id:'startup-'+steps.length,tool:'native_hook',arguments:{action:'hook',mode:'inline',module:startup.module||'libc.so',symbol,skipOriginal:true,returnValue:'-1',errno:13}});
  steps.push({id:'capture',tool:'capture_start',arguments:{cryptoModule:capture.cryptoModule??'',fileModule:capture.fileModule??'',sysModule:capture.sysModule??''}});
  if(startup.antiDebug&&startup.widenAfterMs>0&&(!startup.packages?.length||startup.packages.includes(pkg)))for(const symbol of startup.widenTargets||[])steps.push({id:'widen-'+steps.length,tool:'native_hook',waitMs:steps.some(x=>x.id.startsWith('widen'))?0:startup.widenAfterMs,arguments:{action:'hook',mode:'inline',module:startup.module||'libc.so',symbol,skipOriginal:true,returnValue:'-1',errno:13}});
  return validatePlan({schemaVersion:1,id,title:'Migrated '+pkg,package:pkg,families,steps,metadata:{legacy:{scope:structuredClone(scope),settings:structuredClone(settings),scopeDigest:digest(scope)},automaticApply:false,warning:'Snapshot preserves unknown/retired fields; capture output filters and retired bypass are not installed by this plan.'}});
}

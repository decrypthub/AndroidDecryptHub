import { join } from 'node:path';
import { DATA_DIR, sessions } from './state.ts';
import { Operations, operationFailure, type OperationMeta, type Principal } from './operations.ts';
import { describeTool, type OperationSpec } from './operation_registry.ts';
import { initializeOperatorAccess } from './access_context.ts';
import { OperationError } from './execution_context.ts';

export const operationsRoot=join(DATA_DIR,'operations');
let coordinator: Operations | undefined;
export function targetResource(session: string) {
  const target=sessions.get(session);
  if(!target || !target.online)throw new OperationError('TARGET_OFFLINE','explicit online session required');
  return `target:${session}:${target.pid}:${target.uid}:${target.starttimeTicks || 'legacy'}`;
}
export function getOperations() { return coordinator ??= new Operations(operationsRoot,targetResource); }
export function initializeOperations() { initializeOperatorAccess(operationsRoot); return getOperations(); }
export function automaticSnapshot(session: string) { return getOperations().snapshot(targetResource(session)); }
export async function runAutomatic(session: string, name: string, meta: ReturnType<typeof automaticSnapshot>, fn:()=>Promise<any>) {
  try {
    const engine=getOperations(),current=engine.snapshot(targetResource(session));
    if(current.epoch!==meta.epoch || current.hostEpoch!==meta.hostEpoch)throw new OperationError('STALE_CONTROL','automatic policy was invalidated by a control change');
    const op=await engine.execute({name,mode:'write',session},{session},
      {role:'ai',id:'host-automatic',source:'automatic'},
      {expectedRevision:current.revision,controlEpoch:meta.epoch,hostEpoch:meta.hostEpoch},fn);
    return responseForOperation(op);
  } catch(error) { return operationFailure(error); }
}
export function resolveSpec(spec: OperationSpec, args: any) {
  if(spec.mode==='write' && !spec.global && !spec.session) {
    const online=[...sessions.values()].filter(s=>s.online);
    if(online.length!==1)throw new OperationError('TARGET_REQUIRED','choose an explicit session; targets are ambiguous or offline');
    spec={...spec,session:online[0].sessionId};
    args.session=spec.session;
  }
  return spec;
}
export function responseForOperation(op: any,transport:'mcp'|'http'='mcp') {
  const metadata={ id:op.id,taskId:op.taskId,state:op.state,resource:op.resource,mayHaveExecuted:op.mayHaveExecuted,
    cancelRequested:op.cancelRequested,inFlight:op.inFlight,revision:op.appliedRevision,controlEpoch:op.controlEpoch };
  if(op.result!==undefined) {
    const stored=op.result;
    const envelope=stored && typeof stored==='object' && typeof stored.httpStatus==='number' && Object.hasOwn(stored,'body');
    const result=transport==='http' ? envelope?stored:{httpStatus:stored?.ok===false?400:200,body:stored,contentType:'application/json'} : envelope?stored.body:stored;
    const failure=op.state==='unknown'?{ok:false,code:'UNKNOWN_EXECUTION',error:'some effects remain unconfirmed; inspect the durable operation'}:{};
    return result && typeof result==='object' && !Array.isArray(result) ? {...result,...failure,_operation:metadata}
      : {ok:op.state==='succeeded',value:result,_operation:metadata};
  }
  return {ok:false,code:op.error?.code || (op.state==='unknown'?'UNKNOWN_EXECUTION':'OPERATION_PENDING'),
    error:op.error?.message || 'operation has not completed',_operation:metadata};
}
export async function executeManaged(spec: OperationSpec,args:any,principal:Principal,fn:()=>Promise<any>,transport:'mcp'|'http'='mcp') {
  spec=resolveSpec(spec,args);
  if(spec.mode==='read' && !args._operation?.taskId)return fn();
  const op=await getOperations().execute(spec,args,principal,args._operation || {},fn);
  return responseForOperation(op,transport);
}

type ToolLookup=(name:string)=>{handler:(args:any)=>Promise<any>} | undefined;
export async function manageOperations(a:any,principal:Principal,lookup?:ToolLookup) {
  const engine=getOperations();
  const specFor=()=>resolveSpec(describeTool(a.tool || 'settings',a.arguments || {action:'patch',session:a.session}),a.arguments || {session:a.session});
  if(a.action==='snapshot') {
    const spec=a.tool?specFor():{name:'snapshot',mode:'read' as const,session:a.session};
    return {ok:true,...engine.snapshot(a.resource || engine.resource(spec)),role:principal.role};
  }
  if(a.action==='create')return {ok:true,task:engine.createTask(a.title,principal)};
  if(a.action==='list')return {ok:true,...engine.list(a.taskId,Math.max(1,Math.min(100,Number(a.limit)||50)),Math.max(0,Math.min(10000,Number(a.offset)||0)))};
  if(a.action==='get') {
    if(a.taskId) {
      const tasks=engine.store.read().tasks;
      const task=Object.hasOwn(tasks,a.taskId)?tasks[a.taskId]:undefined;
      if(!task)throw new OperationError('TASK_NOT_FOUND','task does not exist');
      return {ok:true,task,...engine.list(a.taskId)};
    }
    return {ok:true,operation:engine.getOperation(a.id,a.includeResult===true)};
  }
  if(['pause','resume','cancel','complete'].includes(a.action)) {
    if(a.id && a.action==='cancel')return {ok:true,operation:engine.cancelOperation(a.id,principal)};
    return {ok:true,task:engine.taskAction(a.taskId,a.action,principal)};
  }
  if(['takeover','release','resolve','hold'].includes(a.action)) {
    return {ok:true,...engine.control(a.action==='hold'?'pause':a.action,a.resource || (a.session?targetResource(a.session):'host'),principal,a._operation || {},a.acknowledge===true)};
  }
  if(a.action==='submit') {
    if(a.tool==='operations')throw new OperationError('INVALID_OPERATION','cannot recursively submit operation management');
    const tool=lookup?.(a.tool);if(!tool)throw new OperationError('UNKNOWN_TOOL','unknown operation tool');
    const args={...(a.arguments || {})},spec=resolveSpec(describeTool(a.tool,args),args);
    const operation=engine.submit(spec,args,principal,a._operation || {},()=>tool.handler(args));
    return {ok:true,operation};
  }
  return operationFailure(new OperationError('INVALID_ACTION','unknown operations action'));
}

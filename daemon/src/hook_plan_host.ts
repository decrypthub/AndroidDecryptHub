import {join} from 'node:path';
import {DATA_DIR,settings} from './state.ts';
import {HookPlans,validatePlan,legacyPlan,canonical,type PlanTool} from './hook_plans.ts';
import {getDevices} from './device_host.ts';
import {OperationError} from './execution_context.ts';
import {getOperations} from './operation_host.ts';
let library:HookPlans|undefined;
export const getHookPlans=()=>library??=new HookPlans(join(DATA_DIR,'hook-plans'));
type Lookup=(name:string)=>PlanTool|undefined;
export async function hookPlanAction(a:any,lookup:Lookup){
  const plans=getHookPlans();
  switch(a.action||'list'){
    case 'list':return plans.list();
    case 'get':return plans.get(a.digest);
    case 'validate':return {ok:true,plan:validatePlan(a.plan,lookup),applied:false};
    case 'put':return plans.put(a.plan,a.expectedLibraryRevision,lookup);
    case 'import-legacy':return plans.put(legacyPlan(a.scope,a.settings||structuredClone(settings),a.package,a.id),a.expectedLibraryRevision,lookup);
    case 'preflight':return plans.preflight(a.digest,a.session,lookup);
    case 'apply':return plans.apply(a.digest,a.session,lookup);
    case 'run':return {ok:true,run:plans.run(a.runId),operation:getOperations().getOperation(a.runId),recordedStateIsHistorical:true};
    case 'observe':return {...await plans.observe(a.runId,lookup),operation:getOperations().getOperation(a.runId)};
    case 'undo':if(plans.run(a.runId).session!==a.session)throw new OperationError('PLAN_TARGET_MISMATCH','undo must name the original session');return plans.undo(a.runId,lookup);
    case 'early-prepare':return getDevices().call({...a,method:'early.prepare',params:{package:a.package}});
    case 'early-status':return getDevices().call({...a,method:'early.status',params:{package:a.package}});
    case 'early-stage':{
      const {plan}=plans.get(a.digest);validatePlan(plan,lookup);
      return getDevices().call({...a,method:'early.stage',params:{plan,canonicalPlan:canonical(plan),digest:a.digest,binding:a.binding,expiresAt:a.expiresAt,offline:a.offline,expectedCacheRevision:a.expectedCacheRevision}});
    }
    case 'early-revoke':return getDevices().call({...a,method:'early.revoke',params:{package:a.package,deploymentId:a.deploymentId,expectedCacheRevision:a.expectedCacheRevision}});
    case 'migration-preview':return getDevices().call({...a,method:'hooks.migration.preview',params:{package:a.package}});
    case 'migration-apply':return getDevices().call({...a,method:'hooks.migration.apply',params:{package:a.package,scopeRevision:a.scopeRevision,planDigest:a.digest}});
    case 'migration-rollback':return getDevices().call({...a,method:'hooks.migration.rollback',params:{migrationId:a.migrationId,scopeRevision:a.scopeRevision}});
    default:throw new OperationError('INVALID_ACTION','unknown hook plan action');
  }
}

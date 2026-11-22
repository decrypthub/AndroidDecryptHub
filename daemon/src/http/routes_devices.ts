import {deviceAction} from '../device_host.ts';
import {readBody,sessions} from '../state.ts';
import {localObserver,OWN_APP_FILES_ROUTE} from '../local_observer.ts';
import {AppFilesError,readOwnedAppFiles} from '../owned_app_files.ts';
import type {Route,RouteContext} from './types.ts';
/** Wrapped by the same router/operation registry as MCP; no privileged second execution path. */
export function deviceRoutes({req,url,send}:RouteContext):Route[]{
  const online=()=>!!localObserver&&[...sessions.values()].some(s=>
    s.online&&s.pid===localObserver.pid&&s.package===localObserver.package);
  return [{path:'/api/devices',handler:async()=>{
  if(localObserver && req.method==='GET' && url.searchParams.get('action')==='list'){
    // The app session came over the selected USB connection; this is not a paired Device identity.
    return send(200,{ok:true,devices:[],localUsb:{model:localObserver.model,online:online(),appFiles:!!localObserver.ownFilesSerial}});
  }
  const args=req.method==='GET'?Object.fromEntries(url.searchParams):JSON.parse(await readBody(req)||'{}');
  const result=await deviceAction(args);return send(result.ok===false?400:200,result);
  }},{method:'GET',path:OWN_APP_FILES_ROUTE,handler:async()=>{
    if(!localObserver?.ownFilesSerial) return send(403,{ok:false,error:'此入口未启用调试 APP 的只读目录。'});
    if(!online()) return send(409,{ok:false,error:'当前 APP 会话不在线。'});
    try{
      const result=await readOwnedAppFiles(localObserver,url.searchParams.get('action')||'',url.searchParams.get('path')||'');
      if(!online()) return send(409,{ok:false,error:'当前 APP 会话已断开。'});
      return send(200,result);
    }catch(e){
      if(e instanceof AppFilesError) return send(e.status,{ok:false,error:e.message});
      return send(503,{ok:false,error:'目录读取失败。'});
    }
  }}];
}

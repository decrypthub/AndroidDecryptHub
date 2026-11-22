import {deviceAction} from '../device_host.ts';
import {readBody,sessions} from '../state.ts';
import {localObserver} from '../local_observer.ts';
import type {Route,RouteContext} from './types.ts';
/** Wrapped by the same router/operation registry as MCP; no privileged second execution path. */
export function deviceRoutes({req,url,send}:RouteContext):Route[]{return [{path:'/api/devices',handler:async()=>{
  if(localObserver && req.method==='GET' && url.searchParams.get('action')==='list'){
    const online=[...sessions.values()].some(s=>s.online&&s.pid===localObserver.pid&&s.package===localObserver.package);
    // The app session came over the selected USB connection; this is not a paired Device identity.
    return send(200,{ok:true,devices:[],localUsb:{model:localObserver.model,online}});
  }
  const args=req.method==='GET'?Object.fromEntries(url.searchParams):JSON.parse(await readBody(req)||'{}');
  const result=await deviceAction(args);return send(result.ok===false?400:200,result);
}}];}

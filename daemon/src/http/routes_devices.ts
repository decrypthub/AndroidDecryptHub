import {deviceAction} from '../device_host.ts';
import {readBody} from '../state.ts';
import type {Route,RouteContext} from './types.ts';
/** Wrapped by the same router/operation registry as MCP; no privileged second execution path. */
export function deviceRoutes({req,url,send}:RouteContext):Route[]{return [{path:'/api/devices',handler:async()=>{
  const args=req.method==='GET'?Object.fromEntries(url.searchParams):JSON.parse(await readBody(req)||'{}');
  const result=await deviceAction(args);return send(result.ok===false?400:200,result);
}}];}

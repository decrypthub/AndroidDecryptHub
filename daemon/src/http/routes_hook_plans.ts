import {hookPlanAction} from '../hook_plan_host.ts';
import {MCP_MAP} from '../mcp.ts';
import {readBody} from '../state.ts';
import type {Route,RouteContext} from './types.ts';
export function hookPlanRoutes({req,url,send}:RouteContext):Route[]{return [{path:'/api/hook-plans',handler:async()=>{
  const args=req.method==='GET'?Object.fromEntries(url.searchParams):JSON.parse(await readBody(req)||'{}');
  const result:any=await hookPlanAction(args,name=>MCP_MAP.get(name));return send(result.ok===false?400:200,result);
}}];}

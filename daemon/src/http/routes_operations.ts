import { MCP_MAP } from '../mcp.ts';
import { describeHttp } from '../operation_registry.ts';
import { getOperations, manageOperations, operationsRoot, resolveSpec } from '../operation_host.ts';
import { requestPrincipal } from '../access_context.ts';
import { operationFailure } from '../operations.ts';
import { readBody } from '../state.ts';
import type { Route, RouteContext } from './types.ts';

export function operationsRoutes({req,url,send}:RouteContext):Route[] {
  return [{path:'/api/operations',prefix:true,handler:async()=>{
    try {
      const principal=requestPrincipal(req.headers,'panel',operationsRoot);
      const body=req.method==='POST'?JSON.parse(await readBody(req)||'{}'):Object.fromEntries(url.searchParams);
      if(url.pathname==='/api/operations/prepare') {
        const args={...(body.arguments||{})},spec=resolveSpec(describeHttp(body.path,body.method||'GET',args),args);
        return send(200,{ok:true,spec,role:principal.role,...getOperations().snapshot(getOperations().resource(spec))});
      }
      const result=await manageOperations(body,principal,name=>MCP_MAP.get(name));
      return send(result.ok===false?400:200,result);
    } catch(error) { const failure=operationFailure(error);return send(failure.code==='AUTH_FAILED'?403:409,failure); }
  }}];
}

import type http from 'node:http';

import { handleMcp } from '../mcp.ts';
import { readBody, sessions } from '../state.ts';
import { packageFromPath } from './package_path.ts';
import { analysisRoutes, serveDashboard } from './routes_analysis.ts';
import { runtimeRoutes } from './routes_runtime.ts';
import { systemRoutes } from './routes_system.ts';
import type { RouteContext } from './types.ts';
import { operationsRoutes } from './routes_operations.ts';
import { describeHttp } from '../operation_registry.ts';
import { executeManaged, getOperations, operationsRoot, resolveSpec } from '../operation_host.ts';
import { requestPrincipal } from '../access_context.ts';
import { operationFailure } from '../operations.ts';
import {deviceRoutes} from './routes_devices.ts';

export async function handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', 'http://localhost');
  let buffered=false;
  let output:{httpStatus:number;body:any;contentType:string}|undefined;
  const send = (code: number, body: unknown, contentType = 'application/json') => {
    if(buffered) {output={httpStatus:code,body,contentType};return;}
    const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': contentType, 'access-control-allow-origin': '*' });
    res.end(payload);
  };
  const context: RouteContext = { req, res, url, send };
  const routes = [
    ...operationsRoutes(context),
    ...deviceRoutes(context),
    ...systemRoutes(context),
    ...runtimeRoutes(context),
    ...analysisRoutes(context),
  ];

  for (const route of routes) {
    if (route.method && req.method !== route.method) continue;
    const matches = route.prefix
      ? url.pathname.startsWith(route.path)
      : url.pathname === route.path;
    if (matches) {
      if(!url.pathname.startsWith('/api/') || url.pathname.startsWith('/api/operations')) {
        if(url.pathname==='/mcp') {
          try{return await handleMcp(await readBody(req),res,{principal:requestPrincipal(req.headers,'mcp',operationsRoot)});}
          catch(error){return send(403,operationFailure(error));}
        }
        return await route.handler();
      }
      try {
        const principal=requestPrincipal(req.headers,'panel',operationsRoot);
        const args:any={...Object.fromEntries(url.searchParams)};
        if(['POST','PUT','PATCH','DELETE'].includes(req.method||'')) {
          const text=await readBody(req);
          if(text)Object.assign(args,JSON.parse(text));
        }
        if(req.headers['x-adh-operation'])args._operation=JSON.parse(String(req.headers['x-adh-operation']));
        const spec=resolveSpec(describeHttp(url.pathname,req.method||'GET',args),args);
        const engine=getOperations(), resource=spec.mode==='read' && spec.session && !sessions.get(spec.session)?.online?'host':engine.resource(spec);
        res.setHeader('x-adh-control',JSON.stringify(engine.snapshot(resource)));
        if(spec.mode==='read' && !args._operation?.taskId)return await executeManaged(spec,args,principal,async()=>route.handler());
        buffered=true;
        const result:any=await executeManaged(spec,args,principal,async()=>{await route.handler();return output||{httpStatus:204,body:null,contentType:'application/json'};},'http');
        buffered=false;
        res.setHeader('x-adh-control',JSON.stringify(engine.snapshot(resource)));
        if(result.httpStatus!==undefined) {
          const body=result.body && typeof result.body==='object' && !Array.isArray(result.body)?{...result.body,_operation:result._operation}:result.body;
          return send(result._operation?.state==='unknown'?504:result.httpStatus,
            result._operation?.state==='unknown'?{...body,ok:false,code:'UNKNOWN_EXECUTION'}:body,result.contentType);
        }
        return send(result._operation?.state==='unknown'?504:result._operation?.state==='queued'?202:409,result);
      } catch(error) {
        buffered=false;const failure=operationFailure(error);
        return send(failure.code==='AUTH_FAILED'?403:failure.code==='CONTROL_REQUIRED'||failure.code==='STALE_CONTROL'||failure.code==='CONTROL_HELD'?409:400,failure);
      }
    }
  }

  const pkg = packageFromPath(url.pathname);
  if (pkg) {
    if (req.method === 'POST' && url.pathname === `/${pkg}/mcp`) {
      try{return await handleMcp(await readBody(req), res, { package: pkg,principal:requestPrincipal(req.headers,'mcp',operationsRoot) });}
      catch(error){return send(403,operationFailure(error));}
    }
    if (url.pathname === `/${pkg}` || url.pathname === `/${pkg}/`) {
      return await serveDashboard(send);
    }
  }
  send(404, { error: 'not found' });
}

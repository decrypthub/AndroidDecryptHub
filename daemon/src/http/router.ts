import type http from 'node:http';

import { handleMcp } from '../mcp.ts';
import { readBody } from '../state.ts';
import { packageFromPath } from './package_path.ts';
import { analysisRoutes, serveDashboard } from './routes_analysis.ts';
import { runtimeRoutes } from './routes_runtime.ts';
import { systemRoutes } from './routes_system.ts';
import type { RouteContext } from './types.ts';

export async function handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const send = (code: number, body: unknown, contentType = 'application/json') => {
    const payload = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': contentType, 'access-control-allow-origin': '*' });
    res.end(payload);
  };
  const context: RouteContext = { req, res, url, send };
  const routes = [
    ...systemRoutes(context),
    ...runtimeRoutes(context),
    ...analysisRoutes(context),
  ];

  for (const route of routes) {
    if (route.method && req.method !== route.method) continue;
    const matches = route.prefix
      ? url.pathname.startsWith(route.path)
      : url.pathname === route.path;
    if (matches) return await route.handler();
  }

  const pkg = packageFromPath(url.pathname);
  if (pkg) {
    if (req.method === 'POST' && url.pathname === `/${pkg}/mcp`) {
      return await handleMcp(await readBody(req), res, { package: pkg });
    }
    if (url.pathname === `/${pkg}` || url.pathname === `/${pkg}/`) {
      return await serveDashboard(send);
    }
  }
  send(404, { error: 'not found' });
}

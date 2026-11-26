import { patchAppCaptureFamily, patchSettings, settingsHttpStatus } from '../settings_service.ts';
import { HOST_VERSION } from '../version.ts';
import { maintainData } from '../maintenance.ts';
import { localEffect } from '../execution_context.ts';
import { existsSync, unlinkSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { backendMatrix } from '../backends.ts';
import { detectionReport } from '../detect.ts';
import { cryptoView } from '../crypto_view.ts';
import { assembleHttpExchanges, type HttpAssembly, type TlsChunk } from '../http_exchange.ts';
import { AGENT_PORT, webUrls } from '../config.ts';
import { baseFromHost, isValidPackage, mcpOnboarding } from '../mcp_onboarding.ts';
import { handleMcp, MCP_TOOLS } from '../mcp.ts';
import { scopedApps, mergeScope, packageInstalled, readScopeFile, scopePanelOp, writeScopePackages } from '../scope_list.ts';
import { coldStartPackage, runningPid, startPackage, stopPackage } from '../app_launch.ts';
import { localObserver, noteObservedPid } from '../local_observer.ts';
import { readPackageIcon } from '../package_icon.ts';
import { analyzePackage } from '../app_analyze.ts';
import { listCaptureArmProtected } from '../service.ts';
import { readAppCatalog } from '../app_catalog.ts';
import { deletedCaptureIds, findPersistedCaptureById, markCaptureDeleted, queryPersistedCapturesPage } from '../capture_persist.ts';
import {
  broadcast, captureHealth, capturePackage, captures, captureSettingsForPackage, captureTimers,
  clearCaptureStore, clearPackageCaptureStore, configStats, cryptoIdentify, DATA_DIR, dumps, eventPackage,
  events, EVENTS_FILE, exportPackageCapturesJsonl, hexToPreview, hostSettingsSnapshot, log, packageCaptureDiskStats,
  previewForCapture, readBody, sessions, settings, type Capture,
} from '../state.ts';
import type { Route, RouteContext } from './types.ts';

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'public');
const exchangeCache = new Map<string, { stamp: string; value: HttpAssembly }>();

export function systemRoutes({ req, res, url, send }: RouteContext): Route[] {
  const servePublic = (name: string, contentType: string) => async () => {
    const file = join(publicDir, name);
    if (!existsSync(file)) return send(404, { error: 'missing' });
    const buf = await readFile(file);
    res.writeHead(200, {
      'content-type': contentType,
      'cache-control': 'no-cache',
      'access-control-allow-origin': '*',
    });
    res.end(buf);
  };
  return [
    // Temporarily retire the browser history view without discarding stored operations.
    { path:'/workbench',handler:() => {
      res.writeHead(302, { location:'/', 'cache-control':'no-store' });
      res.end();
    } },
    { path:'/workbench.css',handler:servePublic('workbench.css','text/css; charset=utf-8') },
    { path:'/operation-client.js',handler:servePublic('operation-client.js','text/javascript; charset=utf-8') },
    { path:'/workbench-model.js',handler:servePublic('workbench-model.js','text/javascript; charset=utf-8') },
    { path:'/algorithm-observations.js',handler:servePublic('algorithm-observations.js','text/javascript; charset=utf-8') },
    { path:'/workbench.js',handler:servePublic('workbench.js','text/javascript; charset=utf-8') },
    { path:'/quick-start.js',handler:servePublic('quick-start.js','text/javascript; charset=utf-8') },
    { path:'/hook-plans-panel.js',handler:servePublic('hook-plans-panel.js','text/javascript; charset=utf-8') },
    { path:'/operations.js',handler:servePublic('operations.js','text/javascript; charset=utf-8') },
    { method: 'GET', path: '/api/apps/icon', handler: async () => {
      const pkg = url.searchParams.get('package') || '';
      const serial = url.searchParams.get('serial') || undefined;
      const iconVersion = (url.searchParams.get('v') || '').slice(0, 80);
      if (serial && !/^[A-Za-z0-9_-]+$/.test(serial)) return send(400, { ok: false, error: '无效的设备序列号' });
      try {
        const icon = await readPackageIcon(pkg, serial, iconVersion);
        if (!icon) return send(404, { ok: false, error: '没有图标' });
        const headers = { etag: icon.etag, 'cache-control': iconVersion ? 'private, max-age=86400, immutable' : 'private, max-age=60', 'access-control-allow-origin': '*' };
        if (req.headers['if-none-match'] === icon.etag) {
          res.writeHead(304, headers);
          res.end();
          return;
        }
        res.writeHead(200, { ...headers, 'content-type': icon.type });
        res.end(icon.body);
      } catch (e) {
        const unavailable = (e as { code?: string }).code === 'DEVICE_ICON_UNAVAILABLE';
        return send(unavailable ? 503 : 502, { ok: false, error: (e as Error).message });
      }
    } },
    { method: 'POST', path: '/api/apps/control', handler: async () => {
      let body: { package?: string; action?: string };
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { ok: false, error: 'JSON 格式错误' }); }
      const pkg = String(body.package || '').trim();
      const action = body.action;
      if (!pkg || !['open', 'stop', 'restart'].includes(String(action))) return send(400, { ok: false, error: '需要应用和动作' });
      if (!(await packageInstalled(pkg))) return send(404, { ok: false, error: '手机上没有这个应用' });
      const result = action === 'stop' ? await stopPackage(pkg) : action === 'restart' ? await coldStartPackage(pkg) : await startPackage(pkg);
      if (!result.ok) return send(502, result);
      if (action === 'stop') noteObservedPid(pkg, 0);
      else noteObservedPid(pkg, await runningPid(pkg));
      return send(200, result);
    } },
    { path: '/api/apps', handler: async () => {
      if (localObserver) {
        const pkg = localObserver.package;
        if(process.env.ADH_USB_APP_INVENTORY==='1'&&!localObserver.fileBrowserOnly&&!localObserver.demoApiSerial){
          const serial=url.searchParams.get('serial')||'';
          if(serial&&!/^[A-Za-z0-9_-]+$/.test(serial)) return send(400,{ok:false,error:'无效的设备序列号'});
          try{
            const apps=await readAppCatalog(serial||undefined);
            return send(200,{apps,error:null,capture:false,localObservation:true,inventory:true});
          }catch{ return send(200,{apps:[],error:'读不到手机上的应用列表，请检查 USB 连接后重试。',capture:false,localObservation:true,inventory:true}); }
        }
        const online = localObserver.fileBrowserOnly===true || !!localObserver.demoApiSerial || [...sessions.values()].some(s => s.online && s.package === pkg);
        return send(200, {
          apps: [{ package: pkg, label: localObserver.demoApiSerial?'ADH Demo API 采集':pkg }],
          error: online ? null : '还没收到这个 APP 的采集连接',
          capture: false,
          localObservation: true,
        });
      }
      const scope = await scopedApps();
      return send(200, {
        apps: scope.apps, error: scope.error, capture: settings.capture.enabled,
        captureByPackage: Object.fromEntries(Object.keys(settings.capture.familiesByPackage)
          .map(pkg => [pkg, captureSettingsForPackage(pkg).enabled])),
        // Packages that finished one-click unpack and will not be re-armed until next hello.
        unpackProtected: listCaptureArmProtected(),
      });
    } },
    // Host-side allowlist control (the AI/operator channel): the companion reads scope.json at
    // process specialization, so an added package is injected on its next cold start.
    { method: 'GET', path: '/api/scope', handler: async () => {
      const s = await readScopeFile();
      return send(200, { ok: s.error === null, packages: s.packages, version: s.version, mode: s.mode, error: s.error });
    } },
    { method: 'POST', path: '/api/scope', handler: async () => {
      let body: any;
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      if (localObserver) {
        const op = scopePanelOp(body);
        if ('error' in op) return send(400, { ok: false, error: op.error });
        if (!(await packageInstalled(op.package))) return send(404, { ok: false, error: '手机上没有这个应用' });
        body = op.add ? { add: [op.package] } : { remove: [op.package] };
      }
      const cur = await readScopeFile();
      if (cur.error) return send(503, { ok: false, error: cur.error });
      const before = cur.packages;
      const next = Array.isArray(body.set)
        ? mergeScope([], { add: body.set })
        : mergeScope(before, { add: body.add, remove: body.remove });
      const w = await writeScopePackages(next, { version: cur.version, mode: cur.mode });
      if (!w.ok) return send(502, { ok: false, error: w.error, packages: before });
      return send(200, {
        ok: true, packages: w.packages,
        added: w.packages.filter((p) => !before.includes(p)),
        removed: before.filter((p) => !w.packages.includes(p)),
        note: 'cold start the target to apply',
      });
    } },
    // One call from a package name to a report — the "analyze any app" entry point.
    { method: 'POST', path: '/api/analyze-app', handler: async () => {
      let body: any;
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      const pkg = String(body.package ?? '').trim();
      if (!pkg) return send(400, { error: 'need package' });
      try {
        const out = await analyzePackage(pkg, {
          autoScope: body.autoScope !== false,
          forceRestart: body.forceRestart === true,
          captureMs: Number(body.captureMs) > 0 ? Number(body.captureMs) : undefined,
          unpack: body.unpack === true,
          httpCaptureMs: Number(body.httpCaptureMs) > 0 ? Number(body.httpCaptureMs) : 0,
          timeoutMs: Number(body.timeoutMs) > 0 ? Number(body.timeoutMs) : undefined,
          settleMs: Number(body.settleMs) > 0 ? Number(body.settleMs) : undefined,
        });
        return send(out.ok ? 200 : 502, out);
      } catch (e) { return send(500, { ok: false, error: (e as Error).message }); }
    } },
    { path: '/health', handler: () => send(200, {
      ok: true, service: 'adhd', name: 'ADH Daemon', version: HOST_VERSION,
      agents: sessions.size, uptime: process.uptime(), mcpTools: MCP_TOOLS.length, web: webUrls(),
      agent: { port: AGENT_PORT },
      apps: [...sessions.values()].map(s => ({
        package: s.package, pid: s.pid, sessionId: s.sessionId, online: s.online,
      })),
    }) },
    // MCP Streamable HTTP endpoint (JSON-RPC)
    { method: 'POST', path: '/mcp', handler: async () => handleMcp(await readBody(req), res) },
    { path: '/wechat-follow.png', handler: servePublic('wechat-follow.png', 'image/png') },
    { path: '/raven.svg', handler: servePublic('raven.svg', 'image/svg+xml') },
    { path: '/raven.png', handler: servePublic('raven.png', 'image/png') },
    { path: '/favicon.ico', handler: servePublic('raven.png', 'image/png') },
    // HTTP/1.1 exchanges reassembled from SSL_read/SSL_write that share an SSL*.
    { path: '/api/http/exchanges', handler: () => {
      const session = url.searchParams.get('session');
      const pkg = url.searchParams.get('package');
      const fromTsRaw = url.searchParams.get('fromTs');
      const toTsRaw = url.searchParams.get('toTs');
      const fromTs = fromTsRaw ? Number(fromTsRaw) : null;
      const toTs = toTsRaw ? Number(toTsRaw) : null;
      // 全量重组一次要几秒（hex 解码 + 解压 + HPACK），面板每 5s 轮询一次。
      // 记录只追加不可变：net 条数 + 最后一条 net id 没变就直接回缓存。
      let netCount = 0, lastNetId = 0;
      for (const c of captures) if (c.category === 'net') { netCount++; lastNetId = c.id; }
      const stamp = `${netCount}:${lastNetId}`;
      const key = `${session ?? ''}\n${pkg ?? ''}\n${fromTs ?? ''}\n${toTs ?? ''}`;
      const hit = exchangeCache.get(key);
      if (hit && hit.stamp === stamp) return send(200, hit.value);

      let list = captures.filter(c => c.category === 'net');
      if (session) list = list.filter(c => c.sessionId === session);
      if (pkg) list = list.filter(c => capturePackage(c) === pkg);
      if (fromTs != null && Number.isFinite(fromTs)) list = list.filter(c => c.ts >= fromTs);
      if (toTs != null && Number.isFinite(toTs)) list = list.filter(c => c.ts <= toTs);

      // 内存环被高频 crypto 挤出时，从落盘 captures.jsonl 补齐该包的 net 记录
      if (pkg) {
        const disk = queryPersistedCapturesPage(DATA_DIR, {
          package: pkg, session, categories: ['net'],
          fromTs: fromTs != null && Number.isFinite(fromTs) ? fromTs : null,
          toTs: toTs != null && Number.isFinite(toTs) ? toTs : null,
          limit: 2000,
        });
        if (disk && disk.items.length) {
          const byId = new Map<number, Capture>();
          for (const d of disk.items) byId.set(d.id, d as unknown as Capture);
          for (const m of list) byId.set(m.id, m);
          list = [...byId.values()].sort((a, b) => a.id - b.id);
        }
      }

      const records: TlsChunk[] = list.map(c => ({
        id: c.id, sessionId: c.sessionId, func: c.func, hex: c.hex, inl: c.inl,
        tsNs: c.tsNs, ts: c.ts, conn: c.conn,
      }));
      const value = assembleHttpExchanges(records);
      exchangeCache.set(key, { stamp, value });
      if (exchangeCache.size > 8) {
        const oldest = exchangeCache.keys().next().value;
        if (oldest !== undefined) exchangeCache.delete(oldest);
      }
      return send(200, value);
    } },
    // Live + persisted captures with cursor/time pagination:
    // GET /api/captures?package=&session=&category=&since=&beforeId=&fromTs=&toTs=&q=&limit=
    { path: '/api/captures', handler: () => {
      const since = Number(url.searchParams.get('since') ?? 0);
      const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit') ?? 200), 10000));
      const beforeIdRaw = url.searchParams.get('beforeId');
      const fromTsRaw = url.searchParams.get('fromTs');
      const toTsRaw = url.searchParams.get('toTs');
      const beforeId = beforeIdRaw != null && beforeIdRaw !== '' ? Number(beforeIdRaw) : null;
      const fromTs = fromTsRaw != null && fromTsRaw !== '' ? Number(fromTsRaw) : null;
      const toTs = toTsRaw != null && toTsRaw !== '' ? Number(toTsRaw) : null;
      const catRaw = url.searchParams.get('category');
      const categories = catRaw ? catRaw.split(',').map(s => s.trim()).filter(Boolean) : null;
      const catSet = categories && categories.length ? new Set(categories) : null;
      const q = (url.searchParams.get('q') ?? '').trim().toLowerCase();
      const session = url.searchParams.get('session');
      const pkg = url.searchParams.get('package');

      // `applyWindow` keeps the cursor/id window out of the predicate: the page count must
      // describe how many records exist, not how many are left after the cursor.
      const matchesFilters = (c: Capture, applyWindow: boolean) => {
        if (applyWindow) {
          if (c.id <= since) return false;
          if (beforeId != null && Number.isFinite(beforeId) && c.id >= beforeId) return false;
        }
        if (fromTs != null && Number.isFinite(fromTs) && c.ts < fromTs) return false;
        if (toTs != null && Number.isFinite(toTs) && c.ts > toTs) return false;
        if (session && c.sessionId !== session) return false;
        if (pkg && capturePackage(c) !== pkg) return false;
        if (catSet && !catSet.has(c.category)) return false;
        if (q) {
          const hay = `${c.algo || ''} ${c.op || ''} ${c.func || ''} ${c.path || ''} ${c.preview || ''}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      };
      const matchMem = (c: Capture) => matchesFilters(c, true);
      // How many records the current selection has in total (retained window), independent of the
      // page cursor — the panel shows this instead of pretending the page is the whole story.
      const matched = captures.filter(c => matchesFilters(c, false)).length;

      let memList = captures.filter(matchMem);
      let hasMore = memList.length > limit;
      let pageList: Capture[];

      // 内存窗口足够填满当前页 + 判断还有上一页时直接走内存（0 磁盘 IO）；否则穿透读落盘 captures.jsonl
      if (beforeId == null && toTs == null && fromTs == null && memList.length > limit) {
        pageList = memList.slice(-limit);
      } else {
        const disk = queryPersistedCapturesPage(DATA_DIR, {
          package: pkg, session, categories, since,
          beforeId: beforeId != null && Number.isFinite(beforeId) ? beforeId : null,
          fromTs: fromTs != null && Number.isFinite(fromTs) ? fromTs : null,
          toTs: toTs != null && Number.isFinite(toTs) ? toTs : null,
          q, limit,
        });
        if (disk) {
          const byId = new Map<number, Capture>();
          for (const d of disk.items) byId.set(d.id, d as unknown as Capture);
          for (const m of memList) byId.set(m.id, m);
          const merged = [...byId.values()].sort((a, b) => a.id - b.id);
          hasMore = disk.hasMore || merged.length > limit;
          pageList = merged.slice(-limit);
        } else {
          pageList = memList.slice(-limit);
        }
      }

      const health = captureHealth();
      return send(200, {
        total: captures.length, on: captureTimers.size > 0,
        // Records matching the current package/category/query in the retained window.
        // `total` stays the whole per-package store; `matched` is what this page is a slice of.
        matched,
        returned: pageList.length,
        hasMore,
        nextBeforeId: hasMore && pageList.length ? pageList[0].id : null,
        oldestId: pageList[0]?.id ?? null,
        latestId: pageList.at(-1)?.id ?? null,
        ...health, health,
        captures: pageList.map(c => ({
          id: c.id, sessionId: c.sessionId, package: capturePackage(c), source: c.source, category: c.category,
          algo: c.algo, op: c.op, func: c.func, inl: c.inl, outl: c.outHex ? c.outHex.length / 2 : 0,
          hasKey: !!c.keyHex, tid: c.tid, ts: c.ts,
          preview: c.category === 'net' ? previewForCapture(c.func, c.hex) : c.preview,
          ...(c.path ? { path: c.path } : {}),
          ...(c.category === 'crypto' ? { view: cryptoView(c) } : {}),
        })),
      });
    } },
    { path: '/api/captures/packages', handler: () => send(200, { packages: packageCaptureDiskStats() }) },
    { path: '/api/captures/export', handler: () => {
      const pkg = String(url.searchParams.get('package') || '');
      if (!pkg) return send(400, { error: '需要 package' });
      let body = exportPackageCapturesJsonl(pkg);
      if (body == null) return send(404, { error: '该包还没有落盘捕获' });
      const deleted = deletedCaptureIds(DATA_DIR, pkg);
      if (deleted.size) {
        body = body.split('\n').filter(line => {
          if (!line) return false;
          const m = /"id"\s*:\s*(\d+)/.exec(line.slice(0, 64));
          return !(m && deleted.has(Number(m[1])));
        }).join('\n');
      }
      res.writeHead(200, {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'content-disposition': `attachment; filename="${pkg.replace(/[^\w.-]+/g, '_')}-captures.jsonl"`,
      });
      return res.end(body);
    } },
    { path: '/api/captures/', prefix: true, handler: async () => {
      const id = Number(url.pathname.slice('/api/captures/'.length));
      if (req.method === 'POST') {
        let body: { action?: string };
        try { body = JSON.parse(await readBody(req) || '{}'); } catch { return send(400, { ok: false, error: 'bad json' }); }
        if (body?.action !== 'delete') return send(400, { ok: false, error: '未知操作' });
        if (!Number.isFinite(id) || id <= 0) return send(400, { ok: false, error: '无效的记录编号' });
        const idx = captures.findIndex(x => x.id === id);
        const mem = idx >= 0 ? captures.splice(idx, 1)[0] : undefined;
        let pkg = url.searchParams.get('package') || (mem ? capturePackage(mem) : '');
        if (!pkg) pkg = findPersistedCaptureById(DATA_DIR, id)?.package ?? '';
        if (pkg) markCaptureDeleted(DATA_DIR, pkg, id);
        return send(200, { ok: true, id });
      }
      const c = captures.find(x => x.id === id)
        ?? (findPersistedCaptureById(DATA_DIR, id, url.searchParams.get('package') || undefined) as unknown as Capture | null);
      if (!c) return send(404, { error: 'not found' });
      // decode as UTF-8 so Chinese plaintext (gray-market payloads) is readable, not dotted
      let text = '';
      try { text = Buffer.from(c.hex, 'hex').toString('utf8'); } catch { text = hexToPreview(c.hex, 4096); }
      return send(200, { ...c, text, ...(c.category === 'crypto' ? { view: cryptoView(c) } : {}) });
    } },
    // Session events (record/replay): GET /api/events?type=&limit=&since=
    { path: '/api/events', handler: () => {
      const type = url.searchParams.get('type');
      const since = Number(url.searchParams.get('since') ?? 0);
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 500), 5000);
      const pkg = url.searchParams.get('package');
      let list = events.filter(e => e.seq > since && (!type || e.type === type));
      if (pkg) list = list.filter(e => eventPackage(e.data) === pkg);
      return send(200, { total: events.length, returned: Math.min(list.length, limit), events: list.slice(-limit) });
    } },
    // Diagnostic report / export (P/R) — metadata only, no captured keys/plaintext.
    { path: '/api/export/report', handler: () => send(200, {
      report: 'adh-diagnostic', version: '0.1.0', hostVersion: HOST_VERSION, generatedAt: new Date().toISOString(), uptime: process.uptime(),
      agents: [...sessions.values()].map(s => ({ sessionId: s.sessionId, package: s.package, pid: s.pid, abi: s.abi, android: s.android, sdk: s.sdk, entry: s.entry, online: s.online, mapsCount: s.mapsCount })),
      dumps: [...dumps.values()].map(d => ({ sha256: d.sha256, kind: d.kind, size: d.size, source: d.source, tag: d.tag, capturedAt: d.capturedAt })),
      capabilities: { rest: true, websocket: true, mcp: true, mcpTools: MCP_TOOLS.length },
      note: 'metadata only — captured key/plaintext content is never in diagnostic reports',
    }) },
    { method: 'GET', path: '/api/capture/families', handler: () => {
      const pkg = url.searchParams.get('package') || '';
      if (!isValidPackage(pkg)) return send(400, { ok: false, error: '需要有效的包名' });
      return send(200, { ok: true, package: pkg, capture: captureSettingsForPackage(pkg) });
    } },
    { method: 'POST', path: '/api/capture/families', handler: async () => {
      let patch: unknown;
      try { patch = JSON.parse(await readBody(req)); } catch { return send(400, { ok: false, error: 'JSON 格式错误' }); }
      const result = await patchAppCaptureFamily(patch);
      return send(settingsHttpStatus(result), result);
    } },
    // ---- legacy settings / config ----
    { path: '/api/config', handler: async () => {
      if (req.method === 'POST') {
        let patch: any = {};
        try { patch = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
        const result = await patchSettings(patch);
        return send(settingsHttpStatus(result), result);
      }
      return send(200, { settings: hostSettingsSnapshot(), stats: configStats() });
    } },
    { path: '/api/settings/export', handler: () => send(200, hostSettingsSnapshot()) },
    { method: 'POST', path: '/api/settings/import', handler: async () => {
      let obj: any;
      try { obj = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'JSON 格式错误' }); }
      if (typeof obj !== 'object' || Array.isArray(obj)) return send(400, { error: '顶层必须是对象' });
      const result = await patchSettings(obj);
      return send(settingsHttpStatus(result), result);
    } },
    { method: 'GET', path: '/api/maintenance', handler: () => send(200, maintainData()) },
    { method: 'POST', path: '/api/maintenance', handler: async () => {
      let body: any;
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      const result = maintainData(body ?? {});
      return send(result.ok ? 200 : 400, result);
    } },
    { method: 'POST', path: '/api/data/clear', handler: async () => {
      let body: any;
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      const what = String(body.what || '');
      const pkg = String(body.package || '').trim();
      const errors: string[] = [];
      if (!['captures', 'events', 'dumps'].includes(what)) return send(400, { error: 'what 必须是 captures|events|dumps' });
      localEffect(() => {
        if (what === 'captures') {
          exchangeCache.clear();
          if (pkg) errors.push(...clearPackageCaptureStore(pkg));
          else errors.push(...clearCaptureStore());
        }
        else if (what === 'events') {
          events.length = 0;
          try { writeFileSync(EVENTS_FILE, ''); } catch (e) { errors.push(`events 回放文件: ${(e as Error).message}`); }
        }
        else if (what === 'dumps') {
          const victims = [...dumps.values()].filter(d => !pkg || d.package === pkg);
          for (const d of victims) {
            try { if (existsSync(d.path)) unlinkSync(d.path); } catch (e) { errors.push(`${d.path}: ${(e as Error).message}`); }
            dumps.delete(d.sha256);
          }
        }
      });
      broadcast('data.cleared', { what, package: pkg || undefined });
      if (errors.length) { log(`[data/clear] ${what} 部分磁盘删除失败:`, errors.join('; ')); return send(500, { error: `内存索引已清，但磁盘删除失败(${errors.length}项)`, cleared: what, errors, stats: configStats() }); }
      return send(200, { ok: true, cleared: what, package: pkg || undefined, stats: configStats() });
    } },
    { path: '/api/mcp/doc', handler: () => {
      const cell = (value: unknown) => String(value ?? '—').replaceAll('|', '\\|').replace(/\r?\n/g, ' ');
      const md = ['# ADH MCP Tools', '', `Generated from the live ADH Daemon registry (${MCP_TOOLS.length} tools). Endpoint: \`POST /mcp\` (JSON-RPC 2.0).`, '',
        '| Tool | Description | Args |', '|---|---|---|',
        ...MCP_TOOLS.map(t => `| \`${t.name}\` | ${cell(t.description)} | ${cell(Object.keys(t.inputSchema.properties ?? {}).join(', ') || '—')} |`), ''].join('\n');
      res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' }); return res.end(md);
    } },
    { path: '/api/crypto/identify', handler: () => send(200, cryptoIdentify()) },
    { path: '/api/detect/summary', handler: () => send(200, detectionReport({
      package: url.searchParams.get('package') ?? '',
      session: url.searchParams.get('session') ?? '',
    })) },
    { path: '/api/mcp/config', handler: () => {
      // The guide's address must be the one the caller actually reached — LAN for the browser on the
      // phone's Wi-Fi, loopback for a shell on the daemon host. The request Host is that truth;
      // webUrls() is only the fallback for a client that sends no Host at all.
      const rawPkg = url.searchParams.get('package') ?? '';
      if (rawPkg && !isValidPackage(rawPkg)) return send(400, { error: 'package 必须是合法包名（字母数字 . _）' });
      const base = baseFromHost(req.headers.host) ?? webUrls().lan[0] ?? webUrls().local;
      return send(200, mcpOnboarding(base, { package: rawPkg || undefined }));
    } },
    { path: '/api/agents', handler: () => send(200, [...sessions.values()]) },
    { path: '/api/backends', handler: () => send(200, backendMatrix()) },
    { path: '/api/agents/', prefix: true, handler: () => {
      const s = sessions.get(url.pathname.split('/')[3]);
      return s ? send(200, s) : send(404, { error: 'no such session' });
    } },
  ];
}

import { existsSync, unlinkSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { backendMatrix } from '../backends.ts';
import { webUrls } from '../config.ts';
import { handleMcp, MCP_TOOLS } from '../mcp.ts';
import { applyCaptureEnabled } from '../service.ts';
import {
  broadcast, captureHealth, captures, captureTimers, configStats, cryptoIdentify,
  dumps, events, EVENTS_FILE, hexToPreview, log, mergeSettings, readBody,
  recentJavaIn, saveSettings, sessions, settings,
} from '../state.ts';
import type { Route, RouteContext } from './types.ts';

const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'public');
export function systemRoutes({ req, res, url, send }: RouteContext): Route[] {
  const servePublic = (name: string, contentType: string) => async () => {
    const file = join(publicDir, name);
    if (!existsSync(file)) return send(404, { error: 'missing' });
    const buf = await readFile(file);
    res.writeHead(200, {
      'content-type': contentType,
      'cache-control': 'public, max-age=86400',
      'access-control-allow-origin': '*',
    });
    res.end(buf);
  };
  return [
    { path: '/health', handler: () => send(200, {
      ok: true, service: 'adhd', name: 'ADH Daemon', version: '0.1.0',
      agents: sessions.size, uptime: process.uptime(), mcpTools: MCP_TOOLS.length, web: webUrls(),
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
    // Live captures (auto-populated by the persistent hooks): GET /api/captures?since=&limit=
    { path: '/api/captures', handler: () => {
      const since = Number(url.searchParams.get('since') ?? 0);
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 200), 1000);
      const session = url.searchParams.get('session');
      const pkg = url.searchParams.get('package');
      let list = captures.filter(c => c.id > since);
      if (session) list = list.filter(c => c.sessionId === session);
      if (pkg) {
        const sids = new Set([...sessions.values()].filter(s => s.package === pkg).map(s => s.sessionId));
        list = list.filter(c => sids.has(c.sessionId));
      }
      // WS-C: `health` carries honest ring accounting — complete:false + dropped>0 when the
      // agent ring overflowed (no silent loss; the panel should show this in red). The health
      // fields are ALSO mirrored at the top level by SPREADING them, not by hand-copying a subset:
      // the hand-written mirror silently dropped the newer residual fields, so a script could
      // assert on them and pass without ever seeing them.
      const health = captureHealth();
      return send(200, {
        total: captures.length, on: captureTimers.size > 0,
        ...health, health,
        captures: list.slice(-limit).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, func: c.func, inl: c.inl, outl: c.outHex ? c.outHex.length / 2 : 0, tid: c.tid, ts: c.ts, preview: c.preview })),
      });
    } },
    { path: '/api/captures/', prefix: true, handler: () => {
      const id = Number(url.pathname.slice('/api/captures/'.length));
      const c = captures.find(x => x.id === id);
      if (!c) return send(404, { error: 'not found' });
      // decode as UTF-8 so Chinese plaintext (gray-market payloads) is readable, not dotted
      let text = '';
      try { text = Buffer.from(c.hex, 'hex').toString('utf8'); } catch { text = hexToPreview(c.hex, 4096); }
      return send(200, { ...c, text });
    } },
    // Session events (record/replay): GET /api/events?type=&limit=&since=
    { path: '/api/events', handler: () => {
      const type = url.searchParams.get('type');
      const since = Number(url.searchParams.get('since') ?? 0);
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 500), 5000);
      let list = events.filter(e => e.seq > since && (!type || e.type === type));
      return send(200, { total: events.length, returned: Math.min(list.length, limit), events: list.slice(-limit) });
    } },
    // Diagnostic report / export (P/R) — metadata only, no captured keys/plaintext.
    { path: '/api/export/report', handler: () => send(200, {
      report: 'idh-diagnostic', version: '0.1.0', generatedAt: new Date().toISOString(), uptime: process.uptime(),
      agents: [...sessions.values()].map(s => ({ sessionId: s.sessionId, package: s.package, pid: s.pid, abi: s.abi, android: s.android, sdk: s.sdk, entry: s.entry, online: s.online, mapsCount: s.mapsCount })),
      dumps: [...dumps.values()].map(d => ({ sha256: d.sha256, kind: d.kind, size: d.size, source: d.source, tag: d.tag, capturedAt: d.capturedAt })),
      capabilities: { rest: true, websocket: true, mcp: true, mcpTools: MCP_TOOLS.length },
      note: 'metadata only — captured key/plaintext content is never in diagnostic reports',
    }) },
    // ---- settings / config (web 设置面板；IDH 交互) ----
    { path: '/api/config', handler: async () => {
      if (req.method === 'POST') {
        let patch: any = {};
        try { patch = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
        const applied = mergeSettings(patch);
        while (captures.length > settings.capture.retain) captures.shift();
        applyCaptureEnabled().catch((e) => log('[settings] applyCaptureEnabled:', (e as Error).message));
        try { saveSettings(); }
        catch (e) { return send(500, { error: '设置已在内存生效，但写入磁盘失败(重启后丢失): ' + (e as Error).message, applied, settings, persisted: false }); }
        return send(200, { ok: true, applied, settings, stats: configStats(), persisted: true });
      }
      return send(200, { settings, stats: configStats() });
    } },
    { path: '/api/settings/export', handler: () => send(200, settings) },
    { method: 'POST', path: '/api/settings/import', handler: async () => {
      let obj: any;
      try { obj = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'JSON 格式错误' }); }
      if (typeof obj !== 'object' || Array.isArray(obj)) return send(400, { error: '顶层必须是对象' });
      const applied = mergeSettings(obj);
      if (!applied.length) return send(400, { error: '没有可应用的板块(capture/ui/artifacts)' });
      while (captures.length > settings.capture.retain) captures.shift();
      applyCaptureEnabled().catch((e) => log('[settings] applyCaptureEnabled:', (e as Error).message));
      try { saveSettings(); }
      catch (e) { return send(500, { error: '导入已在内存生效，但写入磁盘失败(重启后丢失): ' + (e as Error).message, applied, settings, persisted: false }); }
      return send(200, { ok: true, applied, settings, persisted: true });
    } },
    { method: 'POST', path: '/api/data/clear', handler: async () => {
      let body: any;
      try { body = JSON.parse((await readBody(req)) || '{}'); } catch { return send(400, { error: 'bad json' }); }
      const what = String(body.what || '');
      const errors: string[] = [];
      if (what === 'captures') { captures.length = 0; recentJavaIn.clear(); }
      else if (what === 'events') {
        events.length = 0;
        try { writeFileSync(EVENTS_FILE, ''); } catch (e) { errors.push(`events 回放文件: ${(e as Error).message}`); }
      }
      else if (what === 'dumps') {
        for (const d of dumps.values()) {
          try { if (existsSync(d.path)) unlinkSync(d.path); } catch (e) { errors.push(`${d.path}: ${(e as Error).message}`); }
        }
        dumps.clear();
      } else return send(400, { error: 'what 必须是 captures|events|dumps' });
      broadcast('data.cleared', { what });
      if (errors.length) { log(`[data/clear] ${what} 部分磁盘删除失败:`, errors.join('; ')); return send(500, { error: `内存索引已清，但磁盘删除失败(${errors.length}项)`, cleared: what, errors, stats: configStats() }); }
      return send(200, { ok: true, cleared: what, stats: configStats() });
    } },
    { path: '/api/mcp/doc', handler: () => {
      const cell = (value: unknown) => String(value ?? '—').replaceAll('|', '\\|').replace(/\r?\n/g, ' ');
      const md = ['# ADH MCP Tools', '', `Generated from the live ADH Daemon registry (${MCP_TOOLS.length} tools). Endpoint: \`POST /mcp\` (JSON-RPC 2.0).`, '',
        '| Tool | Description | Args |', '|---|---|---|',
        ...MCP_TOOLS.map(t => `| \`${t.name}\` | ${cell(t.description)} | ${cell(Object.keys(t.inputSchema.properties ?? {}).join(', ') || '—')} |`), ''].join('\n');
      res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' }); return res.end(md);
    } },
    { path: '/api/crypto/identify', handler: () => send(200, cryptoIdentify()) },
    { path: '/api/mcp/config', handler: () => {
      const w = webUrls(); const lan = (w.lan[0] ?? w.local).replace(/^http/, 'http');
      const mcpUrl = `${lan}/mcp`;
      const cfg = {
        note: '把 HTTP MCP 端点配置进支持 JSON-RPC 的客户端；仅限可信网络，不要暴露到公网。',
        endpoint: mcpUrl,
        pinnedEndpoint: `${lan}/<package>/mcp`,
        tools: MCP_TOOLS.length,
        example: { jsonrpc: '2.0', id: 1, method: 'tools/list' },
        quickAsks: [
          '用 crypto_identify 看看这个 App 用了哪些加密算法和密钥',
          '用 dump_all_dex 一键 dump 所有 DEX，然后 dumps_list 给我下载链接',
          '用 live_captures 看实时加解密，挑一条用 capture_detail 展开明文',
          '用 capture_start 打开持续捕获，再 java_call 触发目标的工作负载，然后 live_captures 看明文',
          '用 qbdi_trace 逐指令跟踪这个 native 函数',
        ],
      };
      return send(200, cfg);
    } },
    { path: '/api/agents', handler: () => send(200, [...sessions.values()]) },
    { path: '/api/backends', handler: () => send(200, backendMatrix()) },
    { path: '/api/agents/', prefix: true, handler: () => {
      const s = sessions.get(url.pathname.split('/')[3]);
      return s ? send(200, s) : send(404, { error: 'no such session' });
    } },
  ];
}

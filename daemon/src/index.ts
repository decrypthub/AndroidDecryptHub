// ADH Daemon — Android DecryptHub host daemon (legacy internal name: idhd).
// Boot + agent-TCP frame decode + REST routing live HERE. State + leaf helpers → state.ts;
// agent-command transport + dump engine + capture ops → service.ts; MCP JSON-RPC → mcp.ts.
// (Earlier: all of the above inlined in this one 1585-line file. Split bottom-up to keep the
//  import graph one-directional: state ← service ← mcp/index, no cycles.)
import http from 'node:http';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { writeFileSync, existsSync, unlinkSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { networkInterfaces } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyzeSo, cryptoConstScan, svcScan, disasmSo, OBJDUMP } from './analysis.ts';
import { parseDex, cryptoScan, searchDex, invokeXref, extractMethodCode, analyzeCoverage, rebuildStandardDex, recoverFromSnapshots, stripMethodCode } from './dex.ts';
import { ensureDexIndex, searchDexIndex, listDexReflections } from './dex_index.ts';
import { handleMcp, MCP_TOOLS, MCP_MAP } from './mcp.ts';
import {
  sendCmd, pickSid, dumpBuf, dumpBufPath, dumpRegion, modulesFromMaps, reconstructSo,
  repairDexHeader, withCaptureSuspended, runUnpackSession, startCaptureLoop, applyCaptureEnabled,
} from './service.ts';
import {
  sessions, dumps, agentSockets, pending, nextId, nextCmdId,
  events, recordEvent, settings, mergeSettings, saveSettings, configStats,
  SANDBOX, captures, recentJavaIn, captureTimers, captureHealth, hexToPreview, cryptoIdentify,
  wss, broadcast, log, readBody, frameJson, FRAME_JSON, FRAME_MAX,
  CAPTURES, EVENTS_FILE,
} from './state.ts';
import type { AgentSession, AgentMsg, DumpMeta } from './state.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
// ADH_* preferred; IDH_* kept as legacy aliases.
const HTTP_PORT = Number(process.env.ADH_HTTP_PORT ?? process.env.IDH_HTTP_PORT ?? 8760);
const AGENT_PORT = Number(process.env.ADH_AGENT_PORT ?? process.env.IDH_AGENT_PORT ?? 8761);

// ---- access URLs (mirrors ios-decrypt-helper: surface the LAN address so the console
//      is reachable from the phone / any device on the network, fail-loud if none) -----
// ADH Daemon (the web console) runs on the HOST, so the relevant LAN IP is this machine's,
// not the phone's. The phone reaches it via `adb reverse` (127.0.0.1) OR directly over
// Wi-Fi at the LAN IP. Prefer private ranges (192.168./10./172.16-31.) and stable NICs.
function lanIPv4s(): string[] {
  const nics = networkInterfaces();
  const priv: string[] = [];
  const other: string[] = [];
  for (const [name, addrs] of Object.entries(nics)) {
    for (const a of addrs ?? []) {
      if (a.family !== 'IPv4' || a.internal) continue;
      // skip virtual/container/adb NICs that aren't the real LAN
      if (/^(vEthernet|Loopback|WSL|Hyper-V|docker|veth|utun|tun|tap)/i.test(name)) continue;
      const ip = a.address;
      if (/^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) priv.push(ip);
      else other.push(ip);
    }
  }
  return [...priv, ...other];
}
function webUrls() {
  const port = HTTP_PORT;
  const lan = lanIPv4s().map((ip) => `http://${ip}:${port}`);
  return { port, local: `http://127.0.0.1:${port}`, lan };
}

// ---- Agent TCP server (NDJSON) -------------------------------------------

const agentServer = net.createServer((sock) => {
  let session: AgentSession | null = null;
  let acc: Buffer = Buffer.alloc(0);
  sock.setNoDelay(true);

  sock.on('data', (chunk: Buffer) => {
    acc = acc.length ? Buffer.concat([acc, chunk]) : chunk;
    for (;;) {
      if (acc.length < 5) break;
      const len = acc.readUInt32BE(0);
      const type = acc.readUInt8(4);
      if (len > FRAME_MAX) { log(`agent frame too large ${len} type=${type} — closing`); sock.destroy(); return; }
      if (acc.length < 5 + len) break;                 // wait for the rest of the frame
      const payload = acc.subarray(5, 5 + len);
      acc = acc.subarray(5 + len);
      if (type !== FRAME_JSON) { log(`agent unknown frame type ${type} — skipping`); continue; }
      let msg: AgentMsg;
      try { msg = JSON.parse(payload.toString('utf8')); } catch { log('bad json frame from agent, bytes=', len); continue; }
      handle(msg);
    }
  });

  function handle(msg: AgentMsg) {
    if (msg.t === 'hello') {
      const id = nextId();
      session = {
        sessionId: id,
        pid: msg.pid ?? 0,
        uid: msg.uid ?? 0,
        package: msg.package ?? '?',
        process: msg.process ?? msg.package ?? '?',
        abi: msg.abi ?? '?',
        android: msg.android ?? '?',
        sdk: msg.sdk ?? 0,
        entry: msg.entry ?? '?',
        agentVer: msg.agentVer ?? '?',
        connectedAt: Date.now(),
        lastSeen: Date.now(),
        online: true,
        mapsCount: 0,
        regionsSample: [],
      };
      sessions.set(id, session);
      agentSockets.set(id, sock);
      log(`agent HELLO ${session.package} pid=${session.pid} abi=${session.abi} entry=${session.entry} -> ${id}`);
      sock.write(frameJson({ t: 'ack', sessionId: id }));
      broadcast('agent.hello', session);
      startCaptureLoop(id);   // install persistent hooks + stream captures to the panel
    } else if (msg.t === 'maps' && session) {
      session.mapsCount = msg.count;
      session.regionsSample = (msg.regions ?? []).slice(0, 50);
      session.lastSeen = Date.now();
      log(`agent MAPS ${session.package} count=${msg.count}`);
      broadcast('agent.maps', { sessionId: session.sessionId, count: msg.count });
    } else if (msg.t === 'ping' && session) {
      session.lastSeen = Date.now();
      sock.write(frameJson({ t: 'pong' }));
    } else if (msg.t === 'cmdResult') {
      const p = pending.get(msg.id);
      log(`cmdResult op=${msg.op} id=${msg.id} matched=${!!p} bytes=${JSON.stringify(msg).length}`);
      if (p) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg); }
      if (session) session.lastSeen = Date.now();
    }
  }

  sock.on('close', () => {
    if (session) {
      session.online = false;
      session.lastSeen = Date.now();
      agentSockets.delete(session.sessionId);
      const t = captureTimers.get(session.sessionId);
      if (t) { clearInterval(t); captureTimers.delete(session.sessionId); }
      log(`agent CLOSE ${session.package} ${session.sessionId}`);
      broadcast('agent.close', { sessionId: session.sessionId });
    }
  });
  sock.on('error', (e) => log('agent sock error:', (e as Error).message));
});
// ---- HTTP routing (table-driven; was a 660-line if-chain) ----------------
// Each route: { method?, path, handler, prefix? }. method omitted = any method.
// prefix=true → startsWith match (for /:id path-param routes). First match wins;
// no match → 404. Handler bodies are byte-for-byte the original if-block bodies.
async function handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost`);
  const send = (code: number, body: unknown, type = 'application/json') => {
    const s = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
    res.writeHead(code, { 'content-type': type, 'access-control-allow-origin': '*' });
    res.end(s);
  };

  type Route = { method?: string; path: string; prefix?: boolean; handler: () => any };
  const routes: Route[] = [
    { path: '/health', handler: () => send(200, { ok: true, service: 'adhd', name: 'ADH Daemon', version: '0.1.0', agents: sessions.size, uptime: process.uptime(), mcpTools: MCP_TOOLS.length, web: webUrls() }) },
    // MCP Streamable HTTP endpoint (JSON-RPC)
    { method: 'POST', path: '/mcp', handler: async () => handleMcp(await readBody(req), res) },
    // Live captures (auto-populated by the persistent hooks): GET /api/captures?since=&limit=
    { path: '/api/captures', handler: () => {
      const since = Number(url.searchParams.get('since') ?? 0);
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 200), 1000);
      const list = captures.filter(c => c.id > since);
      // WS-C: `health` carries honest ring accounting — complete:false + dropped>0 when the
      // agent ring overflowed (no silent loss; the panel should show this in red).
      const health = captureHealth();
      return send(200, {
        total: captures.length, on: captureTimers.size > 0,
        complete: health.complete, dropped: health.dropped, jdropped: health.jdropped,
        seq: health.seq, backlog: health.backlog, health,
        captures: list.slice(-limit).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, func: c.func, inl: c.inl, tid: c.tid, ts: c.ts, preview: c.preview })),
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
      if (!applied.length) return send(400, { error: '没有可应用的板块(capture/ui)' });
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
      const md = ['# ADH MCP Tools', '', `Generated from the live ADH Daemon registry (${MCP_TOOLS.length} tools). Endpoint: \`POST /mcp\` (JSON-RPC 2.0).`, '',
        '| Tool | Description | Args |', '|---|---|---|',
        ...MCP_TOOLS.map(t => `| \`${t.name}\` | ${t.description} | ${Object.keys(t.inputSchema.properties ?? {}).join(', ') || '—'} |`), ''].join('\n');
      res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' }); return res.end(md);
    } },
    { path: '/api/crypto/identify', handler: () => send(200, cryptoIdentify()) },
    { path: '/api/mcp/config', handler: () => {
      const w = webUrls(); const lan = (w.lan[0] ?? w.local).replace(/^http/, 'http');
      const mcpUrl = `${lan}/mcp`;
      const cfg = {
        note: '把 mcpServers 这段粘进 Claude Desktop / Cursor 的 MCP 配置，重启后即可让 AI 调用 ADH 的全部逆向工具（分析内存/指令/hook/trace/事件搜索/抓包/脱壳/算法识别）',
        mcpServers: { adh: { type: 'http', url: mcpUrl } },
        endpoint: mcpUrl, tools: MCP_TOOLS.length,
        cli: `claude mcp add --transport http adh "${mcpUrl}"`,
        quickAsks: [
          '用 crypto_identify 看看这个 App 用了哪些加密算法和密钥',
          '用 unpack_run 一键脱壳，然后 dumps_list 给我下载链接',
          '用 live_captures 看实时加解密，挑一条用 capture_detail 展开明文',
          '用 trace_function hook 一下 access，看它检测了哪些 root 路径',
          '用 qbdi_trace 逐指令跟踪这个 native 函数',
        ],
      };
      return send(200, cfg);
    } },
    { path: '/api/agents', handler: () => send(200, [...sessions.values()]) },
    { path: '/api/agents/', prefix: true, handler: () => {
      const s = sessions.get(url.pathname.split('/')[3]);
      return s ? send(200, s) : send(404, { error: 'no such session' });
    } },
    // WS-D protocol self-test: GET /api/debug/frame_echo?session=ID&kb=N
    { path: '/api/debug/frame_echo', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const kb = Math.max(1, Math.min(4096, Number(url.searchParams.get('kb') ?? 64)));
      const padLen = kb * 1024;
      const pad = 'A'.repeat(padLen);
      const tail = 'IDH_FRAME_TAIL_v1';
      try {
        const r = await sendCmd(sid, 'frame_echo', { pad, tail, padLen }, 20_000);
        return send(r.ok ? 200 : 502, { ...r, sentPadLen: padLen, tailOk: r.tail === tail, notTruncated: (r.recvBytes ?? 0) > padLen });
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    // Java method-hook self-test (WS-A / LSPlant): GET /api/java/hook_test?session=ID
    { path: '/api/java/hook_test', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'java_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.javaHook }, 25_000)); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/process/maps', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await sendCmd(sid, 'maps');
        if (r.ok) { const s = sessions.get(sid); if (s) s.mapsCount = r.count; }
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/object/inspect', handler: async () => {
      const body = await readBody(req);
      const { session, className, field } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className || !field) return send(400, { error: 'need session, className, field' });
      try { const r = await sendCmd(sid, 'object_inspect', { className, field }); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/object/invoke', handler: async () => {
      const body = await readBody(req);
      const { session, className, field, method } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className || !field || !method) return send(400, { error: 'need session, className, field, method' });
      try { const r = await sendCmd(sid, 'object_invoke', { className, field, method }); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/compat/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'compat_probe'); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/trace/qbdi', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const symLib = url.searchParams.get('symLib') ?? 'libidhdetect.so';
      const symbol = url.searchParams.get('symbol') ?? 'idh_trace_target';
      try { const r = await sendCmd(sid, 'qbdi_trace', { symLib, symbol }, 30_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/trace/run', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const symLib = url.searchParams.get('symLib') ?? 'libc.so';
      const symbol = url.searchParams.get('symbol') ?? 'access';
      const hookModule = url.searchParams.get('hookModule') ?? 'libidhdetect.so';
      try { const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'trace_run', { symLib, symbol, hookModule, className: url.searchParams.get('class') ?? SANDBOX.detect }, 20_000)); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/detect/watch', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'detect_watch', { module: url.searchParams.get('module') ?? settings.capture.sysModule, className: url.searchParams.get('class') ?? SANDBOX.detect }, 20_000)); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/crypto/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'crypto_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/flow/watch', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'flow_watch', { className: url.searchParams.get('class') ?? SANDBOX.flow }, 25_000));
        const caps = (r.captures ?? []).map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
        const WINDOW_NS = 200_000_000;
        const crypto = caps.filter((c: any) => c.func.startsWith('EVP_') || c.func === 'HMAC_Update');
        const net = caps.filter((c: any) => c.func.startsWith('SSL_'));
        const correlations = [];
        for (const cr of crypto) for (const nw of net) {
          if (cr.tid === nw.tid && Math.abs(cr.tsNs - nw.tsNs) <= WINDOW_NS) {
            correlations.push({ tid: cr.tid, deltaMs: Math.abs(cr.tsNs - nw.tsNs) / 1e6,
              plaintext: cr.ascii, cryptoFunc: cr.func, netFunc: nw.func, request: nw.ascii.slice(0, 120) });
          }
        }
        r.captures = caps;
        return send(r.ok ? 200 : 502, { ...r, correlations });
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/net/hook_test', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'net_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.net }, 25_000));
        if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/file/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'file_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/file/hook_test', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const module = url.searchParams.get('module') ?? settings.capture.fileModule;
      try {
        const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'file_hook_test', { module, className: url.searchParams.get('class') ?? SANDBOX.file }, 25_000));
        if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/fs/list', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const path = url.searchParams.get('path') || '';
      if (!path) return send(400, { error: 'need path' });
      try { const r = await sendCmd(sid, 'list_dir', { path }, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/fs/read', handler: async () => {
      const body = await readBody(req);
      const { session, path } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !path) return send(400, { error: 'need session, path' });
      try {
        const r = await sendCmd(sid, 'read_file', { path: String(path) }, 25_000);
        if (r.ok && r.b64) { try { r.text = Buffer.from(r.b64, 'base64').toString('utf8'); } catch { r.text = ''; } }
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/crypto/hook_test', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'crypto_hook_test', { className: url.searchParams.get('class') ?? SANDBOX.crypto }, 20_000));
        if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/native/inline_hook_test', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const args = {
        module: url.searchParams.get('module') ?? SANDBOX.inlineModule,
        symbol: url.searchParams.get('symbol') ?? SANDBOX.inlineSymbol,
        className: url.searchParams.get('class') ?? SANDBOX.detect,
        method: url.searchParams.get('method') ?? SANDBOX.inlineMethod,
      };
      try {
        const r = await withCaptureSuspended(sid, () => sendCmd(sid, 'inline_crypto_test', args, 20_000));
        if (r.captures) r.captures = r.captures.map((c: any) => ({ ...c, ascii: Buffer.from(c.hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '.') }));
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/hook/selftest', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'gothook_selftest'); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/art/dexfiles', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/art/dump', handler: async () => {
      const body = await readBody(req);
      const { session, begin, size } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !begin || !size) return send(400, { error: 'need session, begin(hex), size' });
      try {
        const { meta, dedup } = await dumpRegion(sid, String(begin).replace(/^0x/, ''), Number(size), 'art_dexfile');
        return send(200, { ...meta, dedup });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { path: '/api/jni/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'jni_probe'); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/memory/scan_magic', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await sendCmd(sid, 'scan_magic', {}, 90_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/memory/read', handler: async () => {
      const body = await readBody(req);
      const { session, addr, size } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
      try {
        const r = await sendCmd(sid, 'read', { addr: String(addr), size: Number(size) });
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/unpack/run', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      const sid = pickSid(body.session);
      if (!sid) return send(400, { error: 'no session' });
      try { return send(200, await runUnpackSession(sid, body)); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/agent/load_so', handler: async () => {
      const { session, path: soPath, symbol } = JSON.parse((await readBody(req)) || '{}');
      const sid = pickSid(session);
      if (!sid || !soPath) return send(400, { error: 'need session + path' });
      try { const r = await sendCmd(sid, 'load_so', { path: soPath, symbol: symbol ?? '' }, 30_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/unpack/trigger', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      const className = url.searchParams.get('class');
      const method = url.searchParams.get('method') ?? '';
      const level = Number(url.searchParams.get('level') ?? 1);
      if (!sid || !className) return send(400, { error: 'need session + class' });
      try {
        const r = await sendCmd(sid, 'trigger', { className, method, level }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/memory/search', handler: async () => {
      const body = await readBody(req);
      const { session, hex, text, limit } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      const pat = hex ?? (text ? Buffer.from(String(text), 'utf8').toString('hex') : '');
      if (!sid || !pat) return send(400, { error: 'need session and hex|text' });
      try {
        const r = await sendCmd(sid, 'search', { pat, limit: Number(limit) || 256 }, 90_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/memory/dump', handler: async () => {
      const body = await readBody(req);
      const { session, addr, size, tag } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !addr || !size) return send(400, { error: 'need session, addr(hex), size' });
      try {
        const { meta, dedup } = await dumpRegion(sid, String(addr).replace(/^0x/, ''), Number(size), String(tag ?? ''));
        return send(200, { ...meta, dedup });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/syscall_scan', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const r = svcScan(buf);
      return send(200, { execSegs: r.execSegs, scannedBytes: r.scanned, svcCount: r.hits.length, hits: r.hits.slice(0, 200) });
    } },
    { method: 'POST', path: '/api/native/crypto_const', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const hits = cryptoConstScan(buf);
      const byName: Record<string, number> = {};
      for (const h of hits) byName[h.name] = (byName[h.name] ?? 0) + 1;
      return send(200, { size: buf.length, hits, byName, algorithms: Object.keys(byName) });
    } },
    { method: 'POST', path: '/api/native/analyze', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, q } = JSON.parse(body || '{}');
      let path: string, tmp: string | null;
      try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try {
        const a = await analyzeSo(path);
        if (q) { const rx = new RegExp(String(q), 'i');
          a.exports = a.exports.filter((s: string) => rx.test(s)); a.imports = a.imports.filter((s: string) => rx.test(s));
          a.strings = a.strings.filter((s: string) => rx.test(s)); }
        const CAP_SYM = 20000, CAP_STR = 1000;
        a.truncated = { exports: a.exports.length > CAP_SYM, imports: a.imports.length > CAP_SYM, strings: a.strings.length > CAP_STR };
        a.exports = a.exports.slice(0, CAP_SYM); a.imports = a.imports.slice(0, CAP_SYM); a.strings = a.strings.slice(0, CAP_STR);
        return send(200, a);
      } catch (e) { return send(502, { error: (e as Error).message }); }
      finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
    } },
    { method: 'POST', path: '/api/native/disasm', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, symbol, start, stop } = JSON.parse(body || '{}');
      let path: string, tmp: string | null;
      try { ({ path, tmp } = await dumpBufPath({ b64, sha })); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try {
        const insns = await disasmSo(path, { symbol, start, stop });
        return send(200, { symbol: symbol ?? null, count: insns.length, instructions: insns.slice(0, 2000) });
      } catch (e) { return send(502, { error: (e as Error).message, objdump: OBJDUMP }); }
      finally { if (tmp) { try { unlinkSync(tmp); } catch {} } }
    } },
    { path: '/api/modules', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try {
        const r = await sendCmd(sid, 'maps');
        if (!r.ok) return send(502, r);
        return send(200, modulesFromMaps(r.regions ?? []));
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/module/dump', handler: async () => {
      const body = await readBody(req);
      const { session, name } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !name) return send(400, { error: 'need session, name' });
      try {
        const maps = await sendCmd(sid, 'maps');
        const mod = modulesFromMaps(maps.regions ?? []).find(m => m.name === name || m.path.includes(name));
        if (!mod) return send(404, { error: `module not found: ${name}` });
        const buf = await reconstructSo(sid, mod.base);
        const sha = createHash('sha256').update(buf).digest('hex');
        const existing = dumps.get(sha);
        if (existing) return send(200, { ...existing, dedup: true, module: mod.name });
        const s = sessions.get(sid);
        const path = join(CAPTURES, `${sha.slice(0, 16)}.so`);
        if (!existsSync(path)) writeFileSync(path, buf);
        const meta: DumpMeta = { sha256: sha, size: buf.length, source: 'so-reassembly', addr: mod.base, tag: mod.name, sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind: 'so' };
        dumps.set(sha, meta);
        broadcast('dump.new', meta);
        return send(200, { ...meta, dedup: false, module: mod.name, segments: mod.segs });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/dex/method_code', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, class: cls, method } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!cls) return send(400, { error: 'need class' });
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const codes = extractMethodCode(buf, parsed, String(cls), method ? String(method) : undefined);
      const recovered = codes.filter(c => c.insnsSize > 0).length;
      return send(200, { class: cls, method: method ?? null, count: codes.length, recovered, empty: codes.length - recovered, methods: codes.slice(0, 200) });
    } },
    { method: 'POST', path: '/api/dex/index', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf(body); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      try { return send(200, ensureDexIndex(buf)); }
      catch (e) { return send(422, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/dex/index/search', handler: async () => {
      const { sha, query, limit } = JSON.parse((await readBody(req)) || '{}');
      if (!sha || query === undefined) return send(400, { error: 'need indexed dex sha and query' });
      try { return send(200, searchDexIndex(String(sha), String(query), limit)); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
    } },
    { method: 'POST', path: '/api/dex/index/reflections', handler: async () => {
      const { sha, limit } = JSON.parse((await readBody(req)) || '{}');
      if (!sha) return send(400, { error: 'need indexed dex sha' });
      try { return send(200, { sha, reflections: listDexReflections(String(sha), limit) }); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
    } },
    { method: 'POST', path: '/api/dex/xref', handler: async () => {
      const body = await readBody(req);
      const { b64, sha, method } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!method) return send(400, { error: 'need method (substring of callee cls->name)' });
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const { xref, methodsWithCode, skipped } = invokeXref(buf, parsed);
      const q = String(method).toLowerCase();
      const results: Record<string, string[]> = {};
      for (const [callee, callers] of xref) if (callee.toLowerCase().includes(q)) results[callee] = callers.slice(0, 200);
      return send(200, { method, methodsWithCode, skipped, matches: Object.keys(results).length, callers: results });
    } },
    { method: 'POST', path: '/api/dex/coverage', handler: async () => {
      const { b64, sha, limitMissing } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      let parsed; try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
      const cov = analyzeCoverage(buf, parsed);
      const lm = Number(limitMissing ?? 100);
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...cov,
        recoveryPct: +(cov.recoveryRate * 100).toFixed(2), missing: cov.missing.slice(0, lm), missingTotal: cov.missing.length });
    } },
    { method: 'POST', path: '/api/dex/recover', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      const load = (b64?: string, sha?: string) => (b64 || (sha && dumps.get(sha))) ? dumpBuf({ b64, sha }) : Promise.resolve(null);
      let base: Buffer | null, restored: Buffer | null;
      try { base = await load(body.baseB64, body.baseSha); restored = await load(body.restoredB64, body.restoredSha); }
      catch (e: any) { return send(e.status ?? 500, { error: e.message }); }
      if (!base || !restored) return send(400, { error: 'need base + restored (b64 or known sha)' });
      let parsed; try { parsed = parseDex(base); } catch (e) { return send(422, { error: (e as Error).message }); }
      const { captures, report } = recoverFromSnapshots(base, restored, parsed);
      const rb = rebuildStandardDex(base, captures);
      let parseOk = true; try { parseDex(rb.dex); } catch { parseOk = false; }
      const outSha = createHash('sha256').update(rb.dex).digest('hex');
      const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
      if (!existsSync(path)) writeFileSync(path, rb.dex);
      const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
      dumps.set(outSha, meta); broadcast('dump.new', meta);
      return send(200, { ok: true, ...report, injected: rb.injected, classesRewritten: rb.classesRewritten, parseOk, sha256: outSha, size: rb.dex.length });
    } },
    { method: 'POST', path: '/api/dex/strip', handler: async () => {
      const { b64, sha, midx } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const stripped = stripMethodCode(buf, Number(midx));
      return send(200, { ok: true, midx: Number(midx), b64: stripped.toString('base64') });
    } },
    { method: 'POST', path: '/api/dex/rebuild', handler: async () => {
      const { b64, sha, captures } = JSON.parse((await readBody(req)) || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      if (!Array.isArray(captures)) return send(400, { error: 'need captures[]' });
      let res; try { res = rebuildStandardDex(buf, captures); } catch (e) { return send(422, { error: (e as Error).message }); }
      let parseOk = true, methods = 0;
      try { const pd = parseDex(res.dex); methods = pd.counts.methods; } catch { parseOk = false; }
      const outSha = createHash('sha256').update(res.dex).digest('hex');
      const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`);
      if (!existsSync(path)) writeFileSync(path, res.dex);
      const meta: DumpMeta = { sha256: outSha, size: res.dex.length, source: 'dex-rebuild', addr: '0', tag: 'rebuilt', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' };
      dumps.set(outSha, meta); broadcast('dump.new', meta);
      return send(200, { ok: true, injected: res.injected, classesRewritten: res.classesRewritten, parseOk, methods, sha256: outSha, size: res.dex.length });
    } },
    // Combined: /api/dex/parse | /api/dex/crypto_scan | /api/dex/search — one body, branches on path.
    { method: 'POST', path: '/api/dex/parse', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/crypto_scan', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/search', handler: dexParseScanSearch },
    { method: 'POST', path: '/api/dex/repair', handler: async () => {
      const body = await readBody(req);
      const { b64, sha } = JSON.parse(body || '{}');
      let buf: Buffer;
      try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
      const info = repairDexHeader(buf);
      return send(200, { ...info, size: buf.length, repairedB64: buf.toString('base64') });
    } },
    { path: '/api/dumps', handler: () => send(200, [...dumps.values()]) },
    { path: '/api/dumps/download', handler: () => {
      const sha = url.searchParams.get('sha') ?? '';
      const m = dumps.get(sha);
      if (!m) return send(404, { error: 'no such dump' });
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-disposition': `attachment; filename="${sha.slice(0, 16)}.${m.kind}.bin"` });
      return createReadStream(m.path).pipe(res);
    } },
    { path: '/', handler: dashboardHtml },
    { path: '/index.html', handler: dashboardHtml },
  ];

  async function dexParseScanSearch() {
    const body = await readBody(req);
    const { b64, sha, full } = JSON.parse(body || '{}');
    let buf: Buffer;
    try { buf = await dumpBuf({ b64, sha }); } catch (e: any) { return send(e.status ?? 400, { error: e.message }); }
    let parsed;
    try { parsed = parseDex(buf); } catch (e) { return send(422, { error: (e as Error).message }); }
    if (url.pathname === '/api/dex/crypto_scan') {
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...cryptoScan(parsed) });
    }
    if (url.pathname === '/api/dex/search') {
      const { query, kinds } = JSON.parse(body || '{}');
      if (!query) return send(400, { error: 'need query' });
      return send(200, { magic: parsed.magic, counts: parsed.counts, ...searchDex(parsed, String(query), kinds) });
    }
    // parse: counts + samples (or full arrays when full=true)
    const cap = full ? Infinity : 200;
    return send(200, {
      magic: parsed.magic, counts: parsed.counts,
      classes: parsed.classes.slice(0, cap).map(c => c.name),
      methods: parsed.methods.slice(0, cap),
      strings: parsed.strings.slice(0, cap),
    });
  }
  async function dashboardHtml() {
    try {
      const html = await readFile(join(__dirname, '..', 'public', 'index.html'), 'utf8');
      return send(200, html, 'text/html; charset=utf-8');
    } catch { return send(500, { error: 'dashboard missing' }); }
  }

  for (const r of routes) {
    if (r.method && req.method !== r.method) continue;
    if (r.prefix ? url.pathname.startsWith(r.path) : url.pathname === r.path) {
      return await r.handler();
    }
  }
  send(404, { error: 'not found' });
}
// Top-level error net: no request may crash the daemon. An uncaught JSON.parse throws SyntaxError
// -> 400; typed errors carry their own status (e.g. dumpBuf 404/400); anything else -> 500.
const httpServer = http.createServer((req, res) => {
  handleHttp(req, res).catch((e: any) => {
    if (res.writableEnded) return;
    const status = e?.status ?? (e instanceof SyntaxError ? 400 : 500);
    try { res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }); res.end(JSON.stringify({ error: e?.message ?? 'internal error' })); } catch {}
  });
});

httpServer.on('upgrade', (req, socket, head) => {
  const { pathname } = new URL(req.url ?? '/', 'http://localhost');
  if (pathname === '/ws') {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(JSON.stringify({ event: 'snapshot', data: [...sessions.values()], ts: Date.now() }));
    });
  } else socket.destroy();
});

// ---- boot -----------------------------------------------------------------

agentServer.listen(AGENT_PORT, '0.0.0.0', () => log(`ADH Daemon agent TCP listening on :${AGENT_PORT}`));
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  const w = webUrls();
  log(`ADH Daemon HTTP + WS listening on 0.0.0.0:${HTTP_PORT}`);
  log('┌─ ADH Daemon web console ────────────────────────────────────');
  log(`│  local : ${w.local}   (this PC's browser)`);
  if (w.lan.length) {
    for (const u of w.lan) log(`│  LAN   : ${u}   (phone / any device on the same network)`);
  } else {
    // fail-loud, like the iOS ref: don't pretend LAN access works when it can't
    log('│  LAN   : (no LAN IPv4 found — console reachable locally only;');
    log('│          the phone can still open it via `adb reverse tcp:8760`)');
  }
  log(`│  phone : also run 'adb reverse tcp:${AGENT_PORT} tcp:${AGENT_PORT}' + 'adb reverse tcp:${HTTP_PORT} tcp:${HTTP_PORT}'`);
  log('└─────────────────────────────────────────────────────────────');
});

process.on('SIGINT', () => { log('shutting down'); process.exit(0); });

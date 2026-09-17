import {
  dumpAllDex, dumpRegion, pickSid, sendCmd, withCaptureSuspended,
} from '../service.ts';
import { watchSyscalls } from '../syscall_watch.ts';
import { liveDisasm } from '../memory.ts';
import { readBody, SANDBOX, sessions, settings } from '../state.ts';
import type { Route, RouteContext } from './types.ts';

export function runtimeRoutes({ req, url, send }: RouteContext): Route[] {
  return [
    // WS-D protocol self-test: GET /api/debug/frame_echo?session=ID&kb=N
    { path: '/api/debug/frame_echo', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const kb = Math.max(1, Math.min(4096, Number(url.searchParams.get('kb') ?? 64)));
      const padLen = kb * 1024;
      const pad = 'A'.repeat(padLen);
      const tail = 'ADH_FRAME_TAIL_v1';
      try {
        const r = await sendCmd(sid, 'frame_echo', { pad, tail, padLen }, 20_000);
        return send(r.ok ? 200 : 502, { ...r, sentPadLen: padLen, tailOk: r.tail === tail, notTruncated: (r.recvBytes ?? 0) > padLen });
      } catch (e) { return send(504, { error: (e as Error).message }); }
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
    { path: '/api/java/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'javahook_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/java/call', handler: async () => {
      const body = await readBody(req);
      const { session, className, method, params, field, args } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className || !method) return send(400, { error: 'need session, className, method' });
      try {
        const r = await sendCmd(sid, 'java_call', {
          className, method, params: params ?? '', field: field ?? '', args: JSON.stringify(args ?? []),
        }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/native/got_enum', handler: async () => {
      const body = await readBody(req);
      const { session, module, filter } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !module) return send(400, { error: 'need session, module' });
      try { const r = await sendCmd(sid, 'got_enum', { module, filter: filter ?? '' }, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/native/hook', handler: async () => {
      const body = await readBody(req);
      const { session, action, hookId, mode, module, symbol, addr } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        const r = await sendCmd(sid, 'native_hook', {
          action, hookId: Number(hookId ?? 0), mode: mode ?? '', module: module ?? '', symbol: symbol ?? '', addr: addr ?? '',
        }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/native/call', handler: async () => {
      const body = await readBody(req);
      const { session, module, symbol, addr, args, confirm } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || (!addr && (!module || !symbol))) return send(400, { error: 'need session and addr or module+symbol' });
      if (confirm !== true) return send(400, { error: 'native_call requires confirm:true (arbitrary target call can crash the process)' });
      try {
        const r = await sendCmd(sid, 'native_call', {
          module: module ?? '', symbol: symbol ?? '', addr: addr ?? '',
          args: Array.isArray(args) ? args.map((v: any) => String(v)).join(',') : String(args ?? ''),
        }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/syscall_watch', handler: async () => {
      const body = await readBody(req);
      const { session, module, limit } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !module) return send(400, { error: 'need session, module' });
      try {
        const r = await watchSyscalls(sid, { module, limit });
        return send(200, r);
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/java/enum', handler: async () => {
      const body = await readBody(req);
      const { session, className } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className) return send(400, { error: 'need session, className' });
      try { const r = await sendCmd(sid, 'java_enum', { className }, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/java/hook', handler: async () => {
      const body = await readBody(req);
      const { session, action, hookId, className, method, params } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        const r = await sendCmd(sid, 'java_hook', {
          action,
          hookId: Number(hookId ?? 0),
          className: className ?? '',
          method: method ?? '',
          params: params ?? '',
        }, 30_000);
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
      const symLib = url.searchParams.get('symLib') ?? 'libadhdetect.so';
      const symbol = url.searchParams.get('symbol') ?? 'adh_trace_target';
      try { const r = await sendCmd(sid, 'qbdi_trace', { symLib, symbol }, 30_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/trace/run', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const symLib = url.searchParams.get('symLib') ?? 'libc.so';
      const symbol = url.searchParams.get('symbol') ?? 'access';
      const hookModule = url.searchParams.get('hookModule') ?? 'libadhdetect.so';
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
    { method: 'POST', path: '/api/memory/disasm', handler: async () => {
      const body = await readBody(req);
      const { session, addr, size, module, offset } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || (!addr && (!module || offset === undefined || offset === null))) {
        return send(400, { error: 'need session and addr, or session+module+offset' });
      }
      try {
        const r = await liveDisasm(sid, { addr, size, module, offset });
        return send(200, r);
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/unpack/dump-all', handler: async () => {
      const body = JSON.parse((await readBody(req)) || '{}');
      const sid = pickSid(body.session);
      if (!sid) return send(400, { error: 'no session' });
      try { return send(200, await dumpAllDex(sid)); }
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
  ];
}

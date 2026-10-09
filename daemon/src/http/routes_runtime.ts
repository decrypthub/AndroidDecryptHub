import {
  dumpAllDex, dumpRegion, pickSid, sendCmd,
} from '../service.ts';
import { watchSyscalls } from '../syscall_watch.ts';
import { nativeBacktrace } from '../backtrace.ts';
import { traceDigest } from '../trace_digest.ts';
import { syscallDigest } from '../syscall_digest.ts';
import { javaTraceStart, javaTraceDigest, javaTraceStop } from '../java_trace.ts';
import { nativeHookAll, nativeUnhookAll } from '../native_hook_all.ts';
import { normalizeThrottleMs } from '../native_hook_args.ts';
import { agentPing, hookEngineSelftest, protocolSelfTest } from '../agent_probe.ts';
import { listDeviceDir, readDeviceFile } from '../fs_browse.ts';
import { jniFieldDigest } from '../jni_field_digest.ts';
import { syscallTraceStart, syscallTraceDigest, syscallTraceStop } from '../syscall_trace.ts';
import { liveDisasm , assertCallableAddress } from '../memory.ts';
import { readBody, sessions, settings } from '../state.ts';
import type { Route, RouteContext } from './types.ts';

// A non-numeric throttleMs is a caller error, not a device failure: answer 400 before the
// sendCmd try/catch blocks below (which turn anything they catch into 502/504).
function parseThrottleMs(value: unknown): { ms: number } | { error: string } {
  try { return { ms: normalizeThrottleMs(value) }; } catch (e) { return { error: (e as Error).message }; }
}

export function runtimeRoutes({ req, url, send }: RouteContext): Route[] {
  return [
    // WS-D protocol self-test: GET /api/debug/frame_echo?session=ID&kb=N
    // Shares protocolSelfTest with the MCP tool protocol_selftest, so the two surfaces cannot drift.
    { path: '/api/debug/frame_echo', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const kb = Math.max(1, Math.min(4096, Number(url.searchParams.get('kb') ?? 64)));
      try {
        const r = await protocolSelfTest(sid, kb);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    // Liveness probe for one session (agent_ping): the agent op existed since v0.2 but no host
    // code ever sent it, so a hung agent could only be diagnosed by waiting out a real timeout.
    { path: '/api/agent/ping', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { return send(200, await agentPing(sid)); }
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
      const { session, action, hookId, mode, module, symbol, addr, skipOriginal, returnValue, argIndex, argValue, confirm, hard, sites, scope, slotsWritable, backtrace, throttleMs } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      if (mode === 'inline' && addr && confirm !== true) return send(400, { error: 'native_hook inline addr requires confirm:true' });
      // v4.99: same coverage and normalization as the MCP tool - every raw-address hook mode
      // (inline/sites/vtable) is checked, the agent receives the address that was checked, and
      // action:unhook/status (hookId only) is not blocked by a stale addr.
      let hookAddr = typeof addr === 'string' ? addr : '';
      if (action === 'hook' && addr && (mode === 'inline' || mode === 'sites' || mode === 'vtable')) {
        const guard = await assertCallableAddress(sid, addr);
        if (!guard.ok) return send(400, { error: guard.error });
        hookAddr = guard.addr;
      }
      const throttle = parseThrottleMs(throttleMs);
      if ('error' in throttle) return send(400, { error: throttle.error });
      try {
        const r = await sendCmd(sid, 'native_hook', {
          action, hookId: Number(hookId ?? 0), mode: mode ?? '', module: module ?? '', symbol: symbol ?? '', addr: hookAddr,
          skipOriginal: skipOriginal ? 'true' : 'false', returnValue: returnValue ?? '',
          backtrace: backtrace ? 'true' : 'false',
          throttleMs: throttle.ms,
          argIndex: Number(argIndex ?? -1), argValue: argValue ?? '', hard: hard ? 'true' : 'false',
          sites: Number(sites ?? 0),
          scope: typeof scope === 'string' ? scope : '',
          slotsWritable: slotsWritable ? 'true' : 'false',
        }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/native/call', handler: async () => {
      const body = await readBody(req);
      const { session, module, symbol, addr, args, confirm } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || (!addr && (!module || !symbol))) return send(400, { error: 'need session and addr or module+symbol' });
      if (confirm !== true) return send(400, { error: 'native_call requires confirm:true (arbitrary target call can crash the process)' });
      // Same guard as the MCP tool (v4.97): the two entry points must not diverge on something that
      // decides whether an arbitrary address is called.
      const guard = await assertCallableAddress(sid, addr);
      if (!guard.ok) return send(400, { error: guard.error });
      try {
        const r = await sendCmd(sid, 'native_call', {
          module: module ?? '', symbol: symbol ?? '', addr: guard.addr,
          args: Array.isArray(args) ? args.map((v: any) => String(v)).join(',') : String(args ?? ''),
        }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/stealth', handler: async () => {
      const body = await readBody(req);
      const { session, action, confirm } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      const act = String(action ?? '');
      if (!sid) return send(400, { error: 'need session' });
      if (act !== 'status' && act !== 'on' && act !== 'off') return send(400, { error: 'action must be on|off|status' });
      if (act !== 'status' && confirm !== true) {
        return send(400, { error: 'stealth on/off changes the target process footprint and requires confirm:true' });
      }
      try {
        const r = await sendCmd(sid, 'stealth', { action: act }, 15_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/syscall/trace', handler: async () => {
      const body = await readBody(req);
      const { session, action, module, syscalls, limit, hookIds, expected, sinceMs, decode, decodeLimit, maxGroups, throttleMs } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        if (action === 'start') {
          const throttle = parseThrottleMs(throttleMs);
          if ('error' in throttle) return send(400, { error: throttle.error });
          return send(200, await syscallTraceStart(sid, { module, syscalls, limit, throttleMs: throttle.ms }));
        }
        if (action === 'digest') return send(200, await syscallTraceDigest(sid, { hookIds, expected, sinceMs, decode, decodeLimit, maxGroups }));
        if (action === 'stop') return send(200, await syscallTraceStop(sid, { hookIds }));
        return send(400, { error: 'action must be start | digest | stop' });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/hook_all', handler: async () => {
      const body = await readBody(req);
      const { session, action, module, prefix, contains, exact, exclude, limit, backtrace, skipOriginal, returnValue, argIndex, argValue, hookIds, confirm, throttleMs } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        if (action === 'unhook') return send(200, await nativeUnhookAll(sid, hookIds));
        if (action !== 'hook') return send(400, { error: 'action must be hook | unhook' });
        if (confirm !== true) return send(400, { error: 'native_hook_all requires confirm:true (it installs inline hooks in the target)' });
        const throttle = parseThrottleMs(throttleMs);
        if ('error' in throttle) return send(400, { error: throttle.error });
        return send(200, await nativeHookAll(sid, { module, prefix, contains, exact, exclude, limit, backtrace, throttleMs: throttle.ms, skipOriginal, returnValue, argIndex, argValue }));
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/java/trace', handler: async () => {
      const body = await readBody(req);
      const { session, action, className, method, params, limit, stack, hookIds, maxTimeline, maxMethods, maxCallers } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid) return send(400, { error: 'need session' });
      try {
        if (action === 'start') return send(200, await javaTraceStart(sid, { className: String(className ?? ''), method, params, limit, stack: stack === true }));
        if (action === 'digest') return send(200, await javaTraceDigest(sid, { hookIds, maxTimeline, maxMethods, maxCallers }));
        if (action === 'stop') return send(200, await javaTraceStop(sid, { hookIds }));
        return send(400, { error: 'action must be start | digest | stop' });
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/jni/field_digest', handler: async () => {
      const body = await readBody(req);
      const { session, sinceMs, limit, maxGroups } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid) return send(400, { error: 'no session' });
      try { return send(200, await jniFieldDigest(sid, { sinceMs, limit, maxGroups })); }
      catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/syscall/digest', handler: async () => {
      const body = await readBody(req);
      const { session, hookIds, expected, sinceMs, limit, maxGroups, decode, decodeLimit } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid) return send(400, { error: 'need session' });
      try {
        return send(200, await syscallDigest(sid, { hookIds, expected, sinceMs, limit, maxGroups, decode, decodeLimit }));
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/trace/digest', handler: async () => {
      const body = await readBody(req);
      const { session, symLib, symbol, args } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !symbol) return send(400, { error: 'need session, symbol' });
      try {
        return send(200, await traceDigest(sid, { symLib, symbol, args }));
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/backtrace', handler: async () => {
      const body = await readBody(req);
      const { session, hookId, fp, lr, maxFrames } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid) return send(400, { error: 'need session' });
      try {
        return send(200, await nativeBacktrace({ session: sid, hookId, fp, lr, maxFrames }));
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/native/syscall_watch', handler: async () => {
      const body = await readBody(req);
      const { session, module, limit, syscalls, throttleMs } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !module) return send(400, { error: 'need session, module' });
      try {
        const throttle = parseThrottleMs(throttleMs);
        if ('error' in throttle) return send(400, { error: throttle.error });
        const r = await watchSyscalls(sid, { module, limit, syscalls, throttleMs: throttle.ms });
        return send(200, r);
      } catch (e) { return send(502, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/jni/onload', handler: async () => {
      const body = await readBody(req);
      const { session, action, module, confirm, skipOriginal, returnValue } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      if (action === 'call' && confirm !== true) return send(400, { error: 'jni_onload call requires confirm:true' });
      try {
        const r = await sendCmd(sid, 'jni_onload', { action, module: module ?? '', skipOriginal: skipOriginal ? 'true' : 'false', returnValue: String(returnValue ?? 0) }, 30_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/jni/hook', handler: async () => {
      const body = await readBody(req);
      const { session, action } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        const r = await sendCmd(sid, 'jni_hook', { action }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/jni/env_hook', handler: async () => {
      const body = await readBody(req);
      const { session, action, function: fn, setValue } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      if (action !== 'status' && !fn) return send(400, { error: 'need function' });
      try {
        const r = await sendCmd(sid, 'jni_env_hook', { action, function: fn ?? '', setValue: setValue ?? '' }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/java/enum', handler: async () => {
      const body = await readBody(req);
      const { session, className } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className) return send(400, { error: 'need session, className' });
      try { const r = await sendCmd(sid, 'java_enum', { className }, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },    { method: 'POST', path: '/api/java/hook', handler: async () => {
      const body = await readBody(req);
      const { session, action, hookId, className, method, params, skipOriginal, returnValue, argIndex, argValue, stack, limit } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !action) return send(400, { error: 'need session, action' });
      try {
        const r = await sendCmd(sid, 'java_hook', {
          action: action === 'hookAll' ? 'hook_all' : action,
          limit: Number(limit ?? 0),
          hookId: Number(hookId ?? 0),
          className: className ?? '',
          method: method ?? '',
          params: params ?? '',
          skipOriginal: skipOriginal ? 'true' : 'false',
          returnValue: returnValue ?? '',
          argIndex: Number(argIndex ?? -1),
          argValue: argValue ?? '',
          stack: stack ? 'true' : 'false',
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
    { method: 'POST', path: '/api/object/set', handler: async () => {
      const body = await readBody(req);
      const { session, className, field, targetField, value } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !className || !field || !targetField) return send(400, { error: 'need session, className, field, targetField' });
      if (value === undefined || value === null) return send(400, { error: 'need value' });
      try {
        const r = await sendCmd(sid, 'object_set', { className, field, targetField, value: String(value) }, 20_000);
        return send(r.ok ? 200 : 502, r);
      } catch (e) { return send(504, { error: (e as Error).message }); }
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
      // No fixture defaults anywhere (agent v4.50 refuses them, and the sandbox names must not leak
      // into the host either): say what is missing instead of silently tracing a fixture.
      const symLib = url.searchParams.get('symLib') ?? '';
      const symbol = url.searchParams.get('symbol') ?? '';
      if (!symLib || !symbol) return send(400, { error: 'qbdi_trace needs symLib and symbol' });
      const args = url.searchParams.get('args') ?? '';
      try { const r = await sendCmd(sid, 'qbdi_trace', { symLib, symbol, args }, 30_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    // The one-shot probe routes lived here until 2026-10-01: /api/trace/run, /api/detect/watch,
    // /api/crypto/probe, /api/flow/watch, /api/net/hook_test and /api/crypto/hook_test all drove
    // agent ops that hardcoded a sandbox trigger contract. The capability now comes from the
    // persistent capture set (MCP capture_start / capture_stop, agent op capture_start), a
    // caller-supplied trigger (MCP java_call) and the daemon-side join in flow.ts.
    { path: '/api/file/probe', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await sendCmd(sid, 'file_probe', {}, 20_000); return send(r.ok ? 200 : 502, r); }
      catch (e) { return send(504, { error: (e as Error).message }); }
    } },
    { path: '/api/fs/list', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      const path = url.searchParams.get('path') || '';
      if (!path) return send(400, { error: 'need path' });
      // Shared with the MCP tool fs_list.
      try { return send(200, await listDeviceDir(sid, path)); }
      catch (e) { return send(502, { ok: false, error: (e as Error).message }); }
    } },
    { method: 'POST', path: '/api/fs/read', handler: async () => {
      const body = await readBody(req);
      const { session, path } = JSON.parse(body || '{}');
      const sid = pickSid(session);
      if (!sid || !path) return send(400, { error: 'need session, path' });
      // Shared with the MCP tool fs_read; `text` is kept for the pre-existing consumers (the web
      // file viewer and verify_v25_fsbrowser read /proc/self/cmdline through it).
      try {
        const r = await readDeviceFile(sid, String(path), { includeBase64: true });
        const text = Buffer.from(r.b64 ?? '', 'base64').toString('utf8');
        return send(200, { ...r, text });
      } catch (e) { return send(502, { ok: false, error: (e as Error).message }); }
    } },
    // Shares hookEngineSelftest with the MCP tool engine_selftest. The agent fields stay top level
    // (replaced/fired/protRestored/perms) and the status code follows the VERDICT, so a build that
    // leaves the page writable no longer answers 200 just because the command ran.
    { path: '/api/hook/selftest', handler: async () => {
      const sid = pickSid(url.searchParams.get('session'));
      if (!sid) return send(400, { error: 'no session' });
      try { const r = await hookEngineSelftest(sid); return send(r.ok ? 200 : 502, r); }
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

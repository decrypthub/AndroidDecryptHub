// mcp.ts — MCP Server (Streamable HTTP / JSON-RPC).
// Exposes the workbench Service Layer as MCP tools for AI clients. Shares the same
// logic as the REST API (no duplicate business logic) — handlers delegate to service.ts
// primitives (agentCmd/dumpBuf/dumpRegion/dumpAllDex/...) + state.ts (captures/...).
// Adding a tool = add one entry to MCP_TOOLS below.
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeSo, cryptoConstScan, svcScan, disasmSo } from './analysis.ts';
import { parseDex, cryptoScan, searchDex, invokeXref, extractMethodCode, analyzeCoverage, rebuildStandardDex, recoverFromSnapshots } from './dex.ts';
import { ensureDexIndex, searchDexIndex, listDexReflections } from './dex_index.ts';
import { agentCmd, dumpAllDex, dumpBuf, dumpBufPath, dumpRegion, pickSid, repairDexHeader, sessionForPackage } from './service.ts';
import { backendMatrix, classifySession } from './backends.ts';
import { automation } from './automation.ts';
import { sessions, dumps, captures, captureTimers, SANDBOX, settings, CAPTURES, cryptoIdentify } from './state.ts';
import type { DumpMeta } from './state.ts';

const S = { type: 'string' }, N = { type: 'number' };
export const MCP_TOOLS: { name: string; description: string; inputSchema: any; handler: (a: any) => Promise<any>; raw?: boolean }[] = [
  { name: 'process_list', description: 'List connected target agent sessions', inputSchema: { type: 'object', properties: {} }, handler: async () => [...sessions.values()] },
  { name: 'backends', description: 'Injection-backend matrix: sessions by entry, host-side Frida Gadget cache + loader command, device-side backend pointers. Pass session to classify which injection paths are really loaded in that process (zygisk / xposed_module / frida_gadget / self_load).', inputSchema: { type: 'object', properties: { session: S } }, handler: async (a) => { const m = backendMatrix(); return a.session ? { ...m, sessionBackends: await classifySession(a.session) } : m; } },
  { name: 'dumps_list', description: 'List captured dump artifacts (dex/so/region)', inputSchema: { type: 'object', properties: {} }, handler: async () => [...dumps.values()] },
  { name: 'compat_probe', description: 'Self-assess agent env + injection footprint: tracer/seccomp/backends/exec/anon/rwx', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'compat_probe') },
  { name: 'memory_maps', description: 'On-demand full /proc/self/maps of the target', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'maps') },
  { name: 'memory_read', description: 'Read target memory at hex addr for size bytes (base64 out)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: (a) => agentCmd(a.session, 'read', { addr: a.addr, size: a.size }) },
  { name: 'memory_search', description: 'Search target memory for hex or text pattern', inputSchema: { type: 'object', properties: { session: S, hex: S, text: S, limit: N } }, handler: (a) => agentCmd(a.session, 'search', { pat: a.hex ?? Buffer.from(String(a.text ?? ''), 'utf8').toString('hex'), limit: a.limit ?? 256 }, 90_000) },
  { name: 'memory_scan_magic', description: 'Scan target memory for dex/elf/oat/vdex/zip magics', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'scan_magic', {}, 90_000) },
  { name: 'art_dexfiles', description: 'Enumerate loaded DexFiles via ART ClassLoader structures (no magic scan)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'art_dexfiles', {}, 30_000) },
  { name: 'crypto_capture', description: 'Hook EVP_CipherUpdate + trigger the target’s crypto workload class; return captured plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'crypto_hook_test', { className: a.class ?? SANDBOX.crypto }, 20_000) },
  { name: 'net_capture', description: 'Hook SSL_write/SSL_read + trigger HTTPS; return captured TLS plaintext', inputSchema: { type: 'object', properties: { session: S, class: S } }, handler: (a) => agentCmd(a.session, 'net_hook_test', { className: a.class ?? SANDBOX.net }, 25_000) },
  { name: 'file_probe', description: 'Recon which loaded module’s GOT holds open/openat/read/write/close pointers (guides file_capture’s module arg)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'file_probe', {}, 20_000) },
  { name: 'file_capture', description: 'Hook open/openat/read/write/close + trigger the target’s file I/O; return captured paths + read/write bytes', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'file_hook_test', { module: a.module ?? settings.capture.fileModule, className: a.class ?? SANDBOX.file }, 25_000) },
  { name: 'detect_watch', description: 'Observe the target’s own anti-analysis checks (debug/root/prop)', inputSchema: { type: 'object', properties: { session: S, module: S, class: S } }, handler: (a) => agentCmd(a.session, 'detect_watch', { module: a.module ?? settings.capture.sysModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'object_inspect', description: 'Read a live Java object’s fields via reflection (static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S }, required: ['className', 'field'] }, handler: (a) => agentCmd(a.session, 'object_inspect', { className: a.className, field: a.field }) },
  { name: 'dex_search', description: 'Search a dex (b64|sha) for strings/classes/methods', inputSchema: { type: 'object', properties: { b64: S, sha: S, query: S, kinds: { type: 'array', items: S } }, required: ['query'] }, handler: async (a) => searchDex(parseDex(await dumpBuf(a)), a.query, a.kinds) },
  { name: 'dex_index', description: 'Build or reuse the persistent SQLite index for a dex (b64|known dump sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => ensureDexIndex(await dumpBuf(a)) },
  { name: 'dex_index_search', description: 'Search an indexed dex for strings, string callers, classes, fields, methods and reflection targets', inputSchema: { type: 'object', properties: { sha: S, query: S, limit: N }, required: ['sha', 'query'] }, handler: async (a) => searchDexIndex(String(a.sha), String(a.query), a.limit) },
  { name: 'dex_reflections', description: 'List statically resolved Class.forName targets and their callers from an indexed dex', inputSchema: { type: 'object', properties: { sha: S, limit: N }, required: ['sha'] }, handler: async (a) => ({ sha: a.sha, reflections: listDexReflections(String(a.sha), a.limit) }) },
  { name: 'dex_xref', description: 'Find callers of a method in a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, method: S }, required: ['method'] }, handler: async (a) => { const buf = await dumpBuf(a); const { xref } = invokeXref(buf, parseDex(buf)); const q = String(a.method).toLowerCase(); const out: Record<string, string[]> = {}; for (const [c, cs] of xref) if (c.toLowerCase().includes(q)) out[c] = cs.slice(0, 200); return out; } },
  { name: 'dex_crypto_scan', description: 'Static crypto scan of a dex (API refs + algorithm strings)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoScan(parseDex(await dumpBuf(a))) },
  { name: 'native_disasm', description: 'Disassemble an ELF .so (b64|sha) by symbol', inputSchema: { type: 'object', properties: { b64: S, sha: S, symbol: S }, required: ['symbol'] }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await disasmSo(t, { symbol: a.symbol }); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_analyze', description: 'Exports/imports/NEEDED/strings of an ELF .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const t = join(tmpdir(), `mcp_${Date.now()}.so`); writeFileSync(t, await dumpBuf(a)); try { return await analyzeSo(t); } finally { try { unlinkSync(t); } catch {} } } },
  { name: 'native_crypto_const', description: 'Locate crypto by constant signatures in a stripped .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => cryptoConstScan(await dumpBuf(a)) },
  { name: 'native_syscall_scan', description: 'Find direct svc #0 syscalls in a .so (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => svcScan(await dumpBuf(a)) },
  { name: 'memory_dump', description: 'Dump target memory [addr,addr+size) to a capture artifact (sha256 dedup)', inputSchema: { type: 'object', properties: { session: S, addr: S, size: N }, required: ['addr', 'size'] }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); const { meta, dedup } = await dumpRegion(sid, String(a.addr).replace(/^0x/, ''), Number(a.size), 'mcp'); return { ...meta, dedup }; } },
  { name: 'flow_correlate', description: 'Hook EVP+SSL_write, trigger encrypt-then-send, capture plaintext+request (tid/ts)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'object_invoke', description: 'Call a no-arg method on a live object (via static field path)', inputSchema: { type: 'object', properties: { session: S, className: S, field: S, method: S }, required: ['className', 'field', 'method'] }, handler: (a) => agentCmd(a.session, 'object_invoke', { className: a.className, field: a.field, method: a.method }) },
  { name: 'trace_function', description: 'Trace calls to a native symbol (args+tid+ts) while the target’s detection workload runs', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S, hookModule: S, class: S }, required: ['symbol', 'hookModule'] }, handler: (a) => agentCmd(a.session, 'trace_run', { symLib: a.symLib ?? 'libc.so', symbol: a.symbol, hookModule: a.hookModule, className: a.class ?? SANDBOX.detect }, 20_000) },
  { name: 'dex_method_code', description: 'Extract a method’s runtime code_item bytecode from a dex (b64|sha)', inputSchema: { type: 'object', properties: { b64: S, sha: S, class: S, method: S }, required: ['class'] }, handler: async (a) => { const buf = await dumpBuf(a); return extractMethodCode(buf, parseDex(buf), String(a.class), a.method); } },
  { name: 'dex_repair', description: 'Repair a dumped dex header (file_size/checksum/signature)', inputSchema: { type: 'object', properties: { b64: S, sha: S } }, handler: async (a) => { const buf = await dumpBuf(a); const info = repairDexHeader(buf); return { ...info, repairedB64: buf.toString('base64') }; } },
  // ---- axis 1: one-glance crypto algorithm identification ----
  { name: 'crypto_identify', description: '一眼看清目标 App 用了哪些加密算法/密钥/IV — summarize all captured crypto (algorithm, key, iv, plaintext) into a plain-language report for non-experts', inputSchema: { type: 'object', properties: {} }, handler: async () => cryptoIdentify() },
  { name: 'live_captures', description: 'List the live captures streamed by the persistent hooks — crypto / net(TLS) / file / system, filterable by category (algorithm+op+preview, newest last)', inputSchema: { type: 'object', properties: { limit: N, category: S } }, handler: async (a) => { const cat = a.category ? String(a.category) : ''; const list = cat ? captures.filter(c => c.category === cat) : captures; return { total: list.length, on: captureTimers.size > 0, captures: list.slice(-(Number(a.limit) || 50)).map(c => ({ id: c.id, source: c.source, category: c.category, algo: c.algo, op: c.op, inl: c.inl, tid: c.tid, ts: c.ts, preview: c.preview })) }; } },
  { name: 'capture_detail', description: 'Full detail of one capture by id: algorithm, key(hex), iv(hex), plaintext(utf8+hex), ciphertext(hex)', inputSchema: { type: 'object', properties: { id: N }, required: ['id'] }, handler: async (a) => { const c = captures.find(x => x.id === Number(a.id)); if (!c) throw new Error('not found'); const text = Buffer.from(c.hex, 'hex').toString('utf8'); return { ...c, text }; } },
  // ---- axis 2: one-click unpack (no AOSP flashing needed) ----
  { name: 'dex_coverage', description: '方法恢复率报告 — per-method state (native/abstract/present/extracted) + recovery rate over a dumped dex', inputSchema: { type: 'object', properties: { b64: S, sha: S }, required: [] }, handler: async (a) => { const buf = await dumpBuf(a); return analyzeCoverage(buf, parseDex(buf)); } },
  { name: 'dump_all_dex', description: '一键 dump 当前目标进程所有已加载 DEX：ART DexFile 枚举 + 逐个 dump + SHA-256 去重', inputSchema: { type: 'object', properties: { session: S } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return dumpAllDex(sid); } },
  { name: 'dex_recover', description: 'Recover extracted CodeItems from a restored snapshot into a base dex + rebuild (baseSha/baseB64 + restoredSha/restoredB64)', inputSchema: { type: 'object', properties: { baseB64: S, baseSha: S, restoredB64: S, restoredSha: S } }, handler: async (a) => { const base = await dumpBuf({ b64: a.baseB64, sha: a.baseSha }); const restored = await dumpBuf({ b64: a.restoredB64, sha: a.restoredSha }); const pd = parseDex(base); const { captures: caps, report } = recoverFromSnapshots(base, restored, pd); const rb = rebuildStandardDex(base, caps); const outSha = createHash('sha256').update(rb.dex).digest('hex'); const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`); if (!existsSync(path)) writeFileSync(path, rb.dex); const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' }; dumps.set(outSha, meta); return { ...report, injected: rb.injected, sha256: outSha }; } },
  // ---- axis 3: everything the AI needs to drive a reversing session ----
  { name: 'trigger', description: 'Actively load a class (level 1) and invoke a safe static no-arg method (level 3) to force code paths — a trigger source for unpacking', inputSchema: { type: 'object', properties: { session: S, class: S, method: S, level: N }, required: ['class'] }, handler: (a) => agentCmd(a.session, 'trigger', { className: a.class, method: a.method ?? '', level: Number(a.level ?? 1) }, 20_000) },
  { name: 'qbdi_trace', description: 'QBDI instruction-level dynamic trace of a native function (per-instruction disassembly + return value)', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S }, required: ['symbol'] }, handler: (a) => agentCmd(a.session, 'qbdi_trace', { symLib: a.symLib ?? 'libadhdetect.so', symbol: a.symbol }, 30_000) },
  { name: 'net_correlate', description: 'Network↔crypto correlation: pair plaintext with the TLS request carrying its ciphertext (same thread + time window)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'load_library', description: '把任意 .so 加载进目标进程（如 frida-gadget，随后 gadget 会按 script 模式自动跑你的 frida 脚本）。可选 symbol 探测。dlopen from inside the target.', inputSchema: { type: 'object', properties: { session: S, path: S, symbol: S }, required: ['path'] }, handler: (a) => agentCmd(a.session, 'load_so', { path: a.path, symbol: a.symbol ?? '' }, 30_000) },
];

MCP_TOOLS.push(
  { name: 'automation_status', description: 'Read-only phone automation status: user toggle, bridge connection, connected device capabilities and package allowlist. This tool never enables automation.', inputSchema: { type: 'object', properties: {} }, handler: async () => ({ enabled: settings.automation.enabled, packages: settings.automation.packages, bridge: automation.status() }) },
  { name: 'phone_observe', description: 'Observe the active phone screen. Prefer the AccessibilityService node tree; when it is empty or non-semantic, fall back to a screenshot that the AI can inspect. Returns snapshotId plus nodes or an image.', inputSchema: { type: 'object', properties: { mode: { type: 'string', enum: ['auto', 'tree', 'visual'] }, includeScreenshot: { type: 'boolean' }, maxNodes: N, package: S } }, raw: true, handler: async (a) => observePhone(a) },
  { name: 'phone_act', description: 'Act on the active phone screen. Prefer snapshotId+ref from phone_observe; use normalized x/y coordinates only when no usable node exists. Supports tap, long_press, swipe, scroll, set_text and global back/home/recents.', inputSchema: { type: 'object', properties: { snapshotId: S, action: { type: 'string', enum: ['tap', 'long_press', 'swipe', 'scroll', 'set_text', 'global'] }, ref: S, x: N, y: N, x2: N, y2: N, coordinateSpace: { type: 'string', enum: ['normalized', 'pixel'] }, text: S, key: { type: 'string', enum: ['back', 'home', 'recents'] }, direction: { type: 'string', enum: ['forward', 'backward'] }, durationMs: N, observeAfter: { type: 'boolean' }, package: S }, required: ['action'] }, raw: true, handler: async (a) => actPhone(a) },
);

async function observePhone(args: any) {
  assertAutomationReady();
  const result = await automation.cmd('observe', normalizeObserveArgs(args), 25_000);
  return observationContent(result);
}

async function actPhone(args: any) {
  assertAutomationReady();
  const result = await automation.cmd('act', normalizeActArgs(args), 25_000);
  const parts: any[] = [{ type: 'text', text: JSON.stringify(result, null, 2) }];
  if (args.observeAfter) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    parts.push(...observationContent(await automation.cmd('observe', normalizeObserveArgs(args), 25_000)).content);
  }
  return { content: parts };
}

function assertAutomationReady() {
  if (!settings.automation.enabled) throw new Error('automation_disabled: enable it in ADH settings on the host');
  if (!settings.automation.packages.length) throw new Error('automation_package_allowlist_empty: add at least one package in ADH settings');
}

function normalizeObserveArgs(args: any) {
  return {
    mode: args.mode ?? 'auto',
    includeScreenshot: args.includeScreenshot ?? 'auto',
    maxNodes: args.maxNodes ?? settings.automation.maxNodes,
    screenshot: settings.automation.screenshot,
    screenshotMaxDimension: settings.automation.screenshotMaxDimension,
    allowedPackages: settings.automation.packages,
    package: args.package,
  };
}

function normalizeActArgs(args: any) {
  return {
    snapshotId: args.snapshotId,
    action: args.action,
    ref: args.ref,
    x: args.x,
    y: args.y,
    x2: args.x2,
    y2: args.y2,
    coordinateSpace: args.coordinateSpace ?? 'normalized',
    text: args.text,
    key: args.key,
    direction: args.direction,
    durationMs: args.durationMs,
    allowedPackages: settings.automation.packages,
    package: args.package,
  };
}

function observationContent(result: any) {
  const screenshot = result?.screenshot;
  const meta = { ...(result ?? {}) };
  if (screenshot) {
    const { base64, ...rest } = screenshot;
    meta.screenshot = rest;
  }
  const content: any[] = [{ type: 'text', text: JSON.stringify(meta, null, 2) }];
  if (screenshot?.base64) content.push({ type: 'image', data: screenshot.base64, mimeType: screenshot.mimeType ?? 'image/jpeg' });
  return { content };
}

function visibleMcpTools() {
  return MCP_TOOLS.filter((tool) => !tool.name.startsWith('phone_') || settings.automation.enabled);
}
export const MCP_MAP = new Map(MCP_TOOLS.map(t => [t.name, t]));

export async function handleMcp(reqBody: string, res: ServerResponse, opts?: { package?: string }) {
  let msg: any;
  try { msg = JSON.parse(reqBody); } catch { res.writeHead(400).end('bad json'); return; }
  const pin = opts?.package;
  const reply = (result?: unknown, error?: unknown) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...(error ? { error } : { result }) });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(body);
  };
  if (msg.method === 'initialize') return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'adhd', version: '0.1.0' } });
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') { res.writeHead(202).end(); return; }
  if (msg.method === 'ping') return reply({});
  if (msg.method === 'tools/list') return reply({ tools: visibleMcpTools().map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
  if (msg.method === 'tools/call') {
    const name = msg.params?.name;
    const t = MCP_MAP.get(name);
    if (!t) return reply(undefined, { code: -32602, message: `unknown tool: ${name}` });
    if (name.startsWith('phone_') && !settings.automation.enabled) return reply(undefined, { code: -32000, message: 'automation_disabled: user has not enabled phone automation' });
    let args = { ...(msg.params?.arguments ?? {}) };
    if (pin && name === 'process_list') {
      const out = [...sessions.values()].filter(s => s.package === pin);
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    }
    if (pin && args.session == null) {
      const sid = sessionForPackage(pin);
      if (sid) args.session = sid;
    }
    try {
      const out = await t.handler(args);
      if (t.raw) return reply(out);
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    } catch (e) { return reply({ content: [{ type: 'text', text: 'error: ' + (e as Error).message }], isError: true }); }
  }
  return reply(undefined, { code: -32601, message: `method not found: ${msg.method}` });
}

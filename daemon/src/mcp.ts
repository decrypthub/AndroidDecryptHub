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
import { agentWaitSightings, findAgentWaitMatch, hasAgentWaitFilters } from './agent_events.ts';
import { implicitSelectorFor, selectorFrom } from './phone_selectors.ts';
import { PhoneSkillStore, resolveSkillInputs } from './phone_skills.ts';
import { resolveTemplates } from './phone_templates.ts';
import { renderScreenText } from './phone_text.ts';
import { blockedPackageFromError, openOutcomeHint } from './phone_foreground.ts';
import { sessions, dumps, captures, captureTimers, events, agentCursor, DATA_DIR, SANDBOX, settings, CAPTURES, cryptoIdentify } from './state.ts';
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

const SEL = {
  text: S,
  textContains: S,
  resourceId: S,
  contentDescription: S,
  contentDescriptionContains: S,
  clickable: { type: 'boolean' },
  editable: { type: 'boolean' },
  scrollable: { type: 'boolean' },
  index: N,
};

MCP_TOOLS.push(
  { name: 'automation_status', description: 'Read-only phone automation status: user toggle, bridge connection, connected device capabilities and package allowlist. This tool never enables automation.', inputSchema: { type: 'object', properties: {} }, handler: async () => ({ enabled: settings.automation.enabled, packages: settings.automation.packages, bridge: automation.status() }) },
  { name: 'phone_observe', description: 'Observe the active phone screen. Prefer the AccessibilityService node tree; when it is empty or non-semantic, fall back to a screenshot that the AI can inspect. Returns snapshotId plus nodes or an image. mode=text renders the same tree as terse plain-text lines (refs stay usable) to save context.', inputSchema: { type: 'object', properties: { mode: { type: 'string', enum: ['auto', 'tree', 'visual', 'text'] }, includeScreenshot: { type: 'boolean' }, maxNodes: N, maxDepth: N, interactiveOnly: { type: 'boolean' }, package: S } }, raw: true, handler: async (a) => observePhone(a) },
  { name: 'phone_find', description: 'Find compact, actionable nodes without transferring the whole tree. Supports text/resourceId/contentDescription and interaction flags; returns refs valid for snapshotId.', inputSchema: { type: 'object', properties: { ...SEL, limit: N, maxNodes: N, interactiveOnly: { type: 'boolean' }, package: S } }, handler: async (a) => findPhone(a) },
  { name: 'phone_wait', description: 'Wait until a screen state / selector matches or the injected agent reports a signal. Agent filters: agentEvent (exact event type), agentEventContains (substring of the event JSON), captureCategory (crypto/net/file/system), captureContains (substring of the decoded capture text + metadata). Same-kind filters are ANDed; the two kinds race and whichever fires first wins. Race-free pattern: take the cursor from the preceding observe/act response and pass it as afterCaptureId / afterEventSeq; lookbackMs is the coarse alternative (bounded 0..300000). On an agent-signal timeout the reply carries saw (recent captures/events from the window plus totals) and the live cursor, so the filter can be retargeted.', inputSchema: { type: 'object', properties: { ...SEL, activePackage: S, activityContains: S, gone: { type: 'boolean' }, agentEvent: S, agentEventContains: S, captureCategory: { type: 'string', enum: ['crypto', 'net', 'file', 'system'] }, captureContains: S, afterEventSeq: N, afterCaptureId: N, lookbackMs: N, timeoutMs: N, intervalMs: N, scroll: { type: 'boolean' }, direction: { type: 'string', enum: ['forward', 'backward'] }, maxScrolls: N, maxNodes: N, interactiveOnly: { type: 'boolean' }, package: S } }, handler: async (a) => waitPhone(a) },
  { name: 'phone_act', description: 'Act on the active phone screen. Prefer a selector or snapshotId+ref from phone_observe; use normalized coordinates only as the visual fallback. Supports tap, long_press, swipe, scroll, set_text and global back/home/recents/notifications/quick_settings/power/lock/screenshot. For set_text the text argument is the payload to write, not a filter (target the field with ref, resourceId, editable or selector); the value can be read back with phone_find.', inputSchema: { type: 'object', properties: { ...SEL, snapshotId: S, action: { type: 'string', enum: ['tap', 'long_press', 'swipe', 'scroll', 'set_text', 'global'] }, ref: S, x: N, y: N, x2: N, y2: N, coordinateSpace: { type: 'string', enum: ['normalized', 'pixel'] }, text: S, key: { type: 'string', enum: ['back', 'home', 'recents', 'notifications', 'quick_settings', 'power', 'lock', 'screenshot'] }, direction: { type: 'string', enum: ['forward', 'backward'] }, durationMs: N, observeAfter: { type: 'boolean' }, package: S }, required: ['action'] }, raw: true, handler: async (a) => actPhone(a) },
  { name: 'phone_app', description: 'Open, stop or restart an allowlisted app by package name. open verifies that the app really reached the foreground and reports verified/foreground/warning when an OEM dialog swallowed the launch (with a hint on how to unblock). Open uses the root Device Daemon when protocol v6+ is available, with a compatibility fallback for older daemons; stop/restart delegate to the same authenticated daemon.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['open', 'stop', 'restart'] }, package: S }, required: ['action', 'package'] }, handler: async (a) => appPhone(a) },
  { name: 'phone_device', description: 'Read or control device power state: status, wake, unlock a non-secure keyguard, or lock the screen. Secure credentials are never bypassed.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['status', 'wake', 'unlock', 'lock'] } }, required: ['action'] }, handler: async (a) => devicePhone(a) },
  { name: 'phone_skill', description: 'Save, list, run or delete named phone recipes (skills). A skill is a validated, bounded list of phone_task steps kept on the host, so a flow the AI worked out once replays in one call. Recipes can take params (declared on save) that steps read as {{input.<name>}} and runs pass as inputs; defaults fill the optional ones. Skills run through the same primitives, allowlist and retry semantics as phone_task; they cannot nest skills or reach a shell.', inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['list', 'save', 'run', 'delete'] }, name: S, description: S, overwrite: { type: 'boolean' }, stopOnError: { type: 'boolean' }, steps: { type: 'array', minItems: 1, maxItems: 30, items: { type: 'object' } }, params: { type: 'array', maxItems: 10, items: { type: 'string' } }, defaults: { type: 'object' }, inputs: { type: 'object' } }, required: ['action'] }, handler: async (a) => skillPhone(a) },
  { name: 'phone_task', description: 'Run a bounded sequence of phone primitives in one MCP call. Steps may observe, find, wait (UI state or agent signal), act, control an app, or control device power; each step supports retries and structured failure output. Steps with an id can be referenced by later steps as {{id.path}} (e.g. take the ref and snapshotId a find discovered straight into act), which avoids ref-expiry between separate calls.', inputSchema: { type: 'object', properties: { stopOnError: { type: 'boolean' }, steps: { type: 'array', minItems: 1, maxItems: 30, items: { type: 'object', properties: { id: S, type: { type: 'string', enum: ['observe', 'find', 'wait', 'act', 'app', 'device'] }, args: { type: 'object' }, retries: N, retryDelayMs: N }, required: ['type'] } } }, required: ['steps'] }, handler: async (a) => taskPhone(a) },
);


function matchesSelector(node: any, selector: any): boolean {
  if (selector.text != null && node.text !== selector.text) return false;
  if (selector.textContains != null && !String(node.text ?? '').includes(String(selector.textContains))) return false;
  if (selector.resourceId != null && node.resourceId !== selector.resourceId) return false;
  if (selector.contentDescription != null && node.contentDescription !== selector.contentDescription) return false;
  if (selector.contentDescriptionContains != null && !String(node.contentDescription ?? '').includes(String(selector.contentDescriptionContains))) return false;
  if (selector.clickable != null && !!node.clickable !== !!selector.clickable) return false;
  if (selector.editable != null && !!node.editable !== !!selector.editable) return false;
  if (selector.scrollable != null && !!node.scrollable !== !!selector.scrollable) return false;
  return true;
}

function findNodes(nodes: any[], selector: any, limit = 20): any[] {
  const matches = (nodes ?? []).filter((node) => matchesSelector(node, selector));
  const index = Number.isFinite(selector.index) ? Math.max(0, Math.floor(selector.index)) : null;
  const selected = index == null ? matches : matches.slice(index, index + 1);
  return selected.slice(0, Math.max(1, Math.min(200, Number(limit) || 20)));
}

function compactNode(node: any) {
  const copy: any = {};
  for (const key of ['ref', 'text', 'contentDescription', 'resourceId', 'className', 'bounds', 'actions', 'clickable', 'editable', 'scrollable', 'selected', 'checked', 'enabled']) {
    if (node?.[key] !== undefined) copy[key] = node[key];
  }
  return copy;
}

async function observeTree(args: any) {
  return await automation.cmd('observe', normalizeObserveArgs({ ...args, mode: 'tree', includeScreenshot: false }), 25_000);
}

async function findPhone(args: any) {
  assertAutomationReady();
  const result = await observeTree(args);
  const selector = selectorFrom(args);
  const matches = findNodes(result.nodes ?? [], selector, args.limit ?? 20);
  return {
    activePackage: result.activePackage,
    screen: result.screen,
    snapshotId: result.snapshotId,
    truncated: result.truncated,
    count: matches.length,
    cursor: agentCursor(),
    nodes: matches.map(compactNode),
  };
}

async function waitPhone(args: any) {
  assertAutomationReady();
  const selector = selectorFrom(args);
  const hasState = args.activePackage != null || args.activityContains != null;
  const needsUi = Object.keys(selector).length > 0 || hasState;
  const wantsAgent = hasAgentWaitFilters(args);
  if (!needsUi && !wantsAgent)
    throw new Error('phone_wait requires a selector, activePackage, activityContains or an agent filter (agentEvent/agentEventContains/captureCategory/captureContains)');
  const timeoutMs = Math.max(500, Math.min(60_000, Number(args.timeoutMs ?? 8_000)));
  const intervalMs = Math.max(100, Math.min(2_000, Number(args.intervalMs ?? 350)));
  const maxScrolls = Math.max(0, Math.min(50, Number(args.maxScrolls ?? 10)));
  const startedAt = Date.now();
  const lookbackMs = Math.max(0, Math.min(300_000, Number(args.lookbackMs ?? 0)));
  const agentWindow = { since: startedAt - lookbackMs, afterEventSeq: args.afterEventSeq, afterCaptureId: args.afterCaptureId };
  let scrolls = 0;
  let last: any = null;
  for (;;) {
    // Agent signals need no node tree, so a pure signal wait never depends on the
    // AccessibilityService, and a mixed wait takes whichever condition fires first.
    if (wantsAgent) {
      const hit = findAgentWaitMatch(args, agentWindow, events, captures);
      if (hit) {
        return {
          matched: true,
          kind: hit.kind,
          item: hit.item,
          elapsedMs: Date.now() - startedAt,
          activePackage: last?.activePackage,
          activity: last?.activity,
          snapshotId: last?.snapshotId,
          scrolls,
        };
      }
    }
    if (needsUi) {
      const result = await observeTree(args);
      last = result;
      const stateMatches =
        (args.activePackage == null || result.activePackage === args.activePackage) &&
        (args.activityContains == null || String(result.activity ?? '').includes(String(args.activityContains)));
      const matches = findNodes(result.nodes ?? [], selector, 1);
      const found = stateMatches && (Object.keys(selector).length === 0 || matches.length > 0);
      if (args.gone ? !found : found) {
        return {
          matched: true,
          gone: !!args.gone,
          elapsedMs: Date.now() - startedAt,
          activePackage: result.activePackage,
          activity: result.activity,
          snapshotId: result.snapshotId,
          scrolls,
          node: found ? compactNode(matches[0]) : null,
        };
      }
    }
    if (Date.now() - startedAt >= timeoutMs) {
      return {
        matched: false,
        timedOut: true,
        elapsedMs: Date.now() - startedAt,
        activePackage: last?.activePackage,
        activity: last?.activity,
        snapshotId: last?.snapshotId,
        truncated: last?.truncated,
        scrolls,
        // On an agent-signal timeout, hand back what did arrive in the window (plus the live
        // cursor) so the AI can retarget the filter instead of guessing blind.
        ...(wantsAgent ? { cursor: agentCursor(), saw: agentWaitSightings(agentWindow, events, captures) } : {}),
      };
    }
    if (needsUi && args.scroll && !args.gone && scrolls < maxScrolls) {
      const scrollable = (last?.nodes ?? []).find((node: any) => node.actions?.includes('scroll_forward'));
      if (scrollable) {
        await automation.cmd('act', {
          snapshotId: last.snapshotId,
          action: 'scroll',
          ref: scrollable.ref,
          direction: args.direction ?? 'forward',
          allowedPackages: settings.automation.packages,
          package: args.package,
        }, 25_000);
        scrolls++;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

const phoneSkills = new PhoneSkillStore(join(DATA_DIR, 'skills.json'));

async function skillPhone(args: any) {
  const action = String(args.action ?? '');
  if (action === 'list') return { skills: phoneSkills.list() };
  if (action === 'delete') {
    const name = String(args.name ?? '');
    if (!name) throw new Error('phone_skill delete requires a name');
    return { name, deleted: phoneSkills.remove(name) };
  }
  if (action === 'save') {
    const skill = phoneSkills.save(args.name, args.description, args.steps, args.overwrite === true, args.params, args.defaults);
    return { name: skill.name, description: skill.description ?? '', steps: skill.steps.length, params: skill.params ?? [], saved: true };
  }
  if (action === 'run') {
    const name = String(args.name ?? '');
    const skill = phoneSkills.get(name);
    if (!skill) throw new Error(`skill_not_found: '${name}' is not saved on this host`);
    const inputs = resolveSkillInputs(skill, args.inputs);
    const result = await taskPhone({ ...args, steps: skill.steps, inputs });
    phoneSkills.noteRun(name);
    return { name, inputs, ...result };
  }
  throw new Error('phone_skill requires action: list | save | run | delete');
}

async function taskPhone(args: any) {
  assertAutomationReady();
  const steps = Array.isArray(args.steps) ? args.steps : [];
  if (!steps.length) throw new Error('phone_task requires at least one step');
  if (steps.length > 30) throw new Error('phone_task supports at most 30 steps');
  const stopOnError = args.stopOnError !== false;
  const results: any[] = [];
  const outputs: Record<string, any> = {};   // step id -> result, plus the reserved `input` namespace
  if (args.inputs && typeof args.inputs === 'object' && !Array.isArray(args.inputs)) outputs.input = args.inputs;
  for (let index = 0; index < steps.length; index++) {
    const step = steps[index] ?? {};
    const type = String(step.type ?? '');
    const stepArgs = step.args && typeof step.args === 'object' ? step.args : {};
    const retries = Math.max(0, Math.min(3, Number(step.retries ?? 0)));
    const retryDelayMs = Math.max(50, Math.min(3_000, Number(step.retryDelayMs ?? 300)));
    let attempt = 0;
    for (;;) {
      try {
        const value = await runTaskStep(type, resolveTemplates(stepArgs, outputs));
        results.push({ index, id: step.id, type, ok: true, result: value });
        if (step.id) outputs[String(step.id)] = value;
        break;
      } catch (error) {
        const message = (error as Error).message || String(error);
        if (attempt >= retries) {
          results.push({ index, id: step.id, type, ok: false, error: message });
          if (stopOnError) return { ok: false, failedStep: index, steps: results };
          break;
        }
        attempt++;
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
  }
  return { ok: results.every((step) => step.ok), steps: results };
}

async function runTaskStep(type: string, args: any): Promise<any> {
  switch (type) {
    case 'observe':
      return contentToValue(await observePhone(args));
    case 'find':
      return await findPhone(args);
    case 'wait': {
      const value = await waitPhone(args);
      // A timed-out wait must fail the step: otherwise the task continues as if the expected
      // UI state / agent signal had arrived. Retries and stopOnError then apply as usual.
      if (value?.timedOut) throw new Error('wait_timeout ' + JSON.stringify({ elapsedMs: value.elapsedMs, activePackage: value.activePackage, activity: value.activity, scrolls: value.scrolls }));
      return value;
    }
    case 'act':
      return contentToValue(await actPhone(args));
    case 'app':
      return await appPhone(args);
    case 'device':
      return await devicePhone(args);
    default:
      throw new Error('unsupported phone_task step: ' + type);
  }
}

function contentToValue(result: any): any {
  const text = result?.content?.find((item: any) => item.type === 'text')?.text;
  if (text == null) return result;
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

async function devicePhone(args: any) {
  assertAutomationReady();
  return await automation.cmd('device', { action: args.action }, 20_000);
}

async function appPhone(args: any) {
  assertAutomationReady();
  const packageName = String(args.package ?? '').trim();
  if (!packageName || !settings.automation.packages.includes(packageName)) {
    throw new Error(`blocked_package: ${packageName || '(empty)'} is not in the automation allowlist`);
  }
  const result = await automation.cmd('app', { action: args.action, package: packageName, allowedPackages: settings.automation.packages }, 25_000);
  if (args.action !== 'open' && args.action !== 'restart') return result;   // stop leaves the app, nothing to verify
  // An OEM dialog can swallow the launch while the call itself succeeds, so confirm the app
  // really reached the foreground and say what is in front when it did not.
  const deadline = Date.now() + 5_000;
  let foreground: string | null = null;
  let blocked = false;
  for (;;) {
    try {
      const probe = await automation.cmd('observe', normalizeObserveArgs({ mode: 'tree', includeScreenshot: false, maxNodes: 1 }), 8_000);
      foreground = probe?.activePackage ?? null;
      blocked = false;
    } catch (error) {
      const packageFromError = blockedPackageFromError((error as Error)?.message);
      foreground = packageFromError;
      blocked = !!packageFromError;
    }
    if (foreground === packageName) return { ...result, verified: true, foreground };
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  const hint = openOutcomeHint(packageName, foreground, blocked);
  return { ...result, verified: false, foreground, warning: hint };
}

async function observePhone(args: any) {
  assertAutomationReady();
  if (args.mode === 'text') {
    // Read the tree, then render it as terse lines on the host — the AI gets refs without the
    // verbose per-node JSON, which matters because every observe costs context.
    const tree = await automation.cmd('observe', normalizeObserveArgs({ ...args, mode: 'tree', includeScreenshot: false }), 25_000);
    return { content: [{ type: 'text', text: renderScreenText(tree, { maxNodes: args.maxNodes }) }] };
  }
  const result = await automation.cmd('observe', normalizeObserveArgs(args), 25_000);
  return observationContent(result);
}

async function actPhone(args: any) {
  assertAutomationReady();
  const cursorBefore = agentCursor();   // taken before dispatch: wait on it to catch this action's signals
  let effective = { ...args };
  // set_text carries its payload in `text`. Reading that same argument as a selector would demand a
  // node whose CURRENT text already equals the value we are about to write, so the field could
  // never be resolved. Exclude it from the implicit selector; selector:{text:...} still works.
  const implicitSelector = implicitSelectorFor(effective.action, effective);
  if (!effective.ref && Object.keys(implicitSelector).length) {
    // Bounded retry: the node tree churns while animations/list items settle, and a single miss
    // used to surface as a spurious selector_not_found. 3 attempts ≈ 500ms worst case.
    let match: any = null;
    let observed: any = null;
    for (let attempt = 0; attempt < 3 && !match; attempt++) {
      if (attempt) await new Promise((resolve) => setTimeout(resolve, 250));
      observed = await observeTree(effective);
      match = findNodes(observed.nodes ?? [], implicitSelector, 1)[0];
    }
    if (!match) throw new Error('selector_not_found: no node matched the selector in the current screen');
    effective = { ...effective, snapshotId: observed.snapshotId, ref: match.ref };
  }
  const result = await automation.cmd('act', normalizeActArgs(effective), 25_000);
  const parts: any[] = [{ type: 'text', text: JSON.stringify({ ...result, cursorBefore }, null, 2) }];
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
    maxDepth: args.maxDepth ?? 50,
    interactiveOnly: args.interactiveOnly ?? false,
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
  const meta = { ...(result ?? {}), cursor: agentCursor() };
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

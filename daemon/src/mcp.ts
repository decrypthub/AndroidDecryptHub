// mcp.ts — MCP Server (Streamable HTTP / JSON-RPC).
// Exposes the workbench Service Layer as MCP tools for AI clients. Shares the same
// logic as the REST API (no duplicate business logic) — handlers delegate to service.ts
// primitives (agentCmd/dumpBuf/dumpRegion/runUnpackSession/...) + state.ts (captures/...).
// Adding a tool = add one entry to MCP_TOOLS below.
import type { ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeSo, cryptoConstScan, svcScan, disasmSo } from './analysis.ts';
import { parseDex, cryptoScan, searchDex, invokeXref, extractMethodCode, analyzeCoverage, rebuildStandardDex, recoverFromSnapshots } from './dex.ts';
import { agentCmd, dumpBuf, dumpBufPath, dumpRegion, pickSid, runUnpackSession, repairDexHeader } from './service.ts';
import { sessions, dumps, captures, captureTimers, SANDBOX, settings, CAPTURES, cryptoIdentify } from './state.ts';
import type { DumpMeta } from './state.ts';

const S = { type: 'string' }, N = { type: 'number' };
export const MCP_TOOLS: { name: string; description: string; inputSchema: any; handler: (a: any) => Promise<any> }[] = [
  { name: 'process_list', description: 'List connected target agent sessions', inputSchema: { type: 'object', properties: {} }, handler: async () => [...sessions.values()] },
  { name: 'dumps_list', description: 'List captured dump artifacts (dex/so/region)', inputSchema: { type: 'object', properties: {} }, handler: async () => [...dumps.values()] },
  { name: 'compat_probe', description: 'Self-assess agent env: tracer/seccomp/hook-backend availability', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'compat_probe') },
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
  { name: 'unpack_run', description: '一键脱壳（无需刷 AOSP）— full unpack session: T0 snapshot → coverage → active trigger → T1 snapshot → recover+rebuild. Set triggerAllPrefix (e.g. "com.target.") to aggressively load ALL of the app\'s classes so a refill-type shell restores every method. Returns per-dex before/after recovery + rebuilt dex sha', inputSchema: { type: 'object', properties: { session: S, triggerAllPrefix: S, triggerClasses: { type: 'array', items: S }, triggerMethod: S, level: N, maxClasses: N } }, handler: async (a) => { const sid = pickSid(a.session); if (!sid) throw new Error('no session'); return runUnpackSession(sid, a); } },
  { name: 'dex_recover', description: 'Recover extracted CodeItems from a restored snapshot into a base dex + rebuild (baseSha/baseB64 + restoredSha/restoredB64)', inputSchema: { type: 'object', properties: { baseB64: S, baseSha: S, restoredB64: S, restoredSha: S } }, handler: async (a) => { const base = await dumpBuf({ b64: a.baseB64, sha: a.baseSha }); const restored = await dumpBuf({ b64: a.restoredB64, sha: a.restoredSha }); const pd = parseDex(base); const { captures: caps, report } = recoverFromSnapshots(base, restored, pd); const rb = rebuildStandardDex(base, caps); const outSha = createHash('sha256').update(rb.dex).digest('hex'); const path = join(CAPTURES, `${outSha.slice(0, 16)}.dex`); if (!existsSync(path)) writeFileSync(path, rb.dex); const meta: DumpMeta = { sha256: outSha, size: rb.dex.length, source: 'dex-recover', addr: '0', tag: 'recovered', sessionId: '', package: '', capturedAt: Date.now(), path, kind: 'dex' }; dumps.set(outSha, meta); return { ...report, injected: rb.injected, sha256: outSha }; } },
  // ---- axis 3: everything the AI needs to drive a reversing session ----
  { name: 'trigger', description: 'Actively load a class (level 1) and invoke a safe static no-arg method (level 3) to force code paths — a trigger source for unpacking', inputSchema: { type: 'object', properties: { session: S, class: S, method: S, level: N }, required: ['class'] }, handler: (a) => agentCmd(a.session, 'trigger', { className: a.class, method: a.method ?? '', level: Number(a.level ?? 1) }, 20_000) },
  { name: 'qbdi_trace', description: 'QBDI instruction-level dynamic trace of a native function (per-instruction disassembly + return value)', inputSchema: { type: 'object', properties: { session: S, symLib: S, symbol: S }, required: ['symbol'] }, handler: (a) => agentCmd(a.session, 'qbdi_trace', { symLib: a.symLib ?? 'libidhdetect.so', symbol: a.symbol }, 30_000) },
  { name: 'net_correlate', description: 'Network↔crypto correlation: pair plaintext with the TLS request carrying its ciphertext (same thread + time window)', inputSchema: { type: 'object', properties: { session: S } }, handler: (a) => agentCmd(a.session, 'flow_watch', { className: a.class ?? SANDBOX.flow }, 25_000) },
  { name: 'load_library', description: '把任意 .so 加载进目标进程（如 frida-gadget，随后 gadget 会按 script 模式自动跑你的 frida 脚本）。可选 symbol 探测。dlopen from inside the target.', inputSchema: { type: 'object', properties: { session: S, path: S, symbol: S }, required: ['path'] }, handler: (a) => agentCmd(a.session, 'load_so', { path: a.path, symbol: a.symbol ?? '' }, 30_000) },
];
export const MCP_MAP = new Map(MCP_TOOLS.map(t => [t.name, t]));

export async function handleMcp(reqBody: string, res: ServerResponse) {
  let msg: any;
  try { msg = JSON.parse(reqBody); } catch { res.writeHead(400).end('bad json'); return; }
  const reply = (result?: unknown, error?: unknown) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: msg.id, ...(error ? { error } : { result }) });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(body);
  };
  if (msg.method === 'initialize') return reply({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'adhd', version: '0.1.0' } });
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') { res.writeHead(202).end(); return; }
  if (msg.method === 'ping') return reply({});
  if (msg.method === 'tools/list') return reply({ tools: MCP_TOOLS.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })) });
  if (msg.method === 'tools/call') {
    const t = MCP_MAP.get(msg.params?.name);
    if (!t) return reply(undefined, { code: -32602, message: `unknown tool: ${msg.params?.name}` });
    try {
      const out = await t.handler(msg.params?.arguments ?? {});
      return reply({ content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
    } catch (e) { return reply({ content: [{ type: 'text', text: 'error: ' + (e as Error).message }], isError: true }); }
  }
  return reply(undefined, { code: -32601, message: `method not found: ${msg.method}` });
}

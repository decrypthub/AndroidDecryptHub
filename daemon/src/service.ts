// service.ts — ADH Daemon service layer: agent-command transport + dump engine + capture ops.
// Imported by mcp.ts (MCP handlers) and index.ts (REST routes + agent TCP + boot).
// Imports ONLY from state.ts (+ dex.ts / so_select.ts pure layers + dex_index.ts for artifact
// retention + node builtins) — no circular refs.
import { readFile } from 'node:fs/promises';
import { writeFileSync, existsSync, readFileSync, mkdirSync, copyFileSync, readdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import {
  frameJson, agentSockets, pending, nextCmdId, sessions, dumps, log, rememberDump,
  captureTimers, captureModules, settings, recentJavaIn, captures,
  pushCapture, broadcast, hexToPreview, previewForCapture, classify, categoryOf, capStats, CAPTURES,
  pruneArtifacts, DATA_DIR,
} from './state.ts';
import { shouldAutoArmPackage, scopedApps } from './scope_list.ts';
import type { AgentSession, DumpMeta, MapsRegion, Capture } from './state.ts';
// dex_index.ts imports state.ts, not this file, so this edge cannot form a cycle; it is here so
// artifact retention can drop the index row of a dex it deletes.
import { deleteDexDocument, ensureDexIndex } from './dex_index.ts';
import { cryptoView, javaHook } from './crypto_view.ts';
import { classifyDexArtifact, parseDex } from './dex.ts';
import { appOwnedSoModules } from './so_select.ts';
import { contiguousReadable, packageSoDirs, preferMainProcess, processFolderLabel } from './dump_inventory.ts';
import { coldStartPackage, waitForFreshSessions } from './app_launch.ts';
import { PACKAGE_FILE_READ_CAP, pullPackageFile } from './sandbox_fs.ts';
import { buildStoredZip } from './zip_store.ts';

// ---- agent command transport ---------------------------------------------
// Issue a command to an agent and await its cmdResult (10s default timeout).
export function sendCmd(sessionId: string, op: string, args: Record<string, unknown> = {}, timeoutMs = 10_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const sock = agentSockets.get(sessionId);
    if (!sock || sock.destroyed) return reject(new Error('agent not connected'));
    const id = nextCmdId();
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('command timeout')); }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    sock.write(frameJson({ ...args, t: 'cmd', id, op }));
  });
}

export const pickSid = (sid?: string) => sid ?? [...sessions.values()].filter(s => s.online).pop()?.sessionId;
export const sessionForPackage = (pkg: string) =>
  [...sessions.values()].filter(s => s.online && s.package === pkg).pop()?.sessionId;
export async function agentCmd(sid: string | undefined, op: string, args: Record<string, unknown> = {}, timeout = 15_000) {
  const s = pickSid(sid); if (!s) throw new Error('no online agent session');
  return sendCmd(s, op, args, timeout);
}

// ---- dump buffer helpers (b64|sha → Buffer / file path) ------------------
export async function dumpBuf(a: any): Promise<Buffer> {
  if (a.b64) return Buffer.from(a.b64, 'base64');
  if (a.sha && dumps.get(a.sha)) {
    try { return await readFile(dumps.get(a.sha)!.path); }
    catch { const e: any = new Error('dump missing'); e.status = 404; throw e; }   // registry knows it, disk lost it
  }
  const e: any = new Error('need b64 or known sha'); e.status = 400; throw e;
}
// File-path variant for the shell-out analyzers (llvm-objdump/readelf need a path, not a
// Buffer). Known sha → its stored path (no copy); b64 → a unique temp file the caller unlinks.
let tmpSeq = 0;
export async function dumpBufPath(a: any): Promise<{ path: string; tmp: string | null }> {
  if (a.sha && dumps.get(a.sha)) return { path: dumps.get(a.sha)!.path, tmp: null };
  if (a.b64) { const tmp = join(tmpdir(), `adh_so_${Date.now()}_${++tmpSeq}.so`); writeFileSync(tmp, Buffer.from(a.b64, 'base64')); return { path: tmp, tmp }; }
  const e: any = new Error('need b64 or known sha'); e.status = 400; throw e;
}

// ---- dump engine ---------------------------------------------------------
function inferKind(b: Buffer): string {
  if (b.length >= 4 && b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a) return 'dex';
  if (b.length >= 4 && b[0] === 0x63 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return 'cdex';
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'so';
  if (b.length >= 2 && b[0] === 0x50 && b[1] === 0x4b) return 'zip';
  if (b.length >= 4 && b[0] === 0x76 && b[1] === 0x64 && b[2] === 0x65 && b[3] === 0x78) return 'vdex';
  if (b.length >= 4 && b[0] === 0x6f && b[1] === 0x61 && b[2] === 0x74 && b[3] === 0x0a) return 'oat';
  return 'region';
}

// Read [addr, addr+size) from the target via chunked agent reads, and SAY whether all of it
// arrived. A short read used to be returned as an ordinary buffer, which let callers treat a
// partial dump as a complete artifact (and a zero-filled hole in a reassembled ELF look real).
export interface MemRead { buf: Buffer; requested: number; read: number; complete: boolean; error?: string; }
export async function readMemEx(sid: string, addr: bigint, size: number): Promise<MemRead> {
  const CHUNK = 1 << 20;
  const parts: Buffer[] = [];
  let a = addr, remaining = size;
  let error: string | undefined;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: a.toString(16), size: want }, 20_000);
    if (!r.ok) { error = String(r.error ?? 'read failed'); break; }
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    a += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) { error = `short read (${b.length}/${want} bytes at 0x${a.toString(16)})`; break; }
  }
  const buf = Buffer.concat(parts);
  return { buf, requested: size, read: buf.length, complete: buf.length === size, error };
}

// Buffer-only view for callers that genuinely do not care (kept for compatibility).
export async function readMem(sid: string, addr: bigint, size: number): Promise<Buffer> {
  return (await readMemEx(sid, addr, size)).buf;
}

// ---- memory write + undo -------------------------------------------------------------------
// The write side of readMem: 1..4096 bytes per call, with the agent returning the bytes it
// replaced. The host remembers that reply, so `memory_restore` can undo a patch without the caller
// keeping the original bytes: an operator (or an AI) that patches one branch to see what happens
// needs ONE command to put it back, not a byte-tracking protocol. Bounded per session - this is a
// convenience, not an audit log.
const WRITE_UNDO_PER_SESSION = 64;
interface WriteUndo { before: string; len: number; at: number; forced: boolean; }
const writeUndo = new Map<string, WriteUndo>();
const writeKey = (sid: string, addr: bigint) => `${sid}:${addr.toString(16)}`;

function parseMemAddress(text: unknown): bigint | null {
  const s = String(text ?? '').trim();
  if (!s) return null;
  try {
    const v = BigInt(s);              // accepts 123 and 0x7f...
    return v > 0n ? v : null;
  } catch { return null; }
}

function rememberWrite(sid: string, addr: bigint, before: string, len: number, forced: boolean) {
  const mine = [...writeUndo.keys()].filter((k) => k.startsWith(`${sid}:`));
  while (mine.length >= WRITE_UNDO_PER_SESSION) writeUndo.delete(mine.shift()!);
  writeUndo.set(writeKey(sid, addr), { before, len, at: Date.now(), forced });
}

/** Write bytes into the target. Returns the agent's reply; validation failures write nothing. */
export async function writeMem(sid: string, addrText: unknown, hexText: unknown, force = false) {
  const addr = parseMemAddress(addrText);
  if (addr === null) return { ok: false, error: 'addr must be a positive number or 0x... string' };
  const clean = String(hexText ?? '').trim().toLowerCase();
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-f]+$/.test(clean)) {
    return { ok: false, error: 'hex must be even-length hex (1..4096 bytes); nothing was written' };
  }
  if (clean.length > 8192) return { ok: false, error: 'hex max 4096 bytes per write' };
  const r: any = await sendCmd(sid, 'write',
    { addr: addr.toString(16), hex: clean, force: force ? 'true' : 'false' }, 20_000);
  if (!r || r.ok !== true) return r ?? { ok: false, error: 'no reply from agent' };
  const before = typeof r.before === 'string' ? r.before : '';
  const trackable = r.beforeReadable === true && before.length > 0;
  if (trackable) rememberWrite(sid, addr, before, Number(r.wrote) || clean.length / 2, force);
  return { ...r, undoAvailable: trackable };
}

/** Put back the bytes the most recent write at this address replaced. */
export async function restoreMem(sid: string, addrText: unknown) {
  const addr = parseMemAddress(addrText);
  if (addr === null) return { ok: false, error: 'addr must be a positive number or 0x... string' };
  const key = writeKey(sid, addr);
  const entry = writeUndo.get(key);
  if (!entry) return { ok: false, error: `no write recorded at 0x${addr.toString(16)} for this session` };
  // A non-writable page needed force the first time and needs it again: every forced write puts the
  // original protection back before replying.
  const r: any = await sendCmd(sid, 'write',
    { addr: addr.toString(16), hex: entry.before, force: entry.forced ? 'true' : 'false' }, 20_000);
  if (r && r.ok === true) writeUndo.delete(key);
  return r ?? { ok: false, error: 'no reply from agent' };
}

// ---- startup policy (host-side pre-arm) ----------------------------------------------------
// Applied the moment a session's hello arrives, before the capture loop starts. The host cannot
// beat a check that runs in .init_array (that needs the Zygisk companion writing policy before
// adh_agent_start), but it can beat "the operator types the command 30 seconds later", which is
// the difference between a dead process and a usable session on a target that exits early.
// Default OFF: neutralizing access()/faccessat() makes EVERY path check in the app fail.
export interface AntiDebugTarget { symbol: string; returnValue: string; errno: number }
// Startup uses the MINIMAL plan on purpose. Measured on the sandbox: hooking access()/faccessat()
// with skipOriginal at hello makes EVERY path check fail during initialization too, and the app
// died within ~0.5s of the hooks landing. ptrace is the one gate that is safe to fake that early
// (returning 0 for TRACEME is harmless). The other two are opt-in per target via extraTargets, or
// applied later with `recipe anti_debug` once the process is initialized.
const ANTI_DEBUG_DEFAULTS: AntiDebugTarget[] = [
  { symbol: 'ptrace', returnValue: '0', errno: 0 },
];

/** Settings + env → the startup policy for this daemon process. ADH_AUTO_ANTIDEBUG wins. */
export function autoAntiDebugEnabled(env: NodeJS.ProcessEnv = process.env, startup = settings.startup): boolean {
  const v = String(env.ADH_AUTO_ANTIDEBUG ?? '').toLowerCase();
  if (v === '1' || v === 'true' || v === 'on') return true;
  if (v === '0' || v === 'false' || v === 'off') return false;
  return startup?.antiDebug === true;
}

/** The exact list applied at hello: the three libc checks plus caller-supplied extra symbols. */
export function antiDebugTargets(startup = settings.startup): AntiDebugTarget[] {
  const out = ANTI_DEBUG_DEFAULTS.map((t) => ({ ...t }));
  for (const name of startup?.extraTargets ?? []) {
    if (!out.some((t) => t.symbol === name)) out.push({ symbol: name, returnValue: '-1', errno: 13 });
  }
  return out;
}

/**
 * Does the pre-arm apply to THIS package? Enabling it neutralizes path checks process-wide, so
 * `startup.packages` (empty = all) is the safety valve: the daemon must not silently change how
 * every other app behaves just because one target needs it.
 */
export function shouldPreArm(pkg: string, env: NodeJS.ProcessEnv = process.env, startup = settings.startup): boolean {
  if (!autoAntiDebugEnabled(env, startup)) return false;
  const list = startup?.packages ?? [];
  return list.length === 0 || list.includes(pkg);
}

/**
 * The delayed half of the policy. The checks that make path lookups fail are unsafe DURING
 * initialization (measured: they killed the sandbox ~0.5 s after hello), so they are installed
 * once the app has settled instead. Pure so the plan can be unit-tested without a device.
 */
export function startupWidenPlan(startup = settings.startup): { afterMs: number; targets: AntiDebugTarget[] } {
  const afterMs = Math.max(0, Math.min(600_000, Number(startup?.widenAfterMs) || 0));
  const seen = new Set<string>();
  const targets: AntiDebugTarget[] = [];
  for (const name of startup?.widenTargets ?? []) {
    if (!name || seen.has(name)) continue;
    seen.add(name);
    targets.push({ symbol: name, returnValue: '-1', errno: 13 });
  }
  return { afterMs, targets };
}

/**
 * NOT WIRED: pre-arming the RegisterNatives hook at hello is measured-UNSAFE on the SDK 35
 * reference target. An install at hello produced a SIGILL (ILL_ILLOPC at a page boundary) and a
 * second run corrupted an ART ConcurrentCopying GC. The inline patch on libart is at fault, not
 * the wrapper. The safe route to the same knowledge is static: disassemble the module's
 * JNI_OnLoad, follow the RegisterNatives call to its JNINativeMethod array and read
 * name/signature/fnPtr. Do not auto-arm `jni_hook`; it stays a manual command.
 */

async function installNeutralizers(sid: string, module: string, targets: AntiDebugTarget[]) {
  const hookIds: number[] = [];
  const failed: { symbol: string; error: string }[] = [];
  for (const t of targets) {
    try {
      const r: any = await sendCmd(sid, 'native_hook', {
        action: 'hook', mode: 'inline', module, symbol: t.symbol,
        skipOriginal: 'true', returnValue: t.returnValue, errno: t.errno,
      }, 20_000);
      if (r?.ok === true && Number(r.hookId) > 0) hookIds.push(Number(r.hookId));
      else failed.push({ symbol: t.symbol, error: String(r?.error ?? 'install failed') });
    } catch (e) {
      failed.push({ symbol: t.symbol, error: (e as Error).message });
    }
  }
  return { hookIds, failed };
}

/** Second phase: install the checks that were unsafe at hello. Runs once per session. */
export async function widenStartupHooks(sid: string): Promise<void> {
  const s = sessions.get(sid);
  if (!s || !s.online || !s.startupHooks || s.startupHooks.widenedAt) return;
  const plan = startupWidenPlan();
  if (!plan.targets.length) return;
  const module = settings.startup.module || 'libc.so';
  const { hookIds, failed } = await installNeutralizers(sid, module, plan.targets);
  // Re-read the session: it may have closed while we were installing (each sendCmd waits).
  const live = sessions.get(sid);
  if (!live || !live.startupHooks || live.startupHooks.widenedAt) return;
  live.startupHooks = {
    ...live.startupHooks,
    hookIds: [...live.startupHooks.hookIds, ...hookIds],
    failed: [...live.startupHooks.failed, ...failed],
    widenedAt: Date.now(),
  };
  log(`[startup] 延迟加宽 ${sid} ${live.package}: +${hookIds.length} 个钩子${failed.length ? `，失败 ${failed.map((f) => f.symbol).join(',')}` : ''}`);
  broadcast('agent.startup.widen', { sessionId: sid, package: live.package, ...live.startupHooks });
}

export async function applyStartupHooks(sid: string): Promise<AgentSession['startupHooks'] | null> {
  const s = sessions.get(sid);
  if (!s || !s.online) return null;
  if (s.startupHooks) return s.startupHooks;      // once per session: a reconnect is a new session
  if (!shouldPreArm(s.package)) return null;
  const module = settings.startup.module || 'libc.so';
  const { hookIds, failed } = await installNeutralizers(sid, module, antiDebugTargets());
  s.startupHooks = { appliedAt: Date.now(), module, hookIds, failed };
  log(`[startup] anti-debug 已布防 ${sid} ${s.package}: ${hookIds.length} 个钩子${failed.length ? `，失败 ${failed.map((f) => f.symbol).join(',')}` : ''}`);
  broadcast('agent.startup', { sessionId: sid, package: s.package, ...s.startupHooks });
  // Delayed widening: an unref'd timer, so a pending widen can never hold the process open (or a
  // test run). A session that closed before it fires is a no-op (checked inside).
  const plan = startupWidenPlan();
  if (plan.afterMs > 0 && plan.targets.length) {
    const timer = setTimeout(() => { void widenStartupHooks(sid); }, plan.afterMs);
    if (typeof timer.unref === 'function') timer.unref();
  }
  return s.startupHooks;
}

/** Writes this session can still undo (newest last). */
export function listWriteUndo(sid: string) {
  return [...writeUndo.entries()]
    .filter(([k]) => k.startsWith(`${sid}:`))
    .map(([k, v]) => ({ addr: '0x' + k.slice(sid.length + 1), len: v.len, forced: v.forced, at: v.at }));
}

// ---- module-load events -------------------------------------------------------------------
// `module_watch start` makes the agent emit MODULE_LOAD for every library mapped afterwards. The
// records arrive through the same capture ring as everything else; this reads the structured
// payload back out of them so a caller does not have to hex-decode a capture by hand.
export function moduleLoads(sid: string, limit = 50) {
  return captures
    .filter((c) => c.func === 'MODULE_LOAD' && c.sessionId === sid)
    .slice(-Math.max(1, Math.min(500, limit)))
    .map((c) => {
      try { return JSON.parse(Buffer.from(c.hex, 'hex').toString('utf8')); }
      catch { return { unparsed: c.hex.slice(0, 120) }; }
    });
}

export interface ModuleInfo { name: string; path: string; base: string; end: string; size: number; segs: number; }
export function modulesFromMaps(regions: MapsRegion[]): ModuleInfo[] {
  const by = new Map<string, MapsRegion[]>();
  for (const r of regions) {
    if (!r.path || !/\.(so|apk|jar|oat|odex|vdex|dex)$/.test(r.path)) continue;
    (by.get(r.path) ?? by.set(r.path, []).get(r.path)!).push(r);
  }
  const out: ModuleInfo[] = [];
  for (const [path, regs] of by) {
    const starts = regs.map(r => BigInt('0x' + r.start));
    const ends = regs.map(r => BigInt('0x' + r.end));
    const base = starts.reduce((m, v) => (v < m ? v : m));
    const end = ends.reduce((m, v) => (v > m ? v : m));
    out.push({ name: path.split('/').pop()!, path, base: base.toString(16), end: end.toString(16), size: Number(end - base), segs: regs.length });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// Reconstruct a loaded .so from memory into a valid ELF (SoFixer-lite):
// file offsets are laid out == virtual addresses, section headers dropped,
// program headers preserved so PT_DYNAMIC (dynsym/dynstr) resolves for analysis.
export async function reconstructSo(sid: string, baseHex: string): Promise<Buffer> {
  const base = BigInt('0x' + baseHex);
  const ehdr = await readMem(sid, base, 64);
  if (ehdr.length < 64 || ehdr.readUInt32LE(0) !== 0x464c457f) throw new Error('no ELF header at base');
  if (ehdr[4] !== 2) throw new Error('only ELF64 supported in v0.2');
  const phoff = ehdr.readBigUInt64LE(32);
  const phentsize = ehdr.readUInt16LE(54);
  const phnum = ehdr.readUInt16LE(56);
  if (phnum === 0 || phentsize < 56) throw new Error('bad program headers');
  const phBuf = await readMem(sid, base + phoff, phnum * phentsize);

  // pass 1: image size = max(p_vaddr + p_memsz) over PT_LOAD
  let imgSize = 0n;
  const loads: { vaddr: bigint; filesz: bigint; memsz: bigint }[] = [];
  for (let i = 0; i < phnum; i++) {
    const p = phBuf.subarray(i * phentsize);
    if (p.readUInt32LE(0) !== 1) continue;              // PT_LOAD
    const vaddr = p.readBigUInt64LE(16);
    const filesz = p.readBigUInt64LE(32);
    const memsz = p.readBigUInt64LE(40);
    if (filesz > memsz) throw new Error(`PT_LOAD at +0x${vaddr.toString(16)} filesz exceeds memsz`);
    loads.push({ vaddr, filesz, memsz });
    if (vaddr + memsz > imgSize) imgSize = vaddr + memsz;
  }
  if (imgSize === 0n || imgSize > 512n * 1024n * 1024n) throw new Error('implausible image size');
  const image = Buffer.alloc(Number(imgSize));

  // pass 2: copy each PT_LOAD's file bytes to file offset == vaddr. p_memsz past p_filesz is BSS
  // and stays the zeros Buffer.alloc already wrote. Reading memsz used to fail the whole module:
  // the mapping ends on a page boundary, so the BSS tail comes back as a short read. A short read
  // of the file bytes themselves is still an error — those zeros would look like real code.
  for (const { vaddr, filesz } of loads) {
    if (filesz === 0n) continue;
    const seg = await readMemEx(sid, base + vaddr, Number(filesz));
    if (!seg.complete) {
      throw new Error(`PT_LOAD file bytes at +0x${vaddr.toString(16)} short read: ${seg.read}/${seg.requested} bytes`
        + (seg.error ? ` (${seg.error})` : ''));
    }
    seg.buf.copy(image, Number(vaddr));
  }
  // rewrite ehdr in image: drop section headers
  ehdr.copy(image, 0, 0, 64);
  image.writeBigUInt64LE(0n, 40);   // e_shoff = 0
  image.writeUInt16LE(0, 60);       // e_shnum = 0
  image.writeUInt16LE(0, 62);       // e_shstrndx = 0
  // rewrite each phdr: p_offset = p_vaddr, p_filesz = p_memsz
  for (let i = 0; i < phnum; i++) {
    const off = Number(phoff) + i * phentsize;
    if (off + 56 > image.length) break;
    const vaddr = image.readBigUInt64LE(off + 16);
    const memsz = image.readBigUInt64LE(off + 40);
    image.writeBigUInt64LE(vaddr, off + 8);   // p_offset = p_vaddr
    image.writeBigUInt64LE(memsz, off + 32);  // p_filesz = p_memsz
  }
  return image;
}

const SO_REASSEMBLY_NOTE = 'reassembled from memory: offsets == vaddrs, section headers dropped, not byte-exact';

const ELF_MAGIC = 0x464c457f;

function sessionPackage(sid: string): string {
  const pkg = sessions.get(sid)?.package ?? '';
  if (!pkg || pkg === '?') throw new Error('session has no package');
  return pkg;
}

async function loadMaps(sid: string): Promise<MapsRegion[]> {
  const maps = await sendCmd(sid, 'maps', {}, 30_000);
  if (!maps.ok) throw new Error(String(maps.error ?? 'maps failed'));
  return Array.isArray(maps.regions) ? maps.regions : [];
}

// Four bytes at the load base. A failure leaves the row unknown instead of failing the inventory.
async function elfAt(sid: string, base: string): Promise<boolean | null> {
  try {
    const mem = await readMemEx(sid, BigInt('0x' + base.replace(/^0x/i, '')), 4);
    if (mem.buf.length < 4) return false;
    return mem.buf.readUInt32LE(0) === ELF_MAGIC;
  } catch {
    return null;
  }
}

export async function inventoryUnpack(sid: string) {
  const pkg = sessionPackage(sid);
  const regions = await loadMaps(sid);
  const art = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
  const listed = Array.isArray(art.dexfiles) ? art.dexfiles : [];
  const dexes = listed.map((dex: any) => {
    const begin = String(dex.begin ?? '');
    const declared = Number(dex.size ?? 0);
    const readable = begin && declared > 0 ? contiguousReadable(regions, begin, declared) : 0;
    const saved = [...dumps.values()].find((item) =>
      item.package === pkg && (item.kind === 'dex' || item.kind === 'cdex') && item.complete === true
      && String(item.addr ?? '').replace(/^0x/i, '') === begin.replace(/^0x/i, ''));
    return {
      begin, declared, readable,
      format: dex.format ?? 'dex',
      status: readable === declared && declared > 0 ? 'ready' : 'short',
      ...(saved ? { sha256: saved.sha256, savedSize: saved.size } : {}),
    };
  });
  const mods = appOwnedSoModules(modulesFromMaps(regions), pkg);
  const loaded = [];
  for (const mod of mods) {
    const saved = [...dumps.values()].find((item) =>
      item.package === pkg && item.kind === 'so' && item.complete === true && item.tag === mod.name);
    loaded.push({
      name: mod.name, path: mod.path, base: mod.base, size: mod.size,
      elf: await elfAt(sid, mod.base),
      ...(saved ? { sha256: saved.sha256, savedSize: saved.size } : {}),
    });
  }
  const names = new Set(mods.map((mod) => mod.name));
  const packaged = [];
  const seen = new Set<string>();
  for (const dir of packageSoDirs(mods.map((mod) => mod.path), pkg)) {
    let entries: any[] = [];
    try {
      const listed = await sendCmd(sid, 'list_dir', { path: dir }, 15_000);
      if (listed?.ok && Array.isArray(listed.entries)) entries = listed.entries;
    } catch { /* a missing files dir is normal */ }
    for (const entry of entries) {
      if (entry?.type !== 'f' || !String(entry.name ?? '').endsWith('.so')) continue;
      const path = `${dir}/${entry.name}`;
      if (seen.has(path)) continue;
      seen.add(path);
      packaged.push({
        name: String(entry.name), path, size: Number(entry.size ?? 0),
        loaded: names.has(String(entry.name)),
      });
    }
  }
  packaged.sort((a, b) => a.name.localeCompare(b.name));
  const session = sessions.get(sid);
  return {
    ok: true, session: sid, package: pkg, pid: session?.pid ?? 0, process: session?.process ?? pkg,
    dexes, loaded, packaged,
  };
}

// Read one declared dex. A short mapping is not stored. A standard dex is stored only after its
// class table walks; a compact dex has no walker here, so a full read is stored and named cdex.
//
// The return shape declares every field optional-on-some-branch (error/status on failure,
// dedup/carrier/classes on success) instead of a union, because `strictNullChecks` is off and
// callers read those fields after a plain `.saved` check.
export interface UnpackedDexRow {
  begin: string; size: number; saved: boolean; readable?: number;
  error?: string; status?: string; dedup?: boolean; sha256?: string;
  bytes?: number; path?: string; format?: string;
  carrier?: boolean; classes?: number; methods?: number;
}
export async function unpackOneDex(
  sid: string, beginHex: string, size: number,
  opts?: { tag?: string; note?: string },
): Promise<UnpackedDexRow> {
  const pkg = sessionPackage(sid);
  const begin = beginHex.replace(/^0x/i, '');
  if (!begin || !Number.isSafeInteger(size) || size <= 0 || size > (256 << 20)) {
    return { begin, size, saved: false, error: 'invalid address/size' };
  }
  const mem = await readMemEx(sid, BigInt('0x' + begin), size);
  if (!mem.complete) {
    return { begin, size, readable: mem.read, saved: false, status: 'short' };
  }
  const magic = mem.buf.subarray(0, 4).toString('latin1');
  let carrier: boolean | undefined;
  let classes: number | undefined;
  let methods: number | undefined;
  if (magic === 'dex\n') {
    try { parseDex(mem.buf); }
    catch (e) { return { begin, size, readable: mem.read, saved: false, error: (e as Error).message }; }
  } else if (magic !== 'cdex') {
    return { begin, size, readable: mem.read, saved: false, error: 'not a dex' };
  }
  const { meta, dedup } = await persistArtifact(mem.buf, {
    source: 'region', addr: begin, tag: opts?.tag || 'dex-all', sessionId: sid, package: pkg,
  }, { requestedSize: size, complete: true, note: opts?.note });
  if (magic === 'dex\n') {
    try {
      const doc = ensureDexIndex(mem.buf);
      const shape = classifyDexArtifact(mem.buf.length, doc.counts?.classes ?? 0, doc.counts?.methods ?? 0);
      carrier = shape.carrier; classes = shape.classes; methods = shape.methods;
    } catch { /* the file is saved; the row simply has no class counts */ }
  }
  return {
    begin, size, readable: mem.read, saved: true, dedup, sha256: meta.sha256, bytes: meta.size,
    path: meta.path, format: meta.kind, ...(carrier === undefined ? {} : { carrier, classes, methods }),
  };
}

/** Pull an on-disk package .so (APK lib/ or private files/) onto the host artifact store. */
export async function pullPackageSo(pkg: string, path: string, name?: string) {
  const label = (name || path.split('/').pop() || 'lib.so').trim() || 'lib.so';
  const r = await pullPackageFile(pkg, path);
  if (r.truncated || !r.b64) {
    return {
      saved: false, name: label, path,
      error: `文件过大或未读到（上限 ${Math.floor(PACKAGE_FILE_READ_CAP / 1048576)} MiB，实际 ${r.fsize} B）`,
      fsize: r.fsize,
    };
  }
  const buf = Buffer.from(r.b64, 'base64');
  const { meta, dedup } = await persistArtifact(buf, {
    source: 'package-so', addr: '', tag: label, sessionId: '', package: pkg,
  }, { note: path, requestedSize: r.fsize, complete: !r.truncated });
  return {
    saved: true, dedup, name: label, path,
    sha256: meta.sha256, size: meta.size, kind: meta.kind, fsize: r.fsize,
  };
}

export async function dumpOneAppSo(sid: string, base: string, name: string) {
  const pkg = sessionPackage(sid);
  try {
    const buf = await reconstructSo(sid, base.replace(/^0x/i, ''));
    const sha = createHash('sha256').update(buf).digest('hex');
    const existing = dumps.get(sha);
    if (existing) return { name, base, saved: true, dedup: true, sha256: sha, size: buf.length, elf: true };
    const path = join(CAPTURES, `${sha.slice(0, 16)}.so`);
    if (!existsSync(path)) await writeFile(path, buf);
    const meta: DumpMeta = {
      sha256: sha, size: buf.length, requestedSize: buf.length, complete: true,
      source: 'so-reassembly', note: SO_REASSEMBLY_NOTE,
      addr: base.replace(/^0x/i, ''), tag: name, sessionId: sid, package: pkg,
      capturedAt: Date.now(), path, kind: 'so',
    };
    rememberDump(meta);
    broadcast('dump.new', meta);
    pruneArtifactsAndIndex(sha);
    return { name, base, saved: true, dedup: false, sha256: sha, size: buf.length, elf: true };
  } catch (e) {
    const message = (e as Error).message;
    return { name, base, saved: false, elf: message.includes('no ELF header') ? false : undefined, error: message };
  }
}

// Dump the selected app's own loaded .so files. System libraries stay out (see appOwnedSoModules).
// A segment that cannot be read in full is a failure for that file: nothing truncated is saved.
export async function dumpAppSo(sid: string) {
  const session = sessions.get(sid);
  const pkg = session?.package ?? '';
  if (!pkg || pkg === '?') throw new Error('session has no package');
  const maps = await sendCmd(sid, 'maps', {}, 30_000);
  if (!maps.ok) throw new Error(String(maps.error ?? 'maps failed'));
  const mods = appOwnedSoModules(modulesFromMaps(maps.regions ?? []), pkg);
  const modules: { name: string; path: string; sha256?: string; size?: number; dedup?: boolean; error?: string }[] = [];
  let dumped = 0, deduped = 0, failed = 0;
  for (const mod of mods) {
    try {
      const buf = await reconstructSo(sid, mod.base);
      const sha = createHash('sha256').update(buf).digest('hex');
      const existing = dumps.get(sha);
      if (existing) {
        dumped++; deduped++;
        modules.push({ name: mod.name, path: mod.path, sha256: sha, size: buf.length, dedup: true });
        continue;
      }
      const path = join(CAPTURES, `${sha.slice(0, 16)}.so`);
      if (!existsSync(path)) await writeFile(path, buf);
      const meta: DumpMeta = {
        sha256: sha, size: buf.length, requestedSize: buf.length, complete: true,
        source: 'so-reassembly', note: SO_REASSEMBLY_NOTE,
        addr: mod.base, tag: mod.name, sessionId: sid, package: pkg, capturedAt: Date.now(), path, kind: 'so',
      };
      rememberDump(meta);
      broadcast('dump.new', meta);
      pruneArtifactsAndIndex(sha);
      dumped++;
      modules.push({ name: mod.name, path: mod.path, sha256: sha, size: buf.length, dedup: false });
    } catch (e) {
      failed++;
      modules.push({ name: mod.name, path: mod.path, error: (e as Error).message });
    }
  }
  log(`[dump] app so ${sid} ${pkg}: ${dumped}/${mods.length} (dedup ${deduped}, failed ${failed})`);
  return { ok: true, session: sid, package: pkg, count: mods.length, dumped, deduped, failed, modules };
}

// ---- dex header repair ----------------------------------------------------
// (adler32 also exists in dex.ts for dex rebuild — kept here too since repairDexHeader
//  is a dump-engine concern; the duplication is one tiny pure function.)
function adler32(buf: Buffer, start = 0): number {
  let a = 1, b = 0; const MOD = 65521;
  for (let i = start; i < buf.length; i++) {
    a = (a + buf[i]) % MOD;
    b = (b + a) % MOD;
  }
  return ((b << 16) | a) >>> 0;
}

// Repair a dumped dex's self-describing header fields (mutates buf):
//   file_size@32 = length ; signature@12(20) = SHA-1(bytes[32..]) ; checksum@8 = adler32(bytes[12..])
// Order matters: file_size is covered by signature & checksum; signature is covered by checksum.
export function repairDexHeader(buf: Buffer): { fileSize: number; checksum: string; signature: string; magicOk: boolean } {
  const magicOk = buf.length >= 40 && buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a;
  const fileSize = buf.length;
  buf.writeUInt32LE(fileSize, 32);
  const sig = createHash('sha1').update(buf.subarray(32)).digest();
  sig.copy(buf, 12);
  const checksum = adler32(buf, 12);
  buf.writeUInt32LE(checksum, 8);
  return { fileSize, checksum: checksum.toString(16).padStart(8, '0'), signature: sig.toString('hex'), magicOk };
}

// Artifact retention, wired to the dex index. Called after a NEW artifact lands (a dedup hit kept
// the file that was already there, so there is nothing to reclaim) and once at boot. Retention
// failing must never break a dump that already succeeded, but it must not be silent either.
export function pruneArtifactsAndIndex(protectSha?: string) {
  try {
    const r = pruneArtifacts((sha) => {
      try { deleteDexDocument(sha); }
      catch (e) { log(`[artifacts] 索引行未删除 ${sha.slice(0, 16)}(已删文件，索引将留下陈旧行):`, (e as Error).message); }
    }, protectSha);
    if (r.removed || r.failed) {
      log(`[artifacts] 回收 ${r.removed} 个（释放 ${(r.bytesFreed / 1048576).toFixed(1)} MiB，`
        + `剩余 ${(r.remainingBytes / 1048576).toFixed(1)} MiB / 上限 ${(settings.artifacts.maxBytes / 1048576).toFixed(0)} MiB，保留 ${r.kept}）`
        + (r.failed ? `，${r.failed} 个删除失败` : ''));
    }
    return r;
  } catch (e) { log('[artifacts] 回收失败:', (e as Error).message); return null; }
}

// Persist an in-memory buffer as a dump artifact, in the same store, directory and naming scheme
// dumpRegion uses, so everything downstream (dumps_list, /api/dumps/download, dex_index by sha)
// works on it unchanged.
//
// This exists because the repair routes used to hand the repaired dex back INLINE as base64. For a
// real packed target that is a 120 MB dex -> a 160 MB reply, which overflows the MCP/HTTP reply and
// leaves the caller with something it cannot use anyway (it already had the bytes). Returning the
// sha and a stored artifact instead makes the repaired dex indexable and downloadable like any
// other dump.
export async function persistArtifact(
  buf: Buffer,
  fields: Pick<DumpMeta, 'source' | 'addr' | 'tag' | 'sessionId' | 'package'>,
  opts: { requestedSize?: number; complete?: boolean; note?: string } = {},
): Promise<{ meta: DumpMeta; dedup: boolean }> {
  const sha = createHash('sha256').update(buf).digest('hex');
  const existing = dumps.get(sha);
  if (existing) return { meta: existing, dedup: true };
  const kind = inferKind(buf);
  const path = join(CAPTURES, `${sha.slice(0, 16)}.${kind}.bin`);
  if (!existsSync(path)) await writeFile(path, buf);
  const meta: DumpMeta = {
    sha256: sha, size: buf.length,
    requestedSize: opts.requestedSize ?? buf.length,
    complete: opts.complete ?? true,
    ...fields, capturedAt: Date.now(), path, kind,
    ...(opts.note ? { note: opts.note } : {}),
  };
  rememberDump(meta);
  broadcast('dump.new', meta);
  pruneArtifactsAndIndex(sha);     // a new file landed: enforce the on-disk budget now
  return { meta, dedup: false };
}

// Dump [addr, addr+size) by orchestrating chunked agent reads, then sha256 + dedup + persist.
export async function dumpRegion(sid: string, addrHex: string, size: number, tag: string): Promise<{ meta: DumpMeta; dedup: boolean }> {
  // Validate before doing anything: Number(undefined) is NaN, and `while (remaining > 0)` with NaN
  // does nothing - the old code then hashed an empty buffer and reported a successful 0-byte dump.
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error(`dump size must be a positive integer (got ${size})`);
  const DUMP_MAX = 512 * 1024 * 1024;
  if (size > DUMP_MAX) throw new Error(`dump size ${size} exceeds the ${DUMP_MAX} byte cap`);
  const CHUNK = 1 << 20;                          // matches agent per-read cap
  let addr = BigInt('0x' + addrHex);
  const parts: Buffer[] = [];
  let remaining = size;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: addr.toString(16), size: want }, 20_000);
    if (!r.ok) { if (parts.length) break; throw new Error(`read failed @0x${addr.toString(16)}: ${r.error}`); }
    // A mid-dump failure keeps what arrived, but the meta below says so (complete:false).
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    addr += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) break;                   // short read (unreadable tail)
  }
  const buf = Buffer.concat(parts);
  const sha = createHash('sha256').update(buf).digest('hex');
  const existing = dumps.get(sha);
  // Dedup by content, but describe THIS request: the stored meta carries the completeness of the
  // request that created it. A short read whose bytes match an earlier artifact used to inherit
  // that artifact meta (complete:true, a smaller requestedSize), so a truncated dump came back
  // looking whole.
  if (existing) {
    return { meta: { ...existing, size: buf.length, requestedSize: size, complete: buf.length === size }, dedup: true };
  }
  const s = sessions.get(sid);
  const kind = inferKind(buf);
  const path = join(CAPTURES, `${sha.slice(0, 16)}.${kind}.bin`);
  if (!existsSync(path)) await writeFile(path, buf);
  const complete = buf.length === size;
  const meta: DumpMeta = {
    sha256: sha, size: buf.length, requestedSize: size, complete, source: 'region', addr: addrHex, tag,
    sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind,
  };
  rememberDump(meta);
  broadcast('dump.new', meta);
  pruneArtifactsAndIndex(sha);     // a new file landed: enforce the on-disk budget now
  return { meta, dedup: false };
}

// ---- capture ops ---------------------------------------------------------
// The one-shot probe endpoints install-and-restore their OWN hooks on the same GOT slot
// the continuous capture uses. Suspend continuous capture around them (pause the drain +
// uninstall the persistent hooks) so the probe sees a clean slot, then resume.
// Remember the agent's per-hook install counters reported by capture_start/capture_stop.
// Fail-loud visibility: the persistent-hook path used to log only "capture_start <sid>", so a
// half-installed hook set (e.g. evp=0) looked identical to a healthy one.
function recordCaptureHooks(sid: string, r: any) {
  if (!r || (r.op !== 'capture_start' && r.op !== 'capture_stop')) return;
  const s = sessions.get(sid);
  if (!s) return;
  s.captureHooks = r;
}

// Apply the capture.enabled toggle to already-connected sessions.
// enabled=false → force-stop hooks everywhere. enabled=true → re-arm only packages that
// should auto-arm (scope allowlist / sandbox), using setCapture for a clean drain→stop→start.
export async function applyCaptureEnabled() {
  if (!settings.capture.enabled) {
    for (const s of sessions.values()) {
      if (!s.online) continue;
      try { await setCapture(s.sessionId, false); }
      catch (e) { log(`[settings] capture_stop 会话 ${s.sessionId} 失败:`, (e as Error).message); }
    }
    return;
  }
  try { await scopedApps(); } catch { /* cache may still help */ }
  for (const s of sessions.values()) {
    if (!s.online) continue;
    if (!shouldAutoArmPackage(s.package, s.entry)) continue;
    // Skip just-unpacked / in-unpack packages — flipping the global switch must not crash SecNeo.
    if (captureArmBlockedReason(s.package)) {
      log(`[settings] capture_start skip ${s.sessionId} (unpack protect ${s.package})`);
      continue;
    }
    try { await setCapture(s.sessionId, true); }
    catch (e) { log(`[settings] capture_start 会话 ${s.sessionId} 失败:`, (e as Error).message); }
  }
}

// ---- capture_start / capture_stop (the tools' one implementation) --------------------------
// The agent answers capture_start with ok:true unconditionally and 20+ per-symbol install
// counters: `ok:true` therefore says "the command ran", never "the hooks are live". The
// daemon derives the verdict here, once, so the MCP tool, any future REST route and the
// settings toggle cannot disagree about what "on" means.
const CRYPTO_COUNTERS = ['evp', 'cipherInit', 'cipherCtxFree', 'digest', 'hmac', 'digestSign', 'sslWrite', 'sslRead'];
const NESTED_COUNTERS: [string, string[]][] = [
  ['pkey', ['sign', 'verify', 'encrypt', 'decrypt']],
  ['aead', ['seal', 'open']],
  ['digestSignVerify', ['signInit', 'verifyInit', 'signFinal', 'verifyUpdate', 'verifyFinal']],
  ['file', ['open', 'openat', 'read', 'write', 'syscall', 'readChk', 'writeChk']],
  ['sys', ['ptrace', 'access', 'faccessat', 'prop', 'propread']],
];

/** Flatten an install reply into {name: count} for exactly the symbol sets that were requested. */
export function captureInstallCounters(reply: any): { name: string; value: number }[] {
  const out: { name: string; value: number }[] = [];
  if (!reply || typeof reply !== 'object') return out;
  // Groups the per-package hook policy turned off. The agent reports them as -1, which would
  // otherwise read as "asked for but missing" — they were never asked for.
  const skipped = new Set(
    String(reply.skipped ?? '').split(',').map((s: string) => s.trim()).filter(Boolean),
  );
  const wanted = (name: string) => !skipped.has(name);
  for (const k of CRYPTO_COUNTERS) if ((k in reply) && wanted(k)) out.push({ name: k, value: Number(reply[k]) || 0 });
  for (const [group, keys] of NESTED_COUNTERS) {
    // The file/sys hook sets are only installed when a module was named for them; when the
    // module is empty the agent does not touch those slots at all and its zeros mean nothing.
    if (group === 'file' && !String(reply.fileModule ?? '')) continue;
    if (group === 'sys' && !String(reply.sysModule ?? '')) continue;
    if (!wanted(group)) continue;
    const g = reply[group];
    if (!g || typeof g !== 'object') continue;
    for (const k of keys) {
      if (!(k in g)) continue;
      const value = Number(g[k]);
      if (!Number.isFinite(value)) continue;
      // System hooks use -1 when libc does not export the symbol (nothing to install).
      // Other groups keep a negative in the list: it is "asked for, not installed".
      if (value < 0 && group === 'sys') continue;
      out.push({ name: `${group}.${k}`, value });
    }
  }
  return out;
}

export interface CaptureToggle {
  ok: boolean; on: boolean; session: string;
  installed: number; attempted: number; notInstalled: string[]; partial: boolean;
  /** true when the result can be trusted as complete (nothing dropped, nothing unknown). */
  complete: boolean;
  /** capture_start re-arms from a clean slate (drain → stop → start) so the per-symbol counters
   *  are authoritative; drainedBeforeRearm is what that drain pulled out of the ring first. */
  rearmed?: boolean; drainedBeforeRearm?: number;
  /** off: how many records the drain pulled out of the agent ring before the stop (0 when the
   *  session has no drain loop - then the stop throws away whatever was still in the ring). */
  drained?: number; drainedOk?: boolean; dropped?: number;
  drainLoop?: 'armed' | 'started' | 'none';
  /** Set when arm was refused because one-click unpack is in progress or just finished. */
  captureSuppressed?: boolean; captureProtected?: boolean; error?: string;
  reply: any;
}

/**
 * Install or remove the persistent hook set for one session.
 * `on`: install, then report installed/attempted/notInstalled and a real verdict - with the
 * module left empty (scan every file-backed module) a symbol that installed nowhere is a
 * failure, while a named module legitimately may not import every symbol (partial, not failed).
 * `off`: drain the ring FIRST (capture_stop resets it - stopping without draining destroys
 * whatever the target produced since the last tick), then stop.
 */
export async function setCapture(
  sid: string,
  on: boolean,
  modules?: { cryptoModule?: string; fileModule?: string; sysModule?: string; force?: boolean },
): Promise<CaptureToggle> {
  const mods = { ...captureModules() };
  // Only keys the caller actually passed override the settings defaults (an explicit undefined
  // must not blank a module out - that would silently turn "hook this module" into "scan all").
  for (const k of ['cryptoModule', 'fileModule', 'sysModule'] as const) {
    const v = modules?.[k];
    if (typeof v === 'string' && v.length) mods[k] = v;
  }
  if (on) {
    const pkg = sessions.get(sid)?.package ?? '';
    const blocked = modules?.force === true ? null : captureArmBlockedReason(pkg);
    if (blocked) {
      return {
        ok: false, on: false, session: sid,
        installed: 0, attempted: 0, notInstalled: [], partial: false,
        complete: false, drainLoop: captureTimers.has(sid) ? 'armed' : 'none',
        captureSuppressed: true, captureProtected: isCaptureArmProtected(pkg),
        error: blocked, reply: { ok: false, error: blocked },
      } as CaptureToggle;
    }
    if (modules?.force === true && pkg) clearCaptureArmProtect(pkg);
    const verdict = await armCaptureHooks(sid, mods);
    // Start the drain loop without a second arm (hello path arms itself after a short delay).
    startCaptureLoop(sid, { skipArm: true });
    return verdict;
  }
  const drained = await drainSession(sid);
  const reply = await sendCmd(sid, 'capture_stop', {}, 8_000);
  recordCaptureHooks(sid, reply);
  const drainedCount = Number(drained.response?.count ?? 0) || 0;
  const dropped = Number(drained.response?.dropped ?? 0) || 0;
  return {
    ok: !!reply?.ok, on: false, session: sid,
    installed: 0, attempted: 0, notInstalled: [], partial: false,
    complete: drained.ok && dropped === 0,
    drained: drainedCount, drainedOk: drained.ok, dropped,
    drainLoop: captureTimers.has(sid) ? 'armed' : 'none',
    reply: { ...reply, drainError: drained.error },
  };
}

/** Manager Hook policy `y=1` enables system detection. Absent / default → off. */
export function policySystemOn(policy: string | undefined | null): boolean {
  if (!policy || policy === 'default') return false;
  const m = /(?:^|,)y=([01])(?:$|,)/.exec(policy);
  return !!m && m[1] === '1';
}

/**
 * Resolve sysModule for one arm: policy off → empty; policy on + empty config → detect_modules;
 * policy on + configured → keep configured. Dynamic-import detect to avoid a load-time cycle.
 */
export async function resolveSysModuleForArm(
  sid: string,
  configured: string,
): Promise<string> {
  const s = sessions.get(sid);
  if (!policySystemOn(s?.policy)) return '';
  const named = (configured ?? '').trim();
  if (named) return named;
  const pkg = s?.package ?? '';
  if (!pkg || pkg === '?') return '';
  try {
    const { planDetectModules } = await import('./detect.ts');
    const plan = await planDetectModules(sid, pkg);
    return String(plan.sysModule ?? '').trim();
  } catch (e) {
    log(`[capture] detect_modules for ${sid} failed:`, (e as Error).message);
    return '';
  }
}

/**
 * Drain → stop → start so GOT install counters are honest. Does not start the drain loop
 * (callers that need streaming must already have called startCaptureLoop / setCapture).
 */
async function armCaptureHooks(sid: string, mods: { cryptoModule: string; fileModule: string; sysModule: string }): Promise<CaptureToggle> {
  // RE-ARM FROM A CLEAN SLATE. adh_got_replace matches a GOT slot by VALUE, so an install that
  // runs while our own wrapper already sits in the slot reports 0 for it - indistinguishable
  // from "this symbol is not imported". Measured on the sandbox: a repeat capture_start said
  // 14/27, a stop-then-start said 23/27, and the 4 remaining zeros are genuinely absent from
  // libjavacore.so. So the verdict is only worth printing if the install started from the
  // original pointers: drain (never lose what the ring holds), stop, then install.
  const drained = await drainSession(sid);
  try { await sendCmd(sid, 'capture_stop', {}, 8_000); } catch { /* not armed: nothing to restore */ }
  const sysModule = await resolveSysModuleForArm(sid, mods.sysModule);
  const armedMods = { ...mods, sysModule };
  const reply = await sendCmd(sid, 'capture_start', armedMods, 15_000);
  recordCaptureHooks(sid, reply);
  const counters = captureInstallCounters(reply);
  const notInstalled = counters.filter((c) => c.value <= 0).map((c) => c.name);
  const installed = counters.length - notInstalled.length;
  const scannedAll = !String(armedMods.cryptoModule ?? '');
  const ok = installed > 0 && (scannedAll ? notInstalled.length === 0 : true);
  return {
    ok, on: true, session: sid,
    installed, attempted: counters.length, notInstalled,
    partial: notInstalled.length > 0,
    complete: ok && notInstalled.length === 0,
    drainLoop: captureTimers.has(sid) ? 'armed' : 'started',
    rearmed: true, drainedBeforeRearm: Number(drained.response?.count ?? 0) || 0,
    reply,
  };
}

// Install persistent hooks on connect, then poll capture_drain and stream each new record
// into the store + over WS. Also auto-dump the app's DEX files so the panel can download
// them. Mirrors the ios-decrypt-helper flow (hooks stay live, events fill the panel).
// Seed from durable captures so ids stay unique across daemon restarts.
let capSeq = captures.reduce((m, c) => Math.max(m, Number(c.id) || 0), 0);

// The agent's capture_drain is POP semantics: whatever the response holds leaves the agent ring for
// good. Only the code that puts it into the local store may therefore send it - a bare
// `sendCmd(sid, 'capture_drain')` throws those records away (and with them any other capture in the
// same batch). Every drainer registers itself here, and readers (java_trace, syscall_digest, ...) go
// through drainSession().
const captureDrainers = new Map<string, () => Promise<any>>();

/**
 * Drain the agent capture ring into the local store for this session.
 * Returns the last frame's response, or null when the session has no capture loop yet (in that case
 * the caller must NOT send capture_drain itself - the records would be lost).
 */
export interface DrainOutcome { ok: boolean; response?: any; error?: string }
export async function drainSession(sid: string): Promise<DrainOutcome> {
  const run = captureDrainers.get(sid);
  if (!run) return { ok: false, error: 'no capture loop registered for this session' };
  try { return { ok: true, response: await run() }; }
  catch (e) { return { ok: false, error: (e as Error).message }; }
}

export function forgetCaptureSession(sid: string) { captureDrainers.delete(sid); }

const captureLoopPending = new Set<string>();

/** Packages for which hello-time capture_start / autoDumpDex must not run (one-click unpack).
 *  SecNeo targets (e.g. 学习通) suicide when GOT crypto hooks land on a fresh process —
 *  measured 2026-10-20: HELLO → capture_stop/start → CLOSE within ~1.5s, before dump. */
const unpackSuppressArm = new Set<string>();
/** After unpack finishes, keep blocking *manual / settings* re-arm on the same live process
 *  until the package hellos again (user restarted the app). Global toggle must not silently
 *  re-arm a just-unpacked SecNeo target. */
const unpackProtectArm = new Set<string>();
export function suppressCaptureArmForUnpack(pkg: string) {
  if (pkg && pkg !== '?') unpackSuppressArm.add(pkg);
}
export function resumeCaptureArmAfterUnpack(pkg: string) {
  if (pkg) unpackSuppressArm.delete(pkg);
}
export function isCaptureArmSuppressed(pkg: string) {
  return !!pkg && unpackSuppressArm.has(pkg);
}
export function protectCaptureArmAfterUnpack(pkg: string) {
  if (pkg && pkg !== '?') unpackProtectArm.add(pkg);
}
/** Call on agent.hello so a fresh process can auto-arm again. */
export function clearCaptureArmProtect(pkg: string) {
  if (pkg) unpackProtectArm.delete(pkg);
}
export function isCaptureArmProtected(pkg: string) {
  return !!pkg && unpackProtectArm.has(pkg);
}
export function listCaptureArmProtected(): string[] {
  return [...unpackProtectArm];
}
const CAPTURE_ARM_BLOCKED = '本包脱壳后未装钩，请先重启 App（或 force:true）';
function captureArmBlockedReason(pkg: string): string | null {
  if (isCaptureArmSuppressed(pkg)) return '本包正在脱壳，暂不装钩';
  if (isCaptureArmProtected(pkg)) return CAPTURE_ARM_BLOCKED;
  return null;
}

export function startCaptureLoop(sid: string, opts?: { skipArm?: boolean }) {
  if (captureTimers.has(sid)) return; // already streaming
  if (!opts?.skipArm && captureLoopPending.has(sid)) return;
  const pkgNow = sessions.get(sid)?.package ?? '';
  // Unpack owns this process: do not arm hooks or auto-dump (unpack will dump itself).
  if (!opts?.skipArm && isCaptureArmSuppressed(pkgNow)) {
    log(`capture loop skip ${sid} (unpack in progress for ${pkgNow})`);
    return;
  }
  const run = async () => {
    captureLoopPending.delete(sid);
    const pkg = sessions.get(sid)?.package ?? '';
    // How this process loaded us (agent hello): 'jni_onload' = self-load, 'start' = Zygisk.
    const entry = sessions.get(sid)?.entry;
    if (isCaptureArmSuppressed(pkg)) {
      log(`capture_start skip ${sid} (unpack in progress for ${pkg})`);
      return;
    }
    // Refresh scope cache (best-effort) then auto-arm when capture is not force-stopped.
    if (!opts?.skipArm && settings.capture.enabled) {
      try { await scopedApps(); } catch { /* keep prior cache */ }
      if (shouldAutoArmPackage(pkg, entry)) {
        try {
          const verdict = await armCaptureHooks(sid, { ...captureModules() });
          log(`capture_start ${sid} ok=${verdict.ok}`);
        } catch (e) { log('capture_start failed', (e as Error).message); }
      } else {
        log(`capture_start skip ${sid} (package not in scope)`);
      }
    }
    if (!opts?.skipArm && settings.capture.autoDumpDex) {
      autoDumpDex(sid).catch((e) => log(`[capture] autoDumpDex ${sid} 失败:`, (e as Error).message));
    }
    if (captureTimers.has(sid)) return;
    let busy = false;
    let drainErrLogged = false;   // fail-loud once per wedged-drain episode, not every 1.5s tick
    const processDrain = (r: any, now: number) => {
      const pkg = sessions.get(sid)?.package ?? '';
      const announce = (entry: Capture) => {
        const outl = entry.outHex ? entry.outHex.length / 2 : 0;
        broadcast('capture.new', {
          id: entry.id, sessionId: sid, package: pkg, source: entry.source, category: entry.category,
          algo: entry.algo, op: entry.op, func: entry.func, preview: entry.preview, inl: entry.inl, outl,
          hasKey: !!entry.keyHex, tid: entry.tid, ts: entry.ts,
          ...(entry.category === 'crypto' ? { view: cryptoView(entry) } : {}),
        });
      };
      for (const c of (r.jcaptures ?? [])) {
        if (c.in) recentJavaIn.set(c.in, now);
        const hasBody = Number(c.inl) > 0 || Number(c.outl) > 0 || (typeof c.out === 'string' && c.out.length > 0);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, package: pkg, source: 'java', func: javaHook(String(c.op || ''), hasBody), algo: c.algo, op: c.op,
          category: 'crypto',
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.in, preview: hexToPreview(c.in),
          keyHex: c.key || '', ivHex: c.iv || '', outHex: c.out || '',
        };
        if (pushCapture(entry)) announce(entry);
      }
      for (const [k, t] of recentJavaIn) if (now - t > 2000) recentJavaIn.delete(k);
      for (const c of (r.captures ?? [])) {
        if (c.hex && recentJavaIn.has(c.hex)) continue;   // already captured richly at the Java layer
        const { algo, op } = classify(c.func);
        const category = categoryOf(c.func);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, package: pkg, source: 'native', func: c.func, algo, op,
          category,
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.hex, preview: previewForCapture(c.func, c.hex),
          // Symmetric captures carry the key/IV the agent joined at EVP_CipherInit_ex; the Java
          // reporter path has always sent these, the native path only since that join exists.
          ...(c.key ? { keyHex: c.key } : {}), ...(c.iv ? { ivHex: c.iv } : {}),
          ...(c.conn ? { conn: String(c.conn) } : {}),
        };
        if (pushCapture(entry)) announce(entry);
      }
    };
    // One drain implementation for both the polling loop and explicit callers: concurrent requests
    // coalesce on the same promise so two drains can never interleave their processDrain calls.
    let inFlight: Promise<any> | null = null;
    const runDrain = async (): Promise<any> => {
      if (inFlight) return inFlight;
      busy = true;
      inFlight = (async () => {
      try {
        // Drain repeatedly while the agent ring has a backlog, so a burst is pulled out
        // fast (WS-C: keeps drops near zero when the pipeline can keep up). Bounded so one
        // tick can't monopolise the session.
        //
        // ACCOUNT PER DRAIN, not per call. The agent's capture_drain has POP semantics: the
        // records in a response have already left its ring. So the counters for what DID arrive
        // must be written as it arrives - batching them until the loop ends threw away the
        // accounting of every earlier iteration whenever a later `sendCmd` failed, and
        // verify_v22's invariant (emitted+backlog+dropped==seq) then read as a silent loss.
        // A response that never arrives at all is still unaccounted (the agent popped it and
        // the bytes are gone with the socket) - that residue is what `unaccounted` in
        // captureHealth()/the tool replies now names instead of hiding.
        let r: any, drains = 0;
        do {
          r = await sendCmd(sid, 'capture_drain', {}, 8_000);
          const count = r?.count ?? 0;
          // Bookkeeping FIRST: the agent has already popped these records, so our accounting must
          // not depend on our own store-side processing succeeding.
          const prev = capStats.get(sid);
          const emittedAfter = (prev?.emitted ?? 0) + count;
          capStats.set(sid, { seq: r.seq ?? 0, emitted: emittedAfter,
            dropped: r.dropped ?? 0, jdropped: r.jdropped ?? 0, drained: r.drained ?? 0,
            backlog: r.backlog ?? 0, firstDropNs: r.firstDropNs ?? 0, lastDropNs: r.lastDropNs ?? 0,
            complete: r.complete === true, ring: r.ring ?? 0, ts: Date.now(), agentResidual: r.residual ?? null,
            // The window this session can account for starts at its FIRST drain response: the
            // agent's seq/dropped are cumulative over its whole process (and keep counting across
            // a daemon restart), while `emitted` only ever counts what we ingested. The records
            // in that first response were already popped before this snapshot, so they are
            // excluded on both sides - see captureHealth() for the identity that then holds.
            base: prev?.base ?? { seq: r.seq ?? 0, dropped: r.dropped ?? 0, jdropped: r.jdropped ?? 0, drained: r.drained ?? 0, emitted: emittedAfter } });
          processDrain(r, Date.now());
          drains++;
        } while (r && r.backlog > 0 && drains < 60);
        drainErrLogged = false;   // a drain succeeded — clear the failure episode
        // fail-loud: announce the first time this session starts dropping (once per session)
        const now = capStats.get(sid);
        if (now && now.dropped > 0 && !now.announcedDrop) {
          now.announcedDrop = true;
          log(`[capture] session ${sid} DROPPING — ring full: dropped=${now.dropped} seq=${now.seq} (complete:false)`);
        }
      } catch (e) {
        if (!drainErrLogged) { drainErrLogged = true; log(`[capture] drain ${sid} 失败 (静默重试直至恢复):`, (e as Error).message); }
        throw e;
      } finally { busy = false; }
      })();
      try { return await inFlight; } finally { inFlight = null; }
    };
    captureDrainers.set(sid, runDrain);
    const timer = setInterval(async () => {
      if (busy || !sessions.get(sid)?.online) return;
      await runDrain().catch(() => null);   // the loop never propagates: it retries next tick
    }, 1500);
    captureTimers.set(sid, timer);
  };
  if (opts?.skipArm) {
    void run();
    return;
  }
  captureLoopPending.add(sid);
  setTimeout(() => { void run(); }, 1200);
}

// Enumerate the app's DEX files, dump each, and say what each one IS.
//
// "14 dex dumped" is not an answer. A packed target hands you a carrier whose header parses but
// which holds the packer's shell rather than the app's code (see classifyDexArtifact); reporting a
// count alone makes that one look exactly like the real ones. Each entry is therefore classified
// from its own class/method table and indexed in the same pass, so the dump is immediately
// searchable and the carrier is named instead of having to be spotted by hand.
export async function dumpAllDex(sid: string, opts?: {
  tag?: string;
  notePrefix?: string;
  onSaved?: (entry: Record<string, unknown>) => void | Promise<void>;
}) {
  const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
  const list = Array.isArray(r.dexfiles) ? r.dexfiles : [];
  if (!list.length) throw new Error('no loaded DexFile found (target may not have Java dex loaded yet)');
  const regions = await loadMaps(sid);
  const dexes: any[] = [];
  let dumped = 0, deduped = 0, failed = 0, indexed = 0, indexReused = 0, carriers = 0, realBytes = 0;
  for (const d of list) {
    const begin = String(d.begin ?? '');
    const size = Number(d.size ?? 0);
    const format = d.format ?? 'dex';
    if (!begin || !size || size > (256 << 20)) {
      failed++;
      dexes.push({ begin, size, format, saved: false, error: 'invalid address/size' });
      continue;
    }
    const readable = contiguousReadable(regions, begin, size);
    if (readable !== size) {
      failed++;
      dexes.push({ begin, size, readable, format, saved: false, status: 'short' });
      continue;
    }
    try {
      const entry = await unpackOneDex(sid, begin, size, {
        tag: opts?.tag,
        note: opts?.notePrefix,
      });
      if (!entry.saved) { failed++; dexes.push({ ...entry, format }); continue; }
      dumped++; if (entry.dedup) deduped++;
      if (entry.carrier) carriers++; else realBytes += Number(entry.bytes) || 0;
      if (entry.classes !== undefined) indexed++;
      const row = { ...entry, format, version: d.version ?? 0, confidence: d.confidence ?? 0 };
      dexes.push(row);
      if (opts?.onSaved) await opts.onSaved(row);
    } catch (e) {
      failed++;
      dexes.push({ begin, size, format, saved: false, error: (e as Error).message });
    }
  }
  const carrierList = dexes.filter((x) => x.carrier)
    .map((x) => ({ begin: x.begin, size: x.size, classes: x.classes, sha256: x.sha256, shape: x.shape }));
  // "Real" means classification SAID so (`carrier === false`). Counting `dexes.length - carriers`
  // instead also counted dexes that never got classified at all — a dump that errored, or an index
  // write that threw — so a run where 3 of 4 dexes failed still reported realDexCount: 4 while
  // realBytes only summed the one that worked. Two numbers that must agree, disagreeing, is the
  // tell. `unclassified` names the remainder so no failure is silently absorbed into a plausible count.
  const realCount = dexes.filter((x) => x.carrier === false).length;
  const unclassified = dexes.filter((x) => x.classifyError || x.error).length;
  const firstClassifyError = dexes.find((x) => x.classifyError)?.classifyError;
  return {
    ok: true, session: sid,
    count: dexes.length, dumped, deduped, failed,
    dexCount: dexes.length, realDexCount: realCount, carrierCount: carriers,
    unclassified, ...(firstClassifyError ? { classifyError: firstClassifyError } : {}),
    realBytes, totalBytes: dexes.reduce((a, x) => a + (Number(x.bytes) || 0), 0),
    index: { built: indexed, reused: indexReused },
    carriers: carrierList,
    dexes,
  };
}

// Auto-dump on connect uses the same one-click primitive; per-dex failures are summarized.
export async function autoDumpDex(sid: string) {
  const r = await dumpAllDex(sid);
  log(`[capture] autoDumpDex ${sid}: ${r.dumped}/${r.count} dex (dedup ${r.deduped}, failed ${r.failed})`);
}

/** Online agent sessions for one package (main process first). */
export function onlineSessionsForPackage(pkg: string): AgentSession[] {
  const rows = [...sessions.values()].filter((s) => s.online && s.package === pkg);
  const main = preferMainProcess(rows);
  if (!main) return rows;
  return [main, ...rows.filter((s) => s.sessionId !== main.sessionId)];
}

/**
 * One-click unpack for a **package**: cold-start the app via adb (unless launch:false),
 * wait for agents, dump every online process, dedupe by SHA-256, pack one ZIP.
 */
export async function runUnpackBundle(opts: {
  package?: string; session?: string; launch?: boolean;
  /** When true, always force-stop + relaunch. Default: reuse online sessions if any. */
  forceRestart?: boolean;
  launchTimeoutMs?: number; settleMs?: number;
}) {
  const sidHint = opts.session ? pickSid(opts.session) : undefined;
  const pkg = (opts.package && opts.package !== '?')
    ? opts.package
    : (sidHint ? sessionPackage(sidHint) : '');
  if (!pkg || pkg === '?') {
    return { ok: false, error: '需要 package 或在线 session', package: pkg || null, bundle: null, included: [] };
  }

  // Must be set BEFORE cold start: hello races startCaptureLoop and would otherwise
  // install crypto GOT hooks that kill SecNeo/Bangcle processes (学习通 2026-10-20).
  suppressCaptureArmForUnpack(pkg);
  let launchInfo: {
    ok: boolean; mode: string; error?: string; waitedMs?: number; reusedOnline?: boolean;
  } | null = null;

  try {
  const alreadyOnline = onlineSessionsForPackage(pkg);
  const wantLaunch = opts.launch !== false;
  const doLaunch = wantLaunch && (opts.forceRestart === true || alreadyOnline.length === 0);
  if (wantLaunch && !doLaunch) {
    launchInfo = {
      ok: true, mode: 'reuse-online', reusedOnline: true,
      waitedMs: 0,
    };
    log(`[unpack] ${pkg}: reuse ${alreadyOnline.length} online session(s), skip force-stop`);
  } else if (doLaunch) {
    const sinceMs = Date.now();
    const started = await coldStartPackage(pkg);
    if (!started.ok) {
      return {
        ok: false, error: started.error || '启动目标应用失败', package: pkg,
        launch: started, bundle: null, included: [], processes: [],
      };
    }
    const waited = await waitForFreshSessions(
      () => onlineSessionsForPackage(pkg),
      {
        sinceMs,
        timeoutMs: opts.launchTimeoutMs ?? 45_000,
        // SecNeo needs a bit longer for real dex to finish loading after splash.
        settleMs: opts.settleMs ?? 4_000,
      },
    );
    launchInfo = { ok: waited.ok, mode: started.mode, waitedMs: waited.waitedMs, error: waited.error };
    if (!waited.ok) {
      return {
        ok: false, error: waited.error || '等待注入超时', package: pkg,
        launch: launchInfo, bundle: null, included: [], processes: [],
      };
    }
  }

  const targets = onlineSessionsForPackage(pkg);
  if (!targets.length) {
    return {
      ok: false, error: '目标应用没有在线进程', package: pkg,
      launch: launchInfo, bundle: null, included: [], processes: [],
    };
  }

  const runId = `u_${Date.now().toString(36)}`;
  const runDir = join(DATA_DIR, 'packages', pkg, 'unpack', runId);
  mkdirSync(join(runDir, 'dex'), { recursive: true });
  const sideEffects = {
    captureArmSkipped: true,
    forceStopped: !!(launchInfo && launchInfo.mode !== 'reuse-online'),
    processCount: targets.length,
    launchMode: launchInfo?.mode ?? (doLaunch ? 'cold' : 'reuse-online'),
  };
  broadcast('unpack.start', { runId, package: pkg, dir: runDir, launch: launchInfo, sideEffects });

  const files: { name: string; data: Buffer }[] = [];
  const included: {
    name: string; sha256: string; size: number; carrier?: boolean;
    process: string; pid: number; runId: string;
  }[] = [];
  const seenSha = new Set<string>();
  const processes: {
    session: string; process: string; pid: number; folder: string;
    dumped: number; failed: number; realDexCount: number; carrierCount: number; error?: string;
  }[] = [];
  let dumped = 0, failed = 0, realDexCount = 0, carrierCount = 0;
  let seq = 0;

  for (const sess of targets) {
    const folder = processFolderLabel(sess.process, pkg);
    mkdirSync(join(runDir, 'dex', folder), { recursive: true });
    let report: Awaited<ReturnType<typeof dumpAllDex>>;
    try {
      report = await dumpAllDex(sess.sessionId, {
        tag: 'unpack-dex',
        notePrefix: `${folder} · ${runId}`,
        onSaved: async (entry) => {
          const sha = String(entry.sha256 ?? '');
          if (!sha || seenSha.has(sha)) return;
          const meta = dumps.get(sha);
          const srcPath = meta?.path || String(entry.path ?? '');
          if (!srcPath || !existsSync(srcPath)) return;
          seenSha.add(sha);
          seq++;
          const label = entry.carrier === true ? 'carrier' : 'classes';
          const baseName = `${String(seq).padStart(2, '0')}_${label}_${sha.slice(0, 8)}.dex`;
          const rel = `dex/${folder}/${baseName}`;
          const dest = join(runDir, rel);
          try { copyFileSync(srcPath, dest); } catch { /* still keep captures/ copy */ }
          const size = Number(entry.bytes) || meta?.size || 0;
          const note = `${folder} · ${label}${entry.classes != null ? ` · ${entry.classes} classes` : ''}`;
          const data = readFileSync(existsSync(dest) ? dest : srcPath);
          files.push({ name: rel, data });
          included.push({
            name: rel, sha256: sha, size, carrier: entry.carrier === true,
            process: sess.process, pid: sess.pid, runId,
          });
          broadcast('unpack.dex', {
            runId, package: pkg, kind: 'dex',
            sha256: sha, size, name: rel, note, carrier: entry.carrier === true,
            process: sess.process, pid: sess.pid, folder, seq,
            capturedAt: Date.now(), path: existsSync(dest) ? dest : srcPath,
          });
        },
      });
    } catch (e) {
      failed++;
      processes.push({
        session: sess.sessionId, process: sess.process, pid: sess.pid, folder,
        dumped: 0, failed: 1, realDexCount: 0, carrierCount: 0, error: (e as Error).message,
      });
      broadcast('unpack.progress', {
        runId, package: pkg, kind: 'process-error',
        process: sess.process, pid: sess.pid, error: (e as Error).message,
      });
      continue;
    }
    dumped += Number(report.dumped) || 0;
    failed += Number(report.failed) || 0;
    realDexCount += Number(report.realDexCount) || 0;
    carrierCount += Number(report.carrierCount) || 0;
    processes.push({
      session: sess.sessionId, process: sess.process, pid: sess.pid, folder,
      dumped: Number(report.dumped) || 0, failed: Number(report.failed) || 0,
      realDexCount: Number(report.realDexCount) || 0, carrierCount: Number(report.carrierCount) || 0,
    });
  }

  if (!files.length) {
    broadcast('unpack.done', {
      runId, package: pkg, ok: false, error: '没有成功保存的 DEX', included: [],
      sideEffects, captureNote: '本包未装钩，重启后再捕',
    });
    return {
      ok: false, error: '没有成功保存的 DEX，无法打包',
      package: pkg, runId, dir: runDir, launch: launchInfo, processes, dumped, failed, realDexCount, carrierCount,
      bundle: null, included: [],
      didSkipAutoArm: true,
      captureNote: '本包未装钩，重启后再捕',
    };
  }

  const primary = targets[0];
  const manifest = {
    package: pkg,
    runId,
    dir: runDir,
    capturedAt: Date.now(),
    launch: launchInfo,
    processes,
    dumped, failed, realDexCount, carrierCount,
    files: included,
  };
  const manifestPath = join(runDir, 'manifest.json');
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  files.push({ name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8') });
  const zip = buildStoredZip(files);
  const zipPath = join(runDir, 'bundle.zip');
  writeFileSync(zipPath, zip);
  const { meta, dedup } = await persistArtifact(zip, {
    source: 'unpack', addr: '', tag: 'unpack-bundle', sessionId: primary.sessionId, package: pkg,
  }, {
    note: `${included.length} dex · ${processes.length} 进程 · real ${realDexCount} · carrier ${carrierCount} · ${runId}`,
  });
  const done = {
    runId, package: pkg, ok: true as const,
    dexCount: included.length, processes: processes.length,
    bundle: { sha256: meta.sha256, size: meta.size },
    dir: runDir,
  };
  broadcast('unpack.done', {
    ...done,
    sideEffects,
    captureNote: '本包未装钩，重启后再捕',
  });
  return {
    ok: true, package: pkg, session: primary.sessionId, runId, dir: runDir,
    launch: launchInfo, processes, dumped, failed, realDexCount, carrierCount, included,
    didSkipAutoArm: true,
    sideEffects,
    captureNote: '本包未装钩，重启后再捕',
    bundle: {
      sha256: meta.sha256, size: meta.size, path: meta.path, kind: meta.kind,
      dedup, capturedAt: meta.capturedAt, note: meta.note,
    },
  };
  } finally {
    // Clear in-flight suppress. Keep protect so settings / MCP cannot re-arm this live process
    // (SecNeo). Next agent.hello clears protect so a real restart can auto-arm again.
    resumeCaptureArmAfterUnpack(pkg);
    protectCaptureArmAfterUnpack(pkg);
  }
}

const UNPACK_RUN_RE = /\b(u_[a-z0-9]+)\b/i;

function unpackRunIdOf(note?: string, path?: string): string | null {
  const fromNote = UNPACK_RUN_RE.exec(String(note || ''));
  if (fromNote) return fromNote[1];
  const fromPath = UNPACK_RUN_RE.exec(String(path || ''));
  return fromPath ? fromPath[1] : null;
}

/** Flat dump rows (legacy). Prefer listUnpackRuns for product UI. */
export function listUnpackBundles(pkg?: string) {
  const rows = [...dumps.values()].filter((d) => {
    if (pkg && d.package !== pkg) return false;
    if (d.kind === 'zip' && d.tag === 'unpack-bundle') return true;
    if (d.tag === 'unpack-dex') return true;
    return false;
  });
  rows.sort((a, b) => (b.capturedAt || 0) - (a.capturedAt || 0));
  return rows.map((d) => ({
    sha256: d.sha256, package: d.package, size: d.size, capturedAt: d.capturedAt,
    note: d.note || (d.tag === 'unpack-bundle' ? '脱壳包 zip' : 'DEX'),
    path: d.path, kind: d.kind, tag: d.tag,
    runId: unpackRunIdOf(d.note, d.path) || undefined,
  }));
}

export interface UnpackRunFile {
  sha256: string; name: string; size: number; carrier?: boolean; note?: string; path?: string;
}
export interface UnpackRun {
  runId: string; package: string; capturedAt: number;
  dexCount: number; size: number; processes?: number;
  bundleSha256?: string; note?: string;
  files: UnpackRunFile[];
}

/** One row per one-click unpack run; files[] are the DEX inside. */
export function listUnpackRuns(pkg?: string): UnpackRun[] {
  const byRun = new Map<string, UnpackRun>();

  const ensure = (runId: string, packageName: string, capturedAt: number): UnpackRun => {
    let run = byRun.get(runId);
    if (!run) {
      run = {
        runId, package: packageName, capturedAt,
        dexCount: 0, size: 0, files: [],
      };
      byRun.set(runId, run);
    } else if (capturedAt > run.capturedAt) {
      run.capturedAt = capturedAt;
    }
    return run;
  };

  // Authoritative: on-disk manifest from each unpack/<runId>/
  const pkgs = pkg
    ? [pkg]
    : [...new Set([...dumps.values()].map((d) => d.package).filter((p) => p && p !== '?'))];
  for (const p of pkgs) {
    const root = join(DATA_DIR, 'packages', p, 'unpack');
    if (!existsSync(root)) continue;
    let dirs: string[] = [];
    try { dirs = readdirSync(root); } catch { continue; }
    for (const name of dirs) {
      if (!name.startsWith('u_')) continue;
      const manifestPath = join(root, name, 'manifest.json');
      if (!existsSync(manifestPath)) continue;
      try {
        const m = JSON.parse(readFileSync(manifestPath, 'utf8'));
        const runId = String(m.runId || name);
        const run = ensure(runId, p, Number(m.capturedAt) || 0);
        run.processes = Array.isArray(m.processes) ? m.processes.length : run.processes;
        const files = Array.isArray(m.files) ? m.files : [];
        for (const f of files) {
          const sha = String(f.sha256 || '');
          if (!sha || run.files.some((x) => x.sha256 === sha)) continue;
          run.files.push({
            sha256: sha,
            name: String(f.name || sha.slice(0, 8) + '.dex'),
            size: Number(f.size) || 0,
            carrier: f.carrier === true,
            note: undefined,
            path: existsSync(join(root, name, String(f.name || ''))) ? join(root, name, String(f.name || '')) : undefined,
          });
        }
        run.dexCount = run.files.length;
      } catch { /* skip bad manifest */ }
    }
  }

  for (const d of dumps.values()) {
    if (pkg && d.package !== pkg) continue;
    const runId = unpackRunIdOf(d.note, d.path);
    if (!runId) {
      // Orphan single-dex / zip without run id — each becomes its own pseudo-run.
      if (d.tag === 'unpack-bundle' || d.tag === 'unpack-dex') {
        const id = `legacy_${d.sha256.slice(0, 10)}`;
        const run = ensure(id, d.package, d.capturedAt || 0);
        if (d.tag === 'unpack-bundle' || d.kind === 'zip') {
          run.bundleSha256 = d.sha256;
          run.size = d.size || run.size;
          run.note = d.note;
        } else if (!run.files.some((x) => x.sha256 === d.sha256)) {
          run.files.push({
            sha256: d.sha256, name: basename(d.path || '') || d.sha256.slice(0, 8) + '.dex',
            size: d.size || 0, note: d.note, path: d.path,
          });
          run.dexCount = run.files.length;
          if (!run.bundleSha256) run.size = run.files.reduce((n, f) => n + (f.size || 0), 0);
        }
      }
      continue;
    }
    const run = ensure(runId, d.package, d.capturedAt || 0);
    if (d.tag === 'unpack-bundle' || d.kind === 'zip') {
      run.bundleSha256 = d.sha256;
      run.size = d.size || run.size;
      run.note = d.note;
      const m = /(\d+)\s*dex/i.exec(String(d.note || ''));
      if (m) run.dexCount = Math.max(run.dexCount, Number(m[1]) || 0);
      const pm = /(\d+)\s*进程/.exec(String(d.note || ''));
      if (pm) run.processes = Number(pm[1]) || run.processes;
    } else if (d.tag === 'unpack-dex') {
      if (!run.files.some((x) => x.sha256 === d.sha256)) {
        run.files.push({
          sha256: d.sha256,
          name: basename(d.path || '') || d.sha256.slice(0, 8) + '.dex',
          size: d.size || 0,
          carrier: /carrier/i.test(String(d.note || '')),
          note: d.note,
          path: d.path,
        });
      }
      run.dexCount = Math.max(run.dexCount, run.files.length);
      if (!run.bundleSha256) run.size = run.files.reduce((n, f) => n + (f.size || 0), 0);
    }
  }

  const runs = [...byRun.values()];
  for (const run of runs) {
    run.files.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    run.dexCount = Math.max(run.dexCount, run.files.length);
    if (!run.size) run.size = run.files.reduce((n, f) => n + (f.size || 0), 0);
  }
  runs.sort((a, b) => (b.capturedAt || 0) - (a.capturedAt || 0));
  return runs;
}

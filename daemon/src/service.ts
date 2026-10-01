// service.ts — ADH Daemon service layer: agent-command transport + dump engine + capture ops.
// Imported by mcp.ts (MCP handlers) and index.ts (REST routes + agent TCP + boot).
// Imports ONLY from state.ts (+ dex.ts pure layer + dex_index.ts for artifact retention +
// node builtins) — no circular refs.
import { readFile } from 'node:fs/promises';
import { writeFileSync, existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  frameJson, agentSockets, pending, nextCmdId, sessions, dumps, log,
  captureTimers, captureModules, settings, recentJavaIn,
  pushCapture, broadcast, hexToPreview, classify, categoryOf, capStats, CAPTURES,
  pruneArtifacts,
} from './state.ts';
import type { AgentSession, DumpMeta, MapsRegion, Capture } from './state.ts';
// dex_index.ts imports state.ts, not this file, so this edge cannot form a cycle; it is here so
// artifact retention can drop the index row of a dex it deletes.
import { deleteDexDocument, ensureDexIndex } from './dex_index.ts';
import { classifyDexArtifact } from './dex.ts';

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
  const loads: { vaddr: bigint; memsz: bigint }[] = [];
  for (let i = 0; i < phnum; i++) {
    const p = phBuf.subarray(i * phentsize);
    if (p.readUInt32LE(0) !== 1) continue;              // PT_LOAD
    const vaddr = p.readBigUInt64LE(16), memsz = p.readBigUInt64LE(40);
    loads.push({ vaddr, memsz });
    if (vaddr + memsz > imgSize) imgSize = vaddr + memsz;
  }
  if (imgSize === 0n || imgSize > 512n * 1024n * 1024n) throw new Error('implausible image size');
  const image = Buffer.alloc(Number(imgSize));

  // pass 2: copy each PT_LOAD's memory to file offset == vaddr. A segment that does not arrive
  // in full is an error: Buffer.alloc already zero-filled the image, so a short read would look
  // like a legitimate zero region and the "reconstructed" .so would be quietly wrong.
  for (const { vaddr, memsz } of loads) {
    const seg = await readMemEx(sid, base + vaddr, Number(memsz));
    if (!seg.complete) {
      throw new Error(`PT_LOAD at +0x${vaddr.toString(16)} short read: ${seg.read}/${seg.requested} bytes`
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
  dumps.set(sha, meta);
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
  dumps.set(sha, meta);
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
  if (s) s.captureHooks = r;
}

// Apply the capture.enabled toggle to already-connected sessions (start/stop the hooks).
export async function applyCaptureEnabled() {
  for (const s of sessions.values()) {
    if (!s.online) continue;
    const cmd = settings.capture.enabled ? 'capture_start' : 'capture_stop';
    const args = settings.capture.enabled ? captureModules() : {};
    // Fail loud: a live session that rejects the toggle means the panel and the target disagree.
    try { recordCaptureHooks(s.sessionId, await sendCmd(s.sessionId, cmd, args, 8_000)); }
    catch (e) { log(`[settings] ${cmd} 会话 ${s.sessionId} 失败:`, (e as Error).message); }
  }
}

// ---- capture_start / capture_stop (the tools' one implementation) --------------------------
// The agent answers capture_start with ok:true unconditionally and 20+ per-symbol install
// counters: `ok:true` therefore says "the command ran", never "the hooks are live". The
// daemon derives the verdict here, once, so the MCP tool, any future REST route and the
// settings toggle cannot disagree about what "on" means.
const CRYPTO_COUNTERS = ['evp', 'digest', 'hmac', 'digestSign', 'sslWrite', 'sslRead'];
const NESTED_COUNTERS: [string, string[]][] = [
  ['pkey', ['sign', 'verify', 'encrypt', 'decrypt']],
  ['aead', ['seal', 'open']],
  ['digestSignVerify', ['signInit', 'verifyInit', 'signFinal', 'verifyUpdate', 'verifyFinal']],
  ['file', ['open', 'openat', 'read', 'write', 'syscall', 'readChk', 'writeChk']],
  ['sys', ['ptrace', 'access', 'prop']],
];

/** Flatten an install reply into {name: count} for exactly the symbol sets that were requested. */
export function captureInstallCounters(reply: any): { name: string; value: number }[] {
  const out: { name: string; value: number }[] = [];
  if (!reply || typeof reply !== 'object') return out;
  for (const k of CRYPTO_COUNTERS) if (k in reply) out.push({ name: k, value: Number(reply[k]) || 0 });
  for (const [group, keys] of NESTED_COUNTERS) {
    // The file/sys hook sets are only installed when a module was named for them; when the
    // module is empty the agent does not touch those slots at all and its zeros mean nothing.
    if (group === 'file' && !String(reply.fileModule ?? '')) continue;
    if (group === 'sys' && !String(reply.sysModule ?? '')) continue;
    const g = reply[group];
    if (!g || typeof g !== 'object') continue;
    for (const k of keys) if (k in g) out.push({ name: `${group}.${k}`, value: Number(g[k]) || 0 });
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
export async function setCapture(sid: string, on: boolean, modules?: { cryptoModule?: string; fileModule?: string; sysModule?: string }): Promise<CaptureToggle> {
  const mods = { ...captureModules() };
  // Only keys the caller actually passed override the settings defaults (an explicit undefined
  // must not blank a module out - that would silently turn "hook this module" into "scan all").
  for (const k of ['cryptoModule', 'fileModule', 'sysModule'] as const) {
    const v = modules?.[k];
    if (typeof v === 'string' && v.length) mods[k] = v;
  }
  if (on) {
    if (!captureTimers.has(sid)) startCaptureLoop(sid);   // no drain loop = nothing would stream
    // RE-ARM FROM A CLEAN SLATE. adh_got_replace matches a GOT slot by VALUE, so an install that
    // runs while our own wrapper already sits in the slot reports 0 for it - indistinguishable
    // from "this symbol is not imported". Measured on the sandbox: a repeat capture_start said
    // 14/27, a stop-then-start said 23/27, and the 4 remaining zeros are genuinely absent from
    // libjavacore.so. So the verdict is only worth printing if the install started from the
    // original pointers: drain (never lose what the ring holds), stop, then install.
    const drained = await drainSession(sid);
    try { await sendCmd(sid, 'capture_stop', {}, 8_000); } catch { /* not armed: nothing to restore */ }
    const reply = await sendCmd(sid, 'capture_start', mods, 15_000);
    recordCaptureHooks(sid, reply);
    const counters = captureInstallCounters(reply);
    const notInstalled = counters.filter((c) => c.value <= 0).map((c) => c.name);
    const installed = counters.length - notInstalled.length;
    const scannedAll = !String(mods.cryptoModule ?? '');
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

// Install persistent hooks on connect, then poll capture_drain and stream each new record
// into the store + over WS. Also auto-dump the app's DEX files so the panel can download
// them. Mirrors the ios-decrypt-helper flow (hooks stay live, events fill the panel).
let capSeq = 0;   // service-local — ++'d here; can't reassign an imported binding (ESM)

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

export function startCaptureLoop(sid: string) {
  setTimeout(async () => {
    if (settings.capture.enabled) {
      try { recordCaptureHooks(sid, await sendCmd(sid, 'capture_start', captureModules(), 15_000)); log(`capture_start ${sid}`); } catch (e) { log('capture_start failed', (e as Error).message); }
    }
    if (settings.capture.autoDumpDex) autoDumpDex(sid).catch((e) => log(`[capture] autoDumpDex ${sid} 失败:`, (e as Error).message));
    if (captureTimers.has(sid)) return;
    let busy = false;
    let drainErrLogged = false;   // fail-loud once per wedged-drain episode, not every 1.5s tick
    const processDrain = (r: any, now: number) => {
      for (const c of (r.jcaptures ?? [])) {
        if (c.in) recentJavaIn.set(c.in, now);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, source: 'java', func: c.op, algo: c.algo, op: c.op,
          category: 'crypto',
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.in, preview: hexToPreview(c.in),
          keyHex: c.key || '', ivHex: c.iv || '', outHex: c.out || '',
        };
        if (pushCapture(entry))
          broadcast('capture.new', { id: entry.id, sessionId: sid, source: 'java', category: entry.category, algo: entry.algo, op: entry.op, preview: entry.preview, inl: entry.inl, ts: entry.ts });
      }
      for (const [k, t] of recentJavaIn) if (now - t > 2000) recentJavaIn.delete(k);
      for (const c of (r.captures ?? [])) {
        if (c.hex && recentJavaIn.has(c.hex)) continue;   // already captured richly at the Java layer
        const { algo, op } = classify(c.func);
        const category = categoryOf(c.func);
        const entry: Capture = {
          id: ++capSeq, sessionId: sid, source: 'native', func: c.func, algo, op,
          category,
          inl: c.inl, tid: c.tid, tsNs: c.tsNs, ts: now,
          hex: c.hex, preview: hexToPreview(c.hex),
        };
        if (pushCapture(entry))
          broadcast('capture.new', { id: entry.id, sessionId: sid, source: 'native', category, algo, op, preview: entry.preview, inl: entry.inl, ts: entry.ts });
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
  }, 1200);
}

// Enumerate the app's DEX files, dump each, and say what each one IS.
//
// "14 dex dumped" is not an answer. A packed target hands you a carrier whose header parses but
// which holds the packer's shell rather than the app's code (see classifyDexArtifact); reporting a
// count alone makes that one look exactly like the real ones. Each entry is therefore classified
// from its own class/method table and indexed in the same pass, so the dump is immediately
// searchable and the carrier is named instead of having to be spotted by hand.
export async function dumpAllDex(sid: string) {
  const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
  const list = Array.isArray(r.dexfiles) ? r.dexfiles : [];
  if (!list.length) throw new Error('no loaded DexFile found (target may not have Java dex loaded yet)');
  const dexes: any[] = [];
  let dumped = 0, deduped = 0, failed = 0, indexed = 0, indexReused = 0, carriers = 0, realBytes = 0;
  for (const d of list) {
    const begin = String(d.begin ?? '');
    const size = Number(d.size ?? 0);
    if (!begin || !size || size > (256 << 20)) {
      failed++;
      dexes.push({ begin, size, format: d.format ?? 'dex', error: 'invalid address/size' });
      continue;
    }
    try {
      const { meta, dedup } = await dumpRegion(sid, begin.replace(/^0x/, ''), size, 'dex-all');
      dumped++; if (dedup) deduped++;
      const entry: any = { begin, size, format: d.format ?? 'dex', version: d.version ?? 0,
        confidence: d.confidence ?? 0, sha256: meta.sha256, bytes: meta.size, dedup, path: meta.path };
      // Classify + index from the stored bytes; a dex that will not parse is reported on its own
      // entry rather than failing the run (the others are still worth having).
      try {
        const buf = await readFile(meta.path);
        const doc = ensureDexIndex(buf);
        indexed++; if (doc.cached) indexReused++;
        const shape = classifyDexArtifact(buf.length, doc.counts?.classes ?? 0, doc.counts?.methods ?? 0);
        Object.assign(entry, {
          classes: shape.classes, methods: shape.methods, bytesPerClass: shape.bytesPerClass,
          carrier: shape.carrier, shape: shape.reason,
        });
        if (shape.carrier) carriers++; else realBytes += meta.size;
      } catch (e) { entry.classifyError = (e as Error).message; }
      dexes.push(entry);
    } catch (e) {
      failed++;
      dexes.push({ begin, size, format: d.format ?? 'dex', error: (e as Error).message });
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

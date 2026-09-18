// service.ts — ADH Daemon service layer: agent-command transport + dump engine + capture ops.
// Imported by mcp.ts (MCP handlers) and index.ts (REST routes + agent TCP + boot).
// Imports ONLY from state.ts (+ dex.ts pure layer + node builtins) — no circular refs.
import { readFile } from 'node:fs/promises';
import { writeFileSync, existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  frameJson, agentSockets, pending, nextCmdId, sessions, dumps, log,
  capturePaused, captureTimers, captureModules, settings, recentJavaIn,
  pushCapture, broadcast, hexToPreview, classify, categoryOf, capStats, CAPTURES,
} from './state.ts';
import type { AgentSession, DumpMeta, MapsRegion, Capture } from './state.ts';

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

// Read [addr, addr+size) from the target via chunked agent reads. Stops on short read.
export async function readMem(sid: string, addr: bigint, size: number): Promise<Buffer> {
  const CHUNK = 1 << 20;
  const parts: Buffer[] = [];
  let a = addr, remaining = size;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: a.toString(16), size: want }, 20_000);
    if (!r.ok) break;
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    a += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) break;
  }
  return Buffer.concat(parts);
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

  // pass 2: copy each PT_LOAD's memory to file offset == vaddr
  for (const { vaddr, memsz } of loads) {
    const seg = await readMem(sid, base + vaddr, Number(memsz));
    seg.copy(image, Number(vaddr));
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

// Dump [addr, addr+size) by orchestrating chunked agent reads, then sha256 + dedup + persist.
export async function dumpRegion(sid: string, addrHex: string, size: number, tag: string): Promise<{ meta: DumpMeta; dedup: boolean }> {
  const CHUNK = 1 << 20;                          // matches agent per-read cap
  let addr = BigInt('0x' + addrHex);
  const parts: Buffer[] = [];
  let remaining = size;
  while (remaining > 0) {
    const want = Math.min(CHUNK, remaining);
    const r = await sendCmd(sid, 'read', { addr: addr.toString(16), size: want }, 20_000);
    if (!r.ok) { if (parts.length) break; throw new Error(`read failed @0x${addr.toString(16)}: ${r.error}`); }
    const b = Buffer.from(r.b64, 'base64');
    parts.push(b);
    addr += BigInt(b.length);
    remaining -= b.length;
    if (b.length < want) break;                   // short read (unreadable tail)
  }
  const buf = Buffer.concat(parts);
  const sha = createHash('sha256').update(buf).digest('hex');
  const existing = dumps.get(sha);
  if (existing) return { meta: existing, dedup: true };
  const s = sessions.get(sid);
  const kind = inferKind(buf);
  const path = join(CAPTURES, `${sha.slice(0, 16)}.${kind}.bin`);
  if (!existsSync(path)) await writeFile(path, buf);
  const meta: DumpMeta = {
    sha256: sha, size: buf.length, source: 'region', addr: addrHex, tag,
    sessionId: sid, package: s?.package ?? '?', capturedAt: Date.now(), path, kind,
  };
  dumps.set(sha, meta);
  broadcast('dump.new', meta);
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

export async function withCaptureSuspended<T>(sid: string, fn: () => Promise<T>): Promise<T> {
  const wasOn = captureTimers.has(sid);
  if (wasOn) {
    capturePaused.add(sid);
    // fail-loud: if stop fails the probe patches a slot the persistent hook still holds — visible, not silent
    try { recordCaptureHooks(sid, await sendCmd(sid, 'capture_stop', {}, 8_000)); }
    catch (e) { log(`[capture] suspend: capture_stop ${sid} 失败 — 探针将在持久 hook 仍占的槽上安装:`, (e as Error).message); }
  }
  try { return await fn(); }
  finally {
    if (wasOn) {
      // fail-loud: a failed resume leaves continuous capture dead — must not vanish silently
      try { recordCaptureHooks(sid, await sendCmd(sid, 'capture_start', captureModules(), 8_000)); }
      catch (e) { log(`[capture] resume: capture_start ${sid} 失败 — 持续捕获已停，需手动重启:`, (e as Error).message); }
      capturePaused.delete(sid);
    }
  }
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
        let r: any, drains = 0, emittedTick = 0;
        do {
          r = await sendCmd(sid, 'capture_drain', {}, 8_000);
          emittedTick += (r?.count ?? 0);
          processDrain(r, Date.now());
          drains++;
        } while (r && r.backlog > 0 && drains < 60);
        drainErrLogged = false;   // a drain succeeded — clear the failure episode
        if (r) {
          const prev = capStats.get(sid);
          capStats.set(sid, { seq: r.seq ?? 0, emitted: (prev?.emitted ?? 0) + emittedTick,
            dropped: r.dropped ?? 0, jdropped: r.jdropped ?? 0,
            backlog: r.backlog ?? 0, firstDropNs: r.firstDropNs ?? 0, lastDropNs: r.lastDropNs ?? 0,
            complete: r.complete === true, ring: r.ring ?? 0, ts: Date.now() });
          // fail-loud: announce the first time this session starts dropping
          if ((r.dropped ?? 0) > 0 && (!prev || prev.dropped === 0))
            log(`[capture] session ${sid} DROPPING — ring full: dropped=${r.dropped} seq=${r.seq} (complete:false)`);
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
      if (busy || capturePaused.has(sid) || !sessions.get(sid)?.online) return;
      await runDrain().catch(() => null);   // the loop never propagates: it retries next tick
    }, 1500);
    captureTimers.set(sid, timer);
  }, 1200);
}

// Enumerate the app's DEX files and dump each so it's downloadable from the panel.
export async function dumpAllDex(sid: string) {
  const r = await sendCmd(sid, 'art_dexfiles', {}, 30_000);
  const list = Array.isArray(r.dexfiles) ? r.dexfiles : [];
  if (!list.length) throw new Error('no loaded DexFile found (target may not have Java dex loaded yet)');
  const dexes: any[] = [];
  let dumped = 0, deduped = 0, failed = 0;
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
      dexes.push({ begin, size, format: d.format ?? 'dex', version: d.version ?? 0, confidence: d.confidence ?? 0,
        sha256: meta.sha256, bytes: meta.size, dedup, path: meta.path });
    } catch (e) {
      failed++;
      dexes.push({ begin, size, format: d.format ?? 'dex', error: (e as Error).message });
    }
  }
  return { ok: true, session: sid, count: dexes.length, dumped, deduped, failed, dexes };
}

// Auto-dump on connect uses the same one-click primitive; per-dex failures are summarized.
export async function autoDumpDex(sid: string) {
  const r = await dumpAllDex(sid);
  log(`[capture] autoDumpDex ${sid}: ${r.dumped}/${r.count} dex (dedup ${r.deduped}, failed ${r.failed})`);
}

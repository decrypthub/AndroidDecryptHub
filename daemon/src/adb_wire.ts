// 直连 adb server(5037) 的协议客户端 —— 参照 frida-core/src/adb.vala 的模型。
// 硬约束：设备操作全部是 5037 上的协议帧，本进程内禁止 spawn/execFile('adb')。
// 每起一个 adb 进程 Windows 都要做一次 USB 枚举；轮询叠加曾把共享控制器上的 HID 饿死。

import net from 'node:net';
import { Duplex } from 'node:stream';

const ADB_PORT = Number(process.env.ANDROID_ADB_SERVER_PORT || process.env.ADH_ADB_SERVER_PORT || 5037);
const ADB_ADDR = process.env.ANDROID_ADB_SERVER_ADDRESS || '127.0.0.1';
const READ_TIMEOUT = 15000;

export class AdbWireError extends Error {
  code?: number; stderr: string; stdout: string; killed?: boolean;
  constructor(message: string, opts?: { code?: number; stderr?: string; stdout?: string; killed?: boolean }) {
    super(message);
    this.code = opts?.code; this.stderr = opts?.stderr ?? ''; this.stdout = opts?.stdout ?? ''; this.killed = opts?.killed;
  }
}

// ---- 帧与连接原语 ----

// smart-socket 请求帧：4 位十六进制长度 + 载荷
function reqFrame(s: string): Buffer {
  const payload = Buffer.from(s, 'utf8');
  return Buffer.concat([Buffer.from(payload.length.toString(16).padStart(4, '0'), 'ascii'), payload]);
}

async function readN(sock: net.Socket, n: number): Promise<Buffer> {
  const out = Buffer.alloc(n); let off = 0;
  while (off < n) {
    const chunk = await new Promise<Buffer | null>((resolve, reject) => {
      const onData = (b: Buffer) => { cleanup(); resolve(b); };
      const onEnd = () => { cleanup(); resolve(null); };
      const onErr = (e: Error) => { cleanup(); reject(e); };
      const cleanup = () => { sock.off('data', onData); sock.off('end', onEnd); sock.off('close', onEnd); sock.off('error', onErr); };
      sock.once('data', onData); sock.once('end', onEnd); sock.once('close', onEnd); sock.once('error', onErr);
    });
    if (!chunk) throw new AdbWireError('adb server 断开了连接');
    const take = Math.min(chunk.length, n - off);
    chunk.copy(out, off, 0, take); off += take;
    if (chunk.length > take) sock.unshift(chunk.subarray(take));
  }
  return out;
}

async function readStatus(sock: net.Socket, what: string): Promise<void> {
  const tag = (await readN(sock, 4)).toString('ascii');
  if (tag === 'OKAY') return;
  if (tag === 'FAIL') {
    const len = parseInt((await readN(sock, 4)).toString('ascii'), 16);
    const msg = len > 0 ? (await readN(sock, len)).toString('utf8') : '';
    throw new AdbWireError(`${what}: ${msg || 'FAIL'}`);
  }
  throw new AdbWireError(`${what}: 未知应答 ${tag}`);
}

function connectServer(timeout: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: ADB_ADDR, port: ADB_PORT });
    sock.setNoDelay(true);
    const timer = setTimeout(() => { sock.destroy(); reject(new AdbWireError('连不上 adb server(5037)——adb 服务可能没在跑', { killed: true })); }, timeout);
    sock.once('connect', () => { clearTimeout(timer); resolve(sock); });
    sock.once('error', (e) => { clearTimeout(timer); reject(new AdbWireError(`连不上 adb server(5037): ${e.message}`, { killed: true })); });
  });
}

function withTimeout<T>(sock: net.Socket, ms: number, work: Promise<T>): Promise<T> {
  const timer = setTimeout(() => sock.destroy(new AdbWireError('ADB 请求超时', { killed: true })), ms);
  return work.finally(() => clearTimeout(timer));
}

// ---- host 级请求 ----

/** host 服务 → OKAY + len-prefixed payload。例：host:devices-l、host:version */
export async function adbHostData(service: string, timeout = READ_TIMEOUT): Promise<string> {
  const sock = await connectServer(timeout);
  try {
    return await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
      const len = parseInt((await readN(sock, 4)).toString('ascii'), 16);
      return len > 0 ? (await readN(sock, len)).toString('utf8') : '';
    })());
  } finally { sock.destroy(); }
}

/** host 服务 → OKAY 即止（无载荷）。例：host:transport-* 之外的确认型服务 */
export async function adbHostOk(service: string, timeout = READ_TIMEOUT): Promise<void> {
  const sock = await connectServer(timeout);
  try {
    await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
    })());
  } finally { sock.destroy(); }
}

/** forward 创建后服务器可附加一个 len-prefixed 已分配端口；无附加时连接直接结束。 */
async function adbHostOptionalData(service: string, timeout = READ_TIMEOUT): Promise<string> {
  const sock = await connectServer(timeout);
  try {
    return await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
      await readStatus(sock, service);
      try {
        const len = parseInt((await readN(sock, 4)).toString('ascii'), 16);
        return len > 0 ? (await readN(sock, len)).toString('utf8') : '';
      } catch {
        return '';
      }
    })());
  } finally { sock.destroy(); }
}

async function adbHostForwardOk(service: string, timeout = READ_TIMEOUT): Promise<void> {
  const sock = await connectServer(timeout);
  try {
    await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
      await readStatus(sock, service);
    })());
  } finally { sock.destroy(); }
}

// Windows 下 AOSP usb_windows.cpp GetDevicePath() 固定返回 "unknown"，导致 devices -l 不带 usb: 字段；
// 而 TCP(ip:port)、mDNS(*._tcp) 与模拟器(emulator-*) 序列号格式固定，其余硬件序列号均为物理 USB 传输。
function enrichWindowsUsbTag(raw: string): string {
  if (process.platform !== 'win32' || !raw) return raw;
  return raw.split(/\r?\n/).map((line) => {
    const t = line.trim();
    if (!t || t.startsWith('List of devices') || t.startsWith('*') || /\busb:/.test(t)) return line;
    const parts = t.split(/\s+/);
    if (parts.length < 2) return line;
    const serial = parts[0];
    if (serial.includes(':') || /^emulator-\d+$/i.test(serial) || serial.includes('._tcp')) return line;
    return `${line} usb:win32`;
  }).join('\n');
}

let trackedRoster: { raw: string; long: boolean } | null = null;
let devicesInflight: Promise<string> | null = null;

/** 设备花名册推送流 —— host:track-devices，server 主动推变更，零轮询。 */
export function adbTrackDevices(onRoster: (raw: string) => void, onError?: (e: Error) => void, useLong = true): { close: () => void } {
  let sock: net.Socket | null = null; let closed = false; let buf = Buffer.alloc(0);
  let longOk = useLong;
  const open = async () => {
    while (!closed) {
      try {
        sock = await connectServer(5000);
        sock.write(reqFrame(longOk ? 'host:track-devices-l' : 'host:track-devices'));
        try {
          await readStatus(sock, 'track-devices');
        } catch (e) {
          if (longOk) { longOk = false; sock.destroy(); continue; } // 老 server 不认 -l
          throw e;
        }
        buf = Buffer.alloc(0);
        sock.on('data', (chunk: Buffer) => {
          buf = Buffer.concat([buf, chunk]);
          while (buf.length >= 4) {
            const len = parseInt(buf.subarray(0, 4).toString('ascii'), 16);
            if (!Number.isFinite(len) || buf.length < 4 + len) break;
            const raw = enrichWindowsUsbTag(buf.subarray(4, 4 + len).toString('utf8'));
            trackedRoster = { raw, long: longOk };
            onRoster(raw);
            buf = buf.subarray(4 + len);
          }
        });
        await new Promise<void>((resolve) => { sock!.once('close', () => resolve()); sock!.once('error', () => resolve()); });
        trackedRoster = null;
        if (!closed) await new Promise(r => setTimeout(r, 2000)); // 掉线重连退避
      } catch (e) {
        trackedRoster = null;
        if (!closed) { onError?.(e as Error); await new Promise(r => setTimeout(r, 2000)); }
      }
    }
  };
  void open();
  return { close: () => { closed = true; trackedRoster = null; sock?.destroy(); } };
}

// ---- 设备级 transport ----

export type Selector = { kind: 'serial' | 'usb' | 'transport'; value?: string };
export const selSerial = (serial: string): Selector => ({ kind: 'serial', value: serial });
export const selUsb: Selector = { kind: 'usb' };
export const selAny: Selector = { kind: 'transport', value: 'any' };
async function openTransport(sel: Selector, timeout: number): Promise<net.Socket> {
  const sock = await connectServer(timeout);
  try {
    await withTimeout(sock, timeout, (async () => {
      const target = sel.kind === 'serial' ? `host:transport:${sel.value}`
        : sel.kind === 'usb' ? 'host:transport-usb'
        : sel.kind === 'transport' && sel.value !== 'any' ? `host:transport-id:${sel.value}`
        : 'host:transport-any';
      sock.write(reqFrame(target));
      await readStatus(sock, target);
    })());
    return sock;
  } catch (e) { sock.destroy(); throw e; }
}

/** 设备级 len-prefixed 服务：get-state / get-serialno / get-devpath / reverse:list */
export async function adbDeviceData(sel: Selector, service: string, timeout = READ_TIMEOUT): Promise<string> {
  const sock = await openTransport(sel, timeout);
  try {
    return await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
      const len = parseInt((await readN(sock, 4)).toString('ascii'), 16);
      return len > 0 ? (await readN(sock, len)).toString('utf8') : '';
    })());
  } finally { sock.destroy(); }
}

/** 设备级无载荷服务：reverse:forward / reverse:killforward */
export async function adbDeviceOk(sel: Selector, service: string, timeout = READ_TIMEOUT): Promise<void> {
  const sock = await openTransport(sel, timeout);
  try {
    await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame(service));
      await readStatus(sock, service);
    })());
  } finally { sock.destroy(); }
}

// ---- shell ----

// shell,v2 包协议（Android 8+）：1B 通道 + 4B LE 长度 + 载荷
const V2 = { stdin: 0, stdout: 1, stderr: 2, exit: 3, closeStdin: 4, winSize: 5 } as const;
let v2Unavailable = false; // 旧 adbd 不支持时降级 shell: 裸流（无退出码/stderr）

export interface AdbStream extends Duplex {
  onStderr?: (chunk: Buffer) => void;
  onExit?: (code: number) => void;
}

function v2Frame(id: number, payload: Buffer): Buffer {
  const head = Buffer.alloc(5); head[0] = id; head.writeUInt32LE(payload.length, 1);
  return Buffer.concat([head, payload]);
}

/** shell,v2 交互流：write → stdin 帧，'data' → stdout，stderr/exit 走钩子。 */
export function adbShell(sel: Selector, command: string, timeout = READ_TIMEOUT): AdbStream {
  const out = new Duplex({
    write(chunk, _enc, cb) {
      if (sock && open) { sock.write(v2Frame(V2.stdin, chunk)); cb(); }
      else { pending.push(chunk); cb(); }
    },
    read() { },
    final(cb) { if (sock && open) sock.write(v2Frame(V2.closeStdin, Buffer.alloc(0))); cb(); },
    destroy(err, cb) { sock?.destroy(); cb(err); },
  }) as AdbStream;
  let sock: net.Socket | null = null; let open = false;
  const pending: Buffer[] = [];
  let vbuf = Buffer.alloc(0); let ended = false;
  const flushPending = () => { for (const c of pending) sock!.write(v2Frame(V2.stdin, c)); pending.length = 0; };
  void (async () => {
    try {
      sock = await openTransport(sel, timeout);
      sock.write(reqFrame(`shell,v2,raw:${command}`));
      await readStatus(sock, 'shell,v2');
      open = true; flushPending();
      sock.on('data', (chunk: Buffer) => {
        vbuf = Buffer.concat([vbuf, chunk]);
        while (vbuf.length >= 5) {
          const id = vbuf[0]; const len = vbuf.readUInt32LE(1);
          if (vbuf.length < 5 + len) break;
          const payload = vbuf.subarray(5, 5 + len); vbuf = vbuf.subarray(5 + len);
          if (id === V2.stdout) out.push(payload);
          else if (id === V2.stderr) out.onStderr?.(payload);
          else if (id === V2.exit) { out.onExit?.(payload[0]); if (!ended) { ended = true; out.push(null); } }
        }
      });
      sock.on('close', () => { if (!ended) { ended = true; out.push(null); } });
      sock.on('error', (e) => { out.destroy(e); });
    } catch (e) { out.destroy(e as Error); }
  })();
  return out;
}

/** exec: 裸流（无退出码/stderr 分离） */
function adbExecRaw(sel: Selector, command: string, timeout: number): Duplex {
  const out = new Duplex({
    write(chunk, _enc, cb) { sock?.write(chunk); cb(); },
    read() { },
    final(cb) { sock?.end(); cb(); },
    destroy(err, cb) { sock?.destroy(); cb(err); },
  });
  let sock: net.Socket | null = null;
  void (async () => {
    try {
      sock = await openTransport(sel, timeout);
      sock.write(reqFrame(`exec:${command}`));
      await readStatus(sock, 'exec');
      sock.on('data', (c: Buffer) => out.push(c));
      sock.on('close', () => out.push(null));
      sock.on('error', (e) => out.destroy(e));
    } catch (e) { out.destroy(e as Error); }
  })();
  return out;
}

/** 收集流全程的兜底：整体超时（execFile 的 killed 语义）+ maxBuffer 上限。 */
function collectStream(s: Duplex & AdbStream, ms: number, maxBuffer: number): Promise<{ stdout: Buffer; stderr: Buffer; code: number }> {
  return new Promise((resolve, reject) => {
    const acc: Buffer[] = []; const errs: Buffer[] = [];
    let bytes = 0; let code = 0; let settled = false;
    const timer = setTimeout(() => s.destroy(new AdbWireError('ADB 请求超时', { killed: true })), ms + 1000);
    const fail = (e: Error) => { if (!settled) { settled = true; clearTimeout(timer); reject(e); } };
    s.on('data', (c: Buffer) => {
      bytes += c.length;
      if (bytes > maxBuffer) { fail(new AdbWireError(`ADB 输出超过 ${maxBuffer} 字节上限`)); s.destroy(); return; }
      acc.push(c);
    });
    s.onStderr = (c: Buffer) => errs.push(c);
    s.onExit = (c: number) => { code = c; };
    s.on('end', () => { if (!settled) { settled = true; clearTimeout(timer); resolve({ stdout: Buffer.concat(acc), stderr: Buffer.concat(errs), code }); } });
    s.on('error', fail);
  });
}

function collectRaw(s: Duplex & AdbStream, ms: number, maxBuffer: number): Promise<{ stdout: string; stderr: string; code: number }> {
  return collectStream(s, ms, maxBuffer).then(r => ({ stdout: r.stdout.toString('utf8'), stderr: r.stderr.toString('utf8'), code: r.code }));
}

/** shell 跑到结束 → {stdout, stderr, code}。execFile 语义：code≠0 抛错。 */
export async function adbShellRun(sel: Selector, command: string, opts: { timeout?: number; stdin?: Buffer; maxBuffer?: number } = {}): Promise<{ stdout: string; stderr: string; code: number }> {
  const timeout = opts.timeout ?? READ_TIMEOUT;
  const maxBuffer = opts.maxBuffer ?? 32 * 1024 * 1024;
  if (v2Unavailable) return collectRaw(adbExecRaw(sel, command, timeout), timeout, maxBuffer);
  try {
    const stream = adbShell(sel, command, timeout);
    if (opts.stdin) stream.write(opts.stdin);
    stream.end();
    const r = await collectStream(stream, timeout, maxBuffer);
    return { stdout: r.stdout.toString('utf8'), stderr: r.stderr.toString('utf8'), code: r.code };
  } catch (e) {
    // 旧 adbd 不认识 shell,v2 → 全进程降级 exec 裸流
    if (e instanceof AdbWireError && /shell,v2/.test(e.message)) {
      v2Unavailable = true;
      return collectRaw(adbExecRaw(sel, command, timeout), timeout, maxBuffer);
    }
    throw e;
  }
}

/** exec-out 到结束 → stdout Buffer（图标/APK 等二进制安全） */
export async function adbExecOutBuf(sel: Selector, command: string, opts: { timeout?: number; maxBuffer?: number } = {}): Promise<Buffer> {
  const timeout = opts.timeout ?? READ_TIMEOUT;
  const r = await collectStream(adbExecRaw(sel, command, timeout) as Duplex & AdbStream, timeout, opts.maxBuffer ?? 32 * 1024 * 1024);
  return r.stdout;
}
export async function adbExecOut(sel: Selector, command: string, opts: { timeout?: number; maxBuffer?: number } = {}): Promise<string> {
  return (await adbExecOutBuf(sel, command, opts)).toString('utf8');
}

// ---- sync 推送（adb push）----

export async function adbPush(sel: Selector, local: Buffer, remotePath: string, opts: { timeout?: number; mode?: number; mtime?: number } = {}): Promise<void> {
  const timeout = opts.timeout ?? READ_TIMEOUT;
  const sock = await openTransport(sel, timeout);
  try {
    await withTimeout(sock, timeout, (async () => {
      sock.write(reqFrame('sync:'));
      await readStatus(sock, 'sync');
      const spec = `${remotePath},${(opts.mode ?? 0o644).toString()}`;
      const specBuf = Buffer.from(spec, 'utf8');
      const head = Buffer.alloc(4); head.writeUInt32LE(specBuf.length, 0);
      sock.write(Buffer.concat([Buffer.from('SEND'), head, specBuf]));
      for (let off = 0; off < local.length; off += 65536) {
        const chunk = local.subarray(off, Math.min(off + 65536, local.length));
        const h = Buffer.alloc(4); h.writeUInt32LE(chunk.length, 0);
        sock.write(Buffer.concat([Buffer.from('DATA'), h, chunk]));
      }
      const done = Buffer.alloc(4); done.writeUInt32LE(opts.mtime ?? Math.floor(Date.now() / 1000), 0);
      sock.write(Buffer.concat([Buffer.from('DONE'), done]));
      const tag = (await readN(sock, 4)).toString('ascii');
      const len = (await readN(sock, 4)).readUInt32LE(0);
      const msg = len > 0 ? (await readN(sock, len)).toString('utf8') : '';
      if (tag === 'FAIL') throw new AdbWireError(`push: ${msg}`);
      if (tag !== 'OKAY') throw new AdbWireError(`push: 未知应答 ${tag}`);
    })());
  } finally { sock.destroy(); }
}

// ---- argv 兼容层：execFile('adb', argv) 的整组映射 ----

// `adb shell -T cmd` 的 PTY 标志由 CLI 剥离；shell,v2,raw 本就无 PTY，等价丢弃。
function stripShellFlags(tokens: string[]): string[] {
  const out = [...tokens];
  while (out.length && /^-[Ttnx]+$/.test(out[0])) out.shift();
  return out;
}

interface ParsedArgs { sel: Selector; rest: string[] }
export function parseAdbArgs(args: string[]): ParsedArgs {
  const rest = [...args]; const sel: Selector = { kind: 'transport', value: 'any' };
  while (rest.length) {
    if (rest[0] === '-s') { rest.shift(); sel.kind = 'serial'; sel.value = rest.shift()!; }
    else if (rest[0] === '-t') { rest.shift(); sel.kind = 'transport'; sel.value = rest.shift()!; }
    else if (rest[0] === '-d') { rest.shift(); sel.kind = 'usb'; }
    else if (rest[0] === '-a' || rest[0] === '--listen-all' || rest[0] === '-L') { rest.shift(); }
    else break;
  }
  return { sel, rest };
}

/** execFile('adb', args, opts) 的 drop-in：同 argv 进，{stdout,stderr} 出；非零退出抛 code/stderr。 */
export async function adbExec(args: string[], opts: { timeout?: number; maxBuffer?: number } = {}): Promise<{ stdout: string; stderr: string }> {
  const timeout = opts.timeout ?? READ_TIMEOUT;
  const { sel, rest } = parseAdbArgs(args);
  const cmd = rest[0];
  if (cmd === 'devices') {
    const wantLong = rest.includes('-l');
    if (trackedRoster && (!wantLong || trackedRoster.long)) {
      return { stdout: 'List of devices attached\n' + trackedRoster.raw, stderr: '' };
    }
    let raw: string;
    if (wantLong) {
      if (!devicesInflight) {
        devicesInflight = (async () => {
          try { return enrichWindowsUsbTag(await adbHostData('host:devices-l', timeout)); }
          catch (e) {
            if (e instanceof AdbWireError && e.message.startsWith('host:devices-l:')) {
              return enrichWindowsUsbTag(await adbHostData('host:devices', timeout));
            }
            throw e;
          }
        })().finally(() => { devicesInflight = null; });
      }
      raw = await devicesInflight;
    } else raw = enrichWindowsUsbTag(await adbHostData('host:devices', timeout));
    return { stdout: 'List of devices attached\n' + raw, stderr: '' };
  }
  if (cmd === 'shell') {
    const command = stripShellFlags(rest.slice(1)).join(' ');
    const r = await adbShellRun(sel, command, { timeout, maxBuffer: opts.maxBuffer });
    if (r.code !== 0) throw new AdbWireError(`Command failed: adb shell ${command}`, { code: r.code, stderr: r.stderr });
    return { stdout: r.stdout, stderr: r.stderr };
  }
  if (cmd === 'exec-out') return { stdout: await adbExecOut(sel, rest.slice(1).join(' '), opts), stderr: '' };
  if (cmd === 'get-state') return { stdout: await adbDeviceData(sel, 'get-state', timeout), stderr: '' };
  if (cmd === 'get-serialno') return { stdout: await adbDeviceData(sel, 'get-serialno', timeout), stderr: '' };
  if (cmd === 'get-devpath') return { stdout: await adbDeviceData(sel, 'get-devpath', timeout), stderr: '' };
  if (cmd === 'reverse') {
    if (rest[1] === '--list') return { stdout: await adbDeviceData(sel, 'reverse:list-forward', timeout), stderr: '' };
    if (rest[1] === '--remove') { await adbDeviceOk(sel, `reverse:killforward:${rest[2]}`, timeout); return { stdout: '', stderr: '' }; }
    await adbDeviceOk(sel, `reverse:forward:${rest[1]};${rest[2]}`, timeout);
    return { stdout: '', stderr: '' };
  }
  if (cmd === 'forward') {
    const prefix = sel.kind === 'serial' ? `host-serial:${sel.value}`
      : sel.kind === 'transport' && sel.value !== 'any' ? `host-transport-id:${sel.value}`
      : sel.kind === 'usb' ? 'host-usb' : 'host';
    if (rest[1] === '--list') return { stdout: await adbHostData(`${prefix}:list-forward`, timeout), stderr: '' };
    if (rest[1] === '--remove') { await adbHostForwardOk(`${prefix}:killforward:${rest[2]}`, timeout); return { stdout: '', stderr: '' }; }
    let at = 1; let norebind = false;
    if (rest[at] === '--no-rebind') { norebind = true; at++; }
    const local = rest[at]; const remote = rest[at + 1];
    if (!local || !remote) throw new AdbWireError(`adb_wire: forward 参数不完整 ${JSON.stringify(args)}`);
    const resolved = await adbHostOptionalData(`${prefix}:forward:${norebind ? 'norebind:' : ''}${local};${remote}`, timeout);
    return { stdout: resolved ? resolved + '\n' : '', stderr: '' };
  }
  if (cmd === 'push') {
    const { readFileSync } = await import('node:fs');
    await adbPush(sel, readFileSync(rest[1]), rest[2], { timeout });
    return { stdout: '', stderr: '' };
  }
  throw new AdbWireError(`adb_wire: 未映射的 adb 参数 ${JSON.stringify(args)} —— 需要显式支持，不许回落 spawn`);
}

/** execFile('adb', args, {encoding:'buffer'}) 的 drop-in：stdout 为 Buffer，二进制安全。 */
export async function adbExecBuffer(args: string[], opts: { timeout?: number; maxBuffer?: number } = {}): Promise<{ stdout: Buffer; stderr: string }> {
  const { sel, rest } = parseAdbArgs(args);
  const timeout = opts.timeout ?? READ_TIMEOUT;
  if (rest[0] === 'exec-out') return { stdout: await adbExecOutBuf(sel, rest.slice(1).join(' '), opts), stderr: '' };
  if (rest[0] === 'shell') {
    // shell,v2 stdout 已是原始字节流
    const stream = adbShell(sel, stripShellFlags(rest.slice(1)).join(' '), timeout);
    stream.end();
    const r = await collectStream(stream, timeout, opts.maxBuffer ?? 32 * 1024 * 1024);
    if (r.code !== 0) throw new AdbWireError(`Command failed: adb shell ${rest.slice(1).join(' ')}`, { code: r.code, stderr: r.stderr.toString('utf8') });
    return { stdout: r.stdout, stderr: r.stderr.toString('utf8') };
  }
  throw new AdbWireError(`adb_wire: 二进制只支持 shell/exec-out: ${JSON.stringify(args)}`);
}

/** spawn('adb', argv) 的 drop-in：返回双向流（write→stdin，data→stdout）。仅 shell/exec-out。 */
export function adbExecStream(args: string[]): AdbStream | Duplex {
  const { sel, rest } = parseAdbArgs(args);
  if (rest[0] === 'shell') return adbShell(sel, stripShellFlags(rest.slice(1)).join(' '));
  if (rest[0] === 'exec-out') return adbExecRaw(sel, rest.slice(1).join(' '), READ_TIMEOUT);
  throw new AdbWireError(`adb_wire: 流式只支持 shell/exec-out: ${JSON.stringify(args)}`);
}

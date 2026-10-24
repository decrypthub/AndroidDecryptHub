// Host orchestration for the optional root-side perf collector. This process owns
// files and queries; the helper only collects kernel samples outside the app.
import { execFile, spawn } from 'node:child_process';
import { randomUUID, createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { assertProcessGeneration } from './proc_identity.ts';

const exec = promisify(execFile);
const HELPER = '/data/local/tmp/adh-root-watch-v1';
const VERSION = 'ADH_ROOT_WATCH_V1';
const localHelper = fileURLToPath(new URL('../../agent/build/adh-root-watch', import.meta.url));
type Target = { sessionId: string; pid: number; process?: string; package: string; uid: number; starttimeTicks?: string };
type Run = { id: string; serial: string; target: Target; file: string; running: boolean; collectorPid?: number;
  stopFile: string; ready?: any; summary?: any; error?: string; stderr: string; samples: number; exitCode?: number | null;
  starttimeTicks: string; sessionGenerationVerified: boolean };
const runs = new Map<string, Run>();

function integer(value: unknown, fallback: number, lo: number, hi: number, name: string): number {
  const n = value === undefined ? fallback : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < lo || n > hi) throw new Error(`${name} must be an integer ${lo}..${hi}`);
  return n;
}
function address(value: unknown, name: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(value)) throw new Error(`${name} must be a hex address`);
  const n = BigInt(value);
  if (!n) throw new Error(`${name} must not be zero`);
  return n;
}
export function normalizeRootWatch(a: Record<string, any>) {
  const tid = integer(a.tid, 0, 1, 0x7fffffff, 'tid');
  const mode = a.mode ?? 'w';
  if (!['w', 'r', 'rw', 'x'].includes(mode)) throw new Error('mode must be w, r, rw or x');
  const width = integer(a.width, mode === 'x' ? 4 : 8, 1, 8, 'width');
  const addr = address(a.addr, 'addr');
  if (![1, 2, 4, 8].includes(width) || addr % BigInt(width) || (mode === 'x' && width !== 4)) throw new Error('width must be 1/2/4/8 and address aligned; execution breakpoints need width 4');
  const durationMs = integer(a.durationMs, 5000, 1, 30000, 'durationMs');
  const maxEvents = integer(a.maxEvents, 128, 1, 2048, 'maxEvents');
  const stackBytes = integer(a.stackBytes, 8192, 0, 16384, 'stackBytes');
  if (stackBytes % 8) throw new Error('stackBytes must be a multiple of 8');
  return { tid, addr: '0x' + addr.toString(16), width, mode, durationMs, maxEvents, stackBytes };
}
async function adb(serial: string, args: string[], timeout = 10000) {
  return (await exec('adb', ['-s', serial, ...args], { timeout, maxBuffer: 1024 * 1024, windowsHide: true })).stdout;
}
async function selectSerial(requested?: string) {
  const devices = (await exec('adb', ['devices'], { timeout: 10000, windowsHide: true })).stdout
    .split(/\r?\n/).map(line => /^(\S+)\s+device$/.exec(line.trim())?.[1]).filter((x): x is string => !!x);
  const serial = requested ?? process.env.ADH_SERIAL ?? process.env.ANDROID_SERIAL;
  if (serial) { if (!devices.includes(serial)) throw new Error(`ADB device ${serial} is not online`); return serial; }
  if (devices.length !== 1) throw new Error('root_watch needs serial when ADB does not have exactly one online device');
  return devices[0];
}
// Shared by read-only runtime diagnostics; never choose an ambiguous device.
export { adb as rootAdb, selectSerial as selectRootSerial };
export async function prepareRootWatch(requested?: string) {
  const serial = await selectSerial(requested);
  if (!existsSync(localHelper)) throw new Error('Root collector not built: run bash tools/build_root_watch.sh first');
  if ((await adb(serial, ['shell', 'su', '-c', 'id -u'])).trim() !== '0') throw new Error('Root collector requires a rooted device; no helper was uploaded');
  await adb(serial, ['push', localHelper, HELPER]);
  await adb(serial, ['shell', 'su', '-c', `chmod 755 ${HELPER}`]);
  const version = (await adb(serial, ['shell', 'su', '-c', `${HELPER} --version`])).trim();
  if (version !== VERSION) throw new Error(`Unexpected root collector version: ${version}`);
  const text = await adb(serial, ['shell', 'su', '-c', `${HELPER} --self-test`]);
  const result = text.trim().split(/\r?\n/).map(line => JSON.parse(line)).at(-1);
  if (result?.selfTest !== true || result?.complete !== true || result?.samples !== 1) throw new Error(`Root watch self-test failed: ${JSON.stringify(result)}`);
  return { ok: true, serial, version, sha256: createHash('sha256').update(readFileSync(localHelper)).digest('hex'), selfTest: result };
}
export async function startRootWatch(target: Target, a: Record<string, any>, dataDir: string) {
  const spec = normalizeRootWatch(a);
  integer(target.pid, 0, 1, 0x7fffffff, 'target pid');
  integer(target.uid, -1, 0, 0x7fffffff, 'target uid');
  if ([...runs.values()].filter(run => run.running).length >= 4) throw new Error('At most four root-watch runs may be active');
  const serial = await selectSerial(a.serial);
  const cmdline = (await adb(serial, ['shell', 'su', '-c', `cat /proc/${target.pid}/cmdline`])).split('\0')[0];
  if (cmdline !== (target.process || target.package)) throw new Error('Device PID does not match the selected agent process');
  const status = await adb(serial, ['shell', 'su', '-c', `cat /proc/${target.pid}/status`]);
  const uid = Number(/^Uid:\s+(\d+)/m.exec(status)?.[1]);
  if (uid !== target.uid) throw new Error('Device PID UID does not match the selected agent');
  const generation = assertProcessGeneration(await adb(serial, ['shell', 'su', '-c', `cat /proc/${target.pid}/stat`]), target.pid, target.starttimeTicks);
  if ((await adb(serial, ['shell', 'su', '-c', `${HELPER} --version`])).trim() !== VERSION) throw new Error('Run root_watch action:prepare first');
  const id = randomUUID();
  const file = join(resolve(dataDir), 'root-watch', `${id}.jsonl`);
  mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, '', { mode: 0o600 });
  const stopFile = `/data/local/tmp/adh-root-watch-stop-${id}`;
  const run: Run = { id, serial, target, file, stopFile, running: true, stderr: '', samples: 0, ...generation };
  runs.set(id, run);
  const command = `${HELPER} ${target.pid} ${spec.tid} ${spec.addr} ${spec.width} ${spec.mode} ${spec.durationMs} ${spec.maxEvents} ${spec.stackBytes} ${stopFile}`;
  const child = spawn('adb', ['-s', serial, 'shell', 'su', '-c', command], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let pending = '';
  await new Promise<void>((resolveReady, reject) => {
    const timer = setTimeout(() => reject(new Error(`Root collector did not become ready; run ${id} remains bounded by durationMs`)), 5000);
    child.stdout.on('data', bytes => {
      pending += bytes.toString('utf8');
      if (pending.length > 131072) { run.error = 'Collector emitted an oversized line'; pending = ''; }
      let end: number;
      while ((end = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, end).trim(); pending = pending.slice(end + 1);
        if (!line) continue;
        try {
          const event = JSON.parse(line);
          appendFileSync(file, line + '\n');
          if (event.ready === true && event.version === VERSION && event.pid === target.pid && event.tid === spec.tid) {
            integer(event.collectorPid, 0, 1, 0x7fffffff, 'collector pid');
            if (event.collectorPid === target.pid) throw new Error('Collector PID must differ from the target PID');
            run.ready = event; run.collectorPid = event.collectorPid; clearTimeout(timer); resolveReady();
          } else if (event.ready === false) { run.error = `${event.stage}: ${event.error} (errno ${event.errno})`; clearTimeout(timer); reject(new Error(run.error)); }
          else if (event.seq) run.samples++;
          else if (event.done) run.summary = event;
        } catch (e) { run.error = `Invalid collector record: ${String(e)}`; }
      }
    });
    child.stderr.on('data', bytes => { run.stderr = (run.stderr + bytes.toString()).slice(-4096); });
    child.on('error', error => { clearTimeout(timer); run.running = false; run.error = error.message; reject(error); });
    child.on('close', code => {
      clearTimeout(timer); run.running = false; run.exitCode = code;
      if (!run.summary) run.error ||= `Collector exited without a final accounting record (${code}): ${run.stderr}`;
      if (!run.ready) reject(new Error(run.error || 'Collector exited before readiness'));
    });
  });
  try {
    // Recheck after perf readiness: a process may exit while ADB starts the
    // helper. Its own TID/Tgid check is necessary but not a generation check.
    assertProcessGeneration(await adb(serial, ['shell', 'su', '-c', `cat /proc/${target.pid}/stat`]), target.pid, generation.starttimeTicks);
  } catch (error) {
    run.error = `Target generation changed during collector startup: ${String(error)}`;
    try { await adb(serial, ['shell', 'su', '-c', `touch ${stopFile}`]); }
    catch (stopError) { run.error += `; cooperative stop failed, collector remains duration-bounded: ${String(stopError)}`; }
    throw new Error(run.error);
  }
  return { ok: true, id, serial, session: target.sessionId, pid: target.pid, ...spec, ...generation,
    identityScope: generation.sessionGenerationVerified ? 'Matches agent hello generation and collector startup.' : 'Stable during startup; legacy agent did not report session generation.',
    scope: 'one-existing-thread', output: file, note: 'Only the named TID is observed. New threads are not inherited. Query read/status for loss and event-limit accounting.' };
}
function getRun(id: string) { const r = runs.get(id); if (!r) throw new Error('Unknown root-watch run (run registry is local to this daemon lifetime)'); return r; }
export function rootWatchStatus(id: string) {
  const r = getRun(id);
  return { id, running: r.running, samples: r.samples, complete: !r.running && !r.error && r.exitCode === 0 && r.summary?.complete === true,
    summary: r.summary ?? null, error: r.error, output: r.file, serial: r.serial, pid: r.target.pid,
    starttimeTicks: r.starttimeTicks, sessionGenerationVerified: r.sessionGenerationVerified };
}
export function projectRootSample(record: any, a: Record<string, any>) {
  const { regs, stack, ...event } = record;
  if (a.registers === true) event.regs = regs;
  const size = integer(a.stackSize, 0, 0, 2048, 'stackSize');
  event.stack = { addr: stack.addr, requested: stack.requested, got: stack.got, short: stack.got < stack.requested };
  if (size) {
    const start = a.stackAddress === undefined ? BigInt(stack.addr) : address(a.stackAddress, 'stackAddress');
    const offset = start - BigInt(stack.addr);
    if (offset < 0n || offset > BigInt(stack.got)) throw new Error('stackAddress is outside the kernel snapshot');
    const bytes = Buffer.from(stack.hex, 'hex').subarray(Number(offset), Number(offset) + size);
    event.stackWindow = { addr: '0x' + start.toString(16), requested: size, got: bytes.length, short: bytes.length < size, hex: bytes.toString('hex') };
  }
  return event;
}
export function readRootWatch(id: string, a: Record<string, any>) {
  const r = getRun(id);
  const after = integer(a.afterSeq, 0, 0, 2048, 'afterSeq'), limit = integer(a.limit, 8, 1, 32, 'limit');
  const records = readFileSync(r.file, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(e => e.seq > after);
  const selected = records.slice(0, limit);
  return { ...rootWatchStatus(id), events: selected.map(e => projectRootSample(e, a)), nextSeq: selected.at(-1)?.seq ?? after, hasMore: records.length > selected.length };
}
export async function stopRootWatch(id: string) {
  const r = getRun(id);
  // Cooperate with this run's nonce, rather than sending signals to a reusable PID.
  if (r.running && !r.summary) await adb(r.serial, ['shell', 'su', '-c', `touch ${r.stopFile}`]);
  return rootWatchStatus(id);
}

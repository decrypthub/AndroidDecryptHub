import { trackedEffect } from './execution_context.ts';
import { deviceProcessControl, deviceProcesses, deviceSerial, deviceState } from './device_bridge.ts';
import { adbExec } from './adb_wire.ts';
// Target app control: one policy, two channels.
//   1. adh.device/1 `process.control` — the Device Daemon refuses system packages, checks the
//      (pid, uid, starttimeTicks) set it is about to replace and the device state generation, then
//      dispatches. This is the path that keeps working when a ROM renames `am` output or the host
//      loses the adb shell surface but keeps the device domain.
//   2. adb (`am`/`monkey`) — explicit fallback for an older module build or a dead channel.
// The result says which channel ran (`via`) and, when adb ran, why the device channel was skipped
// (`fallback`): a green result must not read as "the device domain was exercised".

const PKG_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const BLOCKED = new Set(['com.adh.manager', 'com.adh.daemon', 'android', 'com.android.systemui']);

export type ControlAction = 'open' | 'stop' | 'restart';
export type LaunchVia = 'device' | 'adb';

export interface LaunchResult {
  ok: boolean;
  package: string;
  mode: string;
  /** Which channel produced this result. Absent only when nothing was dispatched. */
  via?: LaunchVia;
  error?: string;
  /** Set when adb ran because the device channel could not serve the call. */
  fallback?: string;
}

export interface ProcessIdentity { pid: number; uid: number; starttimeTicks: string }

/** The slice of the device domain app control needs; injectable so tests never touch a phone. */
export interface ControlChannel {
  state(): Promise<{ stateRevision?: number } | null>;
  processes(pkg: string): Promise<{ rows: ProcessIdentity[]; complete: boolean; total: number } | null>;
  control(pkg: string, action: ControlAction, expected: ProcessIdentity[], revision: number): Promise<any | null>;
}

export type AdbRun = (args: string[], timeoutMs?: number) => Promise<{ ok: boolean; stdout: string; stderr: string }>;

export interface ControlDeps {
  /** `null` forces the adb path; omit to use the live device channel. */
  channel?: ControlChannel | null;
  adbRun?: AdbRun;
}

function adbBase(serial = deviceSerial()): string[] {
  return serial ? ['-s', serial] : [];
}

async function adb(args: string[], timeoutMs = 20_000): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await trackedEffect(() => adbExec([...adbBase(), ...args], {
      timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024,
    }));
    return { ok: true, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') };
  } catch (e: any) {
    return {
      ok: false,
      stdout: String(e?.stdout ?? ''),
      stderr: String(e?.stderr ?? e?.message ?? e),
    };
  }
}

function bridgeChannel(): ControlChannel {
  return {
    async state() { const serial = deviceSerial(); return serial ? deviceState(serial) : null; },
    async processes(pkg) { const serial = deviceSerial(); return serial ? deviceProcesses(serial, pkg) : null; },
    async control(pkg, action, expected, revision) {
      const serial = deviceSerial();
      return serial ? deviceProcessControl(serial, pkg, action, expected, revision) : null;
    },
  };
}

/** Preconditions that only mean "observe again": the device refused before dispatching. */
const RETRY_CODES = new Set(['TARGET_CHANGED', 'STALE_DEVICE_STATE', 'IDENTITY_UNVERIFIED']);

/** Codes that mean "this channel cannot answer at all", never a verdict about the target app. */
const CHANNEL_CODES = new Set([
  'UNSUPPORTED_METHOD', 'DEVICE_DISCONNECTED', 'DEVICE_NOT_READY', 'DEVICE_UNAVAILABLE',
  'INVALID_BOOTSTRAP', 'RPC_BUSY', 'DEVICE_RPC_TIMEOUT', 'FRAME_LIMIT', 'INVALID_FRAME',
  'PROC_UNAVAILABLE',
]);

/**
 * The device domain deliberately does not serve remote control for system/protected packages.
 * That is a class decision, not an observation about this app, so the operator channel
 * (adb, the human's own root path) still serves it — and the result says so in `fallback`.
 */
const DENIED_CODES = new Set(['TARGET_DENIED']);

const VERDICT_TEXT: Record<string, string> = {
  TARGET_DENIED: '设备域不让远程控制系统应用，已改用操作员 adb 通道',
  denied: '设备拒绝控制该应用（只允许非系统的第三方应用）',
  no_launcher: '该应用没有可启动的入口',
  failed: '设备执行失败',
  UNKNOWN_EXECUTION: '设备已执行但没有确认结果',
};

const ACTION_TEXT: Record<ControlAction, string> = { open: '启动', stop: '结束', restart: '重启' };

function codeOf(e: unknown): string {
  const code = (e as { code?: unknown })?.code;
  return typeof code === 'string' ? code : '';
}

function messageOf(e: unknown): string {
  const message = e instanceof Error ? e.message : String(e);
  return (message || 'device channel failed').split('\n')[0].slice(0, 200);
}

/** Only well-formed identities are sent: the device rejects the whole set otherwise. */
export function processIdentities(rows: ProcessIdentity[]): ProcessIdentity[] {
  return rows
    .map(r => ({ pid: Number(r?.pid), uid: Number(r?.uid), starttimeTicks: String(r?.starttimeTicks ?? '') }))
    .filter(r => Number.isSafeInteger(r.pid) && r.pid > 0 && Number.isSafeInteger(r.uid) && r.uid >= 0 && /^[0-9]{1,24}$/.test(r.starttimeTicks))
    .sort((a, b) => a.pid - b.pid || a.starttimeTicks.localeCompare(b.starttimeTicks));
}

/**
 * Reply shape is the operation record. `state` is the device's own outcome, `result.verdict` the
 * backend's, and `uncertain` says the effect was dispatched without a confirmed result — that last
 * one must never be reported as a plain failure, because the package may well have been restarted.
 */
export function controlVerdict(reply: any): { ok: boolean; code: string; uncertain: boolean } {
  const state = typeof reply?.state === 'string' ? reply.state : '';
  const uncertain = reply?.uncertain === true || state === 'unknown';
  const verdict = String(reply?.result?.verdict ?? '');
  const ok = state === 'succeeded' && !uncertain && (verdict ? verdict === 'ok' : reply?.result?.ok === true);
  const code = String(
    reply?.code || reply?.error?.code || (uncertain ? 'UNKNOWN_EXECUTION' : verdict || (reply?.result?.ok === true ? 'ok' : 'failed')),
  );
  return { ok, code, uncertain };
}

async function controlThroughDevice(
  pkg: string,
  action: ControlAction,
  channel: ControlChannel,
): Promise<{ result?: LaunchResult; fallback?: string }> {
  const mode = `device:${action}`;
  const snapshot = async () => {
    const answer = await channel.processes(pkg);
    return answer ? processIdentities(answer.rows) : null;
  };
  const revision = async () => {
    const state = await channel.state();
    const value = Number(state?.stateRevision);
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  };
  const reobserve = async (): Promise<string | null> => {
    try {
      const next = await snapshot();
      const nextRevision = await revision();
      if (!next || nextRevision === null) return 'channel unavailable';
      expected = next;
      stateRevision = nextRevision;
      return null;
    } catch (again) {
      return `${codeOf(again) || 'DEVICE_ERROR'}: ${messageOf(again)}`;
    }
  };

  let expected: ProcessIdentity[] | null;
  let stateRevision: number | null;
  try {
    expected = await snapshot();
    if (!expected) return { fallback: 'channel unavailable' };
    stateRevision = await revision();
    if (stateRevision === null) return { fallback: 'device state revision unavailable' };
  } catch (e) {
    // Both reads are side-effect free, so the adb path is still safe here.
    return { fallback: `${codeOf(e) || 'DEVICE_ERROR'}: ${messageOf(e)}` };
  }

  const unconfirmed = (code: string): LaunchResult => ({
    ok: false, package: pkg, mode, via: 'device',
    error: `${code}: 已下发但设备未确认结果，不重试也不回退 adb`,
  });
  const denied = (code: string): { fallback: string } => ({
    fallback: `${code}: 设备域不服务这一类应用（系统应用/受保护包）的远程控制`,
  });
  const refused = (code: string, detail: string, message = ''): LaunchResult => ({
    ok: false, package: pkg, mode, via: 'device',
    // The device reuses TARGET_CHANGED for "the process set moved" and for "this channel talks to
    // a different boot/daemon generation", so its own wording is the only thing that tells them apart.
    error: `${VERDICT_TEXT[code] || detail}（${code}${message ? `：${message}` : ''}）`,
  });

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const reply = await channel.control(pkg, action, expected, stateRevision);
      if (!reply) return { fallback: 'channel unavailable' };
      const verdict = controlVerdict(reply);
      if (verdict.uncertain) return { result: unconfirmed(verdict.code) };
      if (verdict.ok) return { result: { ok: true, package: pkg, mode, via: 'device' } };
      // A failed record can still carry a precondition code: observe again rather than retry.
      if (attempt === 0 && RETRY_CODES.has(verdict.code)) {
        const reason = await reobserve();
        if (reason) return { fallback: reason };
        continue;
      }
      if (DENIED_CODES.has(verdict.code)) return denied(verdict.code);
      return { result: refused(verdict.code, `${ACTION_TEXT[action]}失败`, String(reply?.error?.message ?? reply?.message ?? '')) };
    } catch (e) {
      const code = codeOf(e);
      const uncertain = (e as { uncertain?: unknown })?.uncertain === true;
      // An unidentified failure is never read as "the channel cannot serve": a write may have
      // been dispatched before the error, and adb would then act on an unknown state.
      if (uncertain) return { result: unconfirmed(code || 'DEVICE_ERROR') };
      if (attempt === 0 && RETRY_CODES.has(code)) {
        const reason = await reobserve();
        if (reason) return { fallback: reason };
        continue;
      }
      if (DENIED_CODES.has(code)) return denied(code);
      // Still unable to enumerate the package's processes (older module builds count a process
      // that exits mid-scan as unknown): nothing was dispatched, so adb may run — and the reason
      // is reported instead of being hidden behind a green result.
      if (code === 'IDENTITY_UNVERIFIED' || CHANNEL_CODES.has(code)) {
        return { fallback: `${code}: ${messageOf(e)}` };
      }
      return { result: { ok: false, package: pkg, mode, via: 'device', error: `${code || 'DEVICE_ERROR'}: ${messageOf(e)}` } };
    }
  }
  return { result: refused('TARGET_CHANGED', `${ACTION_TEXT[action]}失败`) };
}

/** Pick `pkg/activity` from `cmd package resolve-activity --brief` output. */
export function pickLauncherComponent(resolveActivityOut: string): string | null {
  const tokens = String(resolveActivityOut || '').trim().split(/\s+/);
  return tokens.find((t) => /^[A-Za-z0-9._]+\/[A-Za-z0-9._$]+$/.test(t)) ?? null;
}

export function mayLaunchPackage(pkg: string): boolean {
  const name = pkg.trim();
  return !!name && PKG_RE.test(name) && !BLOCKED.has(name);
}

function resolveChannel(deps: ControlDeps): ControlChannel | null {
  return 'channel' in deps ? (deps.channel ?? null) : bridgeChannel();
}

async function stopViaAdb(pkg: string, run: AdbRun): Promise<LaunchResult> {
  const stop = await run(['shell', 'am', 'force-stop', pkg], 15_000);
  if (!stop.ok && /no devices|not found|device offline/i.test(stop.stderr)) {
    return { ok: false, package: pkg, mode: 'adb', via: 'adb', error: `adb 不可用: ${stop.stderr.slice(0, 160)}` };
  }
  return { ok: true, package: pkg, mode: 'force-stop', via: 'adb' };
}

async function startViaAdb(pkg: string, run: AdbRun): Promise<LaunchResult> {
  const resolved = await run([
    'shell', 'cmd', 'package', 'resolve-activity', '--brief',
    '-c', 'android.intent.category.LAUNCHER', pkg,
  ], 15_000);
  const component = pickLauncherComponent(resolved.stdout);
  if (component) {
    const start = await run(['shell', 'am', 'start', '-n', component], 15_000);
    if (start.ok || /Starting:/i.test(start.stdout + start.stderr)) {
      return { ok: true, package: pkg, mode: `am start -n ${component}`, via: 'adb' };
    }
  }
  const monkey = await run([
    'shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1',
  ], 20_000);
  if (monkey.ok || /Events injected/i.test(monkey.stdout + monkey.stderr)) {
    return { ok: true, package: pkg, mode: component ? `monkey (retry after ${component})` : 'monkey', via: 'adb' };
  }
  return {
    ok: false, package: pkg, mode: 'failed', via: 'adb',
    error: `启动失败: ${(monkey.stderr || resolved.stderr || 'no launcher').slice(0, 200)}`,
  };
}

async function runControl(pkg: string, action: ControlAction, deps: ControlDeps): Promise<LaunchResult> {
  if (!mayLaunchPackage(pkg)) {
    return { ok: false, package: pkg, mode: 'denied', error: `不允许${ACTION_TEXT[action]}该包名` };
  }
  const channel = resolveChannel(deps);
  let fallback: string | undefined;
  if (channel) {
    const attempt = await controlThroughDevice(pkg, action, channel);
    if (attempt.result) return attempt.result;
    fallback = attempt.fallback || 'device channel unavailable';
  }
  const run = deps.adbRun ?? adb;
  const result = action === 'stop'
    ? await stopViaAdb(pkg, run)
    : action === 'open'
      ? await startViaAdb(pkg, run)
      : await (async () => {
        const stopped = await stopViaAdb(pkg, run);
        if (!stopped.ok) return { ...stopped, fallback };
        await sleep(400);
        return startViaAdb(pkg, run);
      })();
  return { ...result, ...(fallback ? { fallback } : {}) };
}

export async function stopPackage(pkg: string, deps: ControlDeps = {}): Promise<LaunchResult> {
  return runControl(pkg.trim(), 'stop', deps);
}

/** Start the launcher activity. Does not stop a process that is already running. */
export async function startPackage(pkg: string, deps: ControlDeps = {}): Promise<LaunchResult> {
  return runControl(pkg.trim(), 'open', deps);
}

/** Force-stop then start the launcher activity; one device-side `restart` when the channel serves it. */
export async function coldStartPackage(pkg: string, deps: ControlDeps = {}): Promise<LaunchResult> {
  return runControl(pkg.trim(), 'restart', deps);
}

/** Main process pid when it can be attributed, else the lowest pid of the package. */
export function pickPackagePid(rows: Array<ProcessIdentity & { process?: string; package?: string }>, pkg: string): number {
  if (!rows.length) return 0;
  const main = rows.find(r => String(r.process ?? '') === pkg);
  const sorted = [...rows].sort((a, b) => a.pid - b.pid);
  return main ? main.pid : sorted[0].pid;
}

export async function runningPid(pkg: string, deps: ControlDeps = {}): Promise<number> {
  const channel = resolveChannel(deps);
  if (channel) {
    try {
      const answer = await channel.processes(pkg);
      // An answer is authoritative, including "no process": falling back to adb here would
      // resurrect the very reading the device just corrected.
      if (answer) return pickPackagePid(answer.rows as any[], pkg);
    } catch {
      // Channel could not answer; a read failure says nothing about the process table.
    }
  }
  const run = deps.adbRun ?? adb;
  const out = await run(['shell', 'pidof', pkg], 5_000);
  const pid = Number(String(out.stdout).trim().split(/\s+/)[0]);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : 0;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Poll until `listOnline` reports at least one session for the package that connected
 * at/after `sinceMs`, then wait `settleMs` so secondary processes can join.
 */
export async function waitForFreshSessions<T extends { connectedAt?: number }>(
  listOnline: () => T[],
  opts: { sinceMs: number; timeoutMs?: number; settleMs?: number; pollMs?: number },
): Promise<{ ok: boolean; sessions: T[]; waitedMs: number; error?: string }> {
  const timeoutMs = opts.timeoutMs ?? 45_000;
  const settleMs = opts.settleMs ?? 2_500;
  const pollMs = opts.pollMs ?? 700;
  const started = Date.now();
  let sessions: T[] = [];
  while (Date.now() - started < timeoutMs) {
    sessions = listOnline().filter((s) => (s.connectedAt ?? 0) >= opts.sinceMs);
    if (sessions.length) break;
    await sleep(pollMs);
  }
  if (!sessions.length) {
    return {
      ok: false, sessions: [], waitedMs: Date.now() - started,
      error: '等待 agent 上线超时 — 确认已勾选注入作用域、模块已刷入，且 adb reverse 正常',
    };
  }
  await sleep(settleMs);
  sessions = listOnline().filter((s) => (s.connectedAt ?? 0) >= opts.sinceMs);
  if (!sessions.length) sessions = listOnline();
  return { ok: true, sessions, waitedMs: Date.now() - started };
}

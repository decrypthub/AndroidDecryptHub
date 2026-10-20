// Host-side cold start of a target package via adb (same path verify scripts use).
// Device Daemon also has controlPackage(open|restart); the Host cannot speak AIDL, so adb is the
// operator/AI channel — see REQUIREMENTS module W / retired module X.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

const PKG_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const BLOCKED = new Set(['com.adh.manager', 'com.adh.daemon', 'android', 'com.android.systemui']);

function adbBase(): string[] {
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return serial ? ['-s', serial] : [];
}

async function adb(args: string[], timeoutMs = 20_000): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileP('adb', [...adbBase(), ...args], {
      timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
    });
    return { ok: true, stdout: String(stdout ?? ''), stderr: String(stderr ?? '') };
  } catch (e: any) {
    return {
      ok: false,
      stdout: String(e?.stdout ?? ''),
      stderr: String(e?.stderr ?? e?.message ?? e),
    };
  }
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

export type LaunchResult = {
  ok: boolean;
  package: string;
  mode: string;
  error?: string;
};

/** Force-stop then start the launcher activity (monkey fallback). */
export async function coldStartPackage(pkg: string): Promise<LaunchResult> {
  if (!mayLaunchPackage(pkg)) {
    return { ok: false, package: pkg, mode: 'denied', error: '不允许启动该包名' };
  }
  const stop = await adb(['shell', 'am', 'force-stop', pkg], 15_000);
  if (!stop.ok && /no devices|not found|device offline/i.test(stop.stderr)) {
    return { ok: false, package: pkg, mode: 'adb', error: `adb 不可用: ${stop.stderr.slice(0, 160)}` };
  }
  await sleep(400);

  const resolved = await adb([
    'shell', 'cmd', 'package', 'resolve-activity', '--brief',
    '-c', 'android.intent.category.LAUNCHER', pkg,
  ], 15_000);
  const component = pickLauncherComponent(resolved.stdout);
  if (component) {
    const start = await adb(['shell', 'am', 'start', '-n', component], 15_000);
    if (start.ok || /Starting:/i.test(start.stdout + start.stderr)) {
      return { ok: true, package: pkg, mode: `am start -n ${component}` };
    }
  }
  const monkey = await adb([
    'shell', 'monkey', '-p', pkg, '-c', 'android.intent.category.LAUNCHER', '1',
  ], 20_000);
  if (monkey.ok || /Events injected/i.test(monkey.stdout + monkey.stderr)) {
    return { ok: true, package: pkg, mode: component ? `monkey (retry after ${component})` : 'monkey' };
  }
  return {
    ok: false, package: pkg, mode: 'failed',
    error: `启动失败: ${(monkey.stderr || resolved.stderr || 'no launcher').slice(0, 200)}`,
  };
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

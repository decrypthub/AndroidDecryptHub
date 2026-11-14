// app_analyze.ts — "analyze this app" as ONE call, from a package name to a bounded report.
//
// The pieces already existed but the order was knowledge: add the package to the injection scope,
// cold start it, wait for the Zygisk-injected agent, then run triage/unpack/http_capture against the
// right process. Recipes orchestrate primitives for an EXISTING session; this module owns the part
// before the session exists, which is exactly what a human (or an AI client) has when it only knows
// the app.
//
// Rules kept from recipes.ts: every phase is reported with ok/detail, a failed phase does not throw
// away the others, and each phase returns a small summary instead of a multi-megabyte agent reply.
import { coldStartPackage, mayLaunchPackage, waitForFreshSessions } from './app_launch.ts';
import { preferMainProcess } from './dump_inventory.ts';
import { runRecipe } from './recipes.ts';
import { mergeScope, packageInstalled, readScopeFile, writeScopePackages } from './scope_list.ts';
import { onlineSessionsForPackage, runUnpackBundle } from './service.ts';

export interface AnalyzeOptions {
  /** Add the package to the phone's injection allowlist when it is missing. Default: true. */
  autoScope?: boolean;
  /** Force-stop and relaunch even when the app already has an online agent. */
  forceRestart?: boolean;
  /** Triage observation window (ms) while capture is armed. Default 3000. */
  captureMs?: number;
  /** Dump every DEX into a stored bundle. Default: false (triage alone is the fast answer). */
  unpack?: boolean;
  /** Arm TLS capture, wait and pair HTTP exchanges. 0 = skip. */
  httpCaptureMs?: number;
  /** How long to wait for the injected agent after cold start. Default 60000. */
  timeoutMs?: number;
  /** Extra settle time after the first agent of a package connects. Default 4000. */
  settleMs?: number;
}

type Phase = { ok: boolean; detail?: unknown; error?: string };

/** The main process (no ':') is the one a caller means by "the app"; fall back to the newest. */
export function pickAnalysisSession<T extends { process: string; package: string; online: boolean }>(rows: readonly T[]): T | null {
  return preferMainProcess(rows);
}

export async function analyzePackage(pkg: string, opts: AnalyzeOptions = {}) {
  const name = String(pkg ?? '').trim();
  const started = Date.now();
  const phases: Record<string, Phase> = {};
  if (!mayLaunchPackage(name)) {
    return { ok: false, package: name, error: '这个包名不能分析（系统包、ADH 自己，或包名不合法）', phases };
  }
  if (!(await packageInstalled(name))) {
    return { ok: false, package: name, error: `未安装：${name}`, phases };
  }

  // 1) scope — without it the companion never injects, and the failure would look like "the app
  //    refused us". The write is reported, because it changes device state the operator should know.
  let scopeAdded = false;
  const scope = await readScopeFile();
  phases.scope = { ok: scope.error === null, detail: { packages: scope.packages.length, error: scope.error } };
  if (!scope.packages.includes(name)) {
    if (opts.autoScope === false) {
      return { ok: false, package: name, error: `不在注入作用域：${name}（autoScope:false）`, scope: scope.packages, phases };
    }
    const merged = mergeScope(scope.packages, { add: [name] });
    const written = await writeScopePackages(merged, { version: scope.version, mode: scope.mode });
    if (!written.ok) {
      return { ok: false, package: name, error: `加入注入作用域失败：${written.error}`, phases };
    }
    scopeAdded = true;
    phases.scope = { ok: true, detail: { added: name, packages: written.packages.length } };
  }

  // 2) a live process — reuse when it already has an agent, otherwise cold start and wait.
  let launch: unknown = null;
  const existing = onlineSessionsForPackage(name);
  let rows = existing;
  if (!existing.length || opts.forceRestart === true) {
    const since = Date.now();
    const startedApp = await coldStartPackage(name);
    launch = startedApp;
    if (!startedApp.ok) {
      phases.launch = { ok: false, error: startedApp.error || '启动失败', detail: startedApp };
      return { ok: false, package: name, error: startedApp.error || '启动失败', scopeAdded, phases };
    }
    const waited = await waitForFreshSessions(() => onlineSessionsForPackage(name), {
      sinceMs: since,
      timeoutMs: opts.timeoutMs ?? 60_000,
      settleMs: opts.settleMs ?? 4_000,
    });
    phases.launch = { ok: waited.ok, detail: { mode: startedApp.mode, waitedMs: waited.waitedMs, error: waited.error } };
    if (!waited.ok) {
      return { ok: false, package: name, error: waited.error || '等待注入超时', scopeAdded, launch, phases };
    }
    rows = onlineSessionsForPackage(name);
  } else {
    phases.launch = { ok: true, detail: { mode: 'reuse-online', sessions: existing.length } };
  }

  const main = pickAnalysisSession(rows);
  if (!main) {
    return { ok: false, package: name, error: '目标没有在线进程', scopeAdded, launch, phases };
  }
  const sid = main.sessionId;

  // 3) triage — the "what is this app doing" answer. A failed step is listed, not hidden.
  try {
    const triage = await runRecipe('triage', sid, { captureMs: opts.captureMs ?? 3000 });
    phases.triage = {
      ok: triage.ok,
      detail: {
        summary: triage.summary,
        failedSteps: triage.steps.filter((s) => !s.ok).map((s) => ({ step: s.step, error: s.error })),
      },
    };
  } catch (e) {
    phases.triage = { ok: false, error: (e as Error).message };
  }

  // 4) optional unpack — every DEX into the artifact store.
  if (opts.unpack) {
    try {
      const u = await runUnpackBundle({ package: name, launch: false });
      phases.unpack = { ok: u.ok, detail: { bundle: u.bundle, included: (u.included ?? []).length, error: u.error } };
    } catch (e) {
      phases.unpack = { ok: false, error: (e as Error).message };
    }
  }

  // 5) optional traffic window — what the app actually sends.
  if (opts.httpCaptureMs && opts.httpCaptureMs > 0) {
    try {
      const h = await runRecipe('http_capture', sid, { ms: opts.httpCaptureMs });
      phases.http = { ok: h.ok, detail: h.summary };
    } catch (e) {
      phases.http = { ok: false, error: (e as Error).message };
    }
  }

  return {
    ok: Object.values(phases).every((p) => p.ok),
    package: name,
    session: sid,
    process: main.process,
    pid: main.pid,
    agentVer: main.agentVer,
    entry: main.entry,
    selfModule: main.selfModule,
    scopeAdded,
    elapsedMs: Date.now() - started,
    processes: rows.map((r) => ({ process: r.process, pid: r.pid, session: r.sessionId })),
    phases,
    hint: 'counts grow only while capture is armed; pass httpCaptureMs for a traffic window and unpack:true for all DEX',
  };
}

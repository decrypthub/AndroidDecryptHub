// Class-level Java tracing: hook a whole class (or one method with all its overloads) and turn the
// resulting JAVA_HOOK events into "what ran, in what order, with which arguments".
//
// Three explicit actions instead of one magic call, because the interesting traffic usually has to be
// triggered by the operator or by another tool in between:
//   start  -> java_hook hook_all, hooks stay installed, returns hookIds + matched + a capture cursor
//   digest -> drain the agent's capture ring and digest every event of those hooks
//   stop   -> unhook exactly those ids (never "unhook 0", which would take unrelated hooks with it)
import { captures } from './state.ts';
import { sendCmd } from './service.ts';

export interface JavaTraceSample {
  hookId: number;
  target: string;
  ts: number;
  tid: number;
  arg: string;
  ret: string;
  error: string;
  stack?: string;
}

export interface JavaTraceMethod {
  target: string;
  count: number;
  firstTs: number;
  lastTs: number;
  tids: number[];
  lastArg: string;
  lastReturn: string;
  errorCount: number;
  lastError: string;
}

export interface JavaTraceDigest {
  samples: number;
  methods: JavaTraceMethod[];
  timeline: { ts: number; tid: number; target: string; arg: string; ret: string }[];
  callers: { caller: string; count: number }[];
  observedFrom: number | null;
  observedTo: number | null;
  notes: string[];
}

/** "com.pkg.Cls#method:12" -> "com.pkg.Cls#method"; the stack string is innermost-first. */
export function callerOfStack(stack: string | undefined): string | null {
  if (!stack) return null;
  const first = String(stack).split(' <- ')[0]?.trim();
  if (!first) return null;
  const m = /^([A-Za-z0-9_.$]+#[A-Za-z0-9_$<>]+)(?::\d+)?$/.exec(first);
  return m ? m[1] : (first.length > 120 ? first.slice(0, 120) + '...' : first);
}

export function digestJavaTrace(samples: JavaTraceSample[], opts: { maxTimeline?: number; maxMethods?: number; maxCallers?: number; maxTids?: number } = {}): JavaTraceDigest {
  const maxTimeline = Math.max(1, Math.min(500, opts.maxTimeline ?? 100));
  const maxMethods = Math.max(1, Math.min(100, opts.maxMethods ?? 50));
  const maxCallers = Math.max(1, Math.min(50, opts.maxCallers ?? 20));
  const maxTids = Math.max(1, Math.min(16, opts.maxTids ?? 6));
  const notes: string[] = [];
  const list = (Array.isArray(samples) ? samples : []).filter((s) => s && typeof s.ts === 'number')
    .sort((a, b) => a.ts - b.ts || a.hookId - b.hookId);

  const methodMap = new Map<string, JavaTraceMethod>();
  const callerMap = new Map<string, number>();
  let observedFrom: number | null = null;
  let observedTo: number | null = null;

  for (const s of list) {
    const key = s.target || `hook#${s.hookId}`;
    const m = methodMap.get(key);
    if (m) {
      m.count++;
      if (s.ts < m.firstTs) m.firstTs = s.ts;
      if (s.ts > m.lastTs) m.lastTs = s.ts;
      if (m.tids.length < maxTids && !m.tids.includes(s.tid)) m.tids.push(s.tid);
      m.lastArg = s.arg ?? m.lastArg;
      m.lastReturn = s.ret ?? m.lastReturn;
      if (s.error) { m.errorCount++; m.lastError = s.error; }
    } else {
      methodMap.set(key, {
        target: key, count: 1, firstTs: s.ts, lastTs: s.ts, tids: [s.tid],
        lastArg: s.arg ?? '', lastReturn: s.ret ?? '', errorCount: s.error ? 1 : 0, lastError: s.error ?? '',
      });
    }
    const caller = callerOfStack(s.stack);
    if (caller) callerMap.set(caller, (callerMap.get(caller) ?? 0) + 1);
    if (observedFrom === null || s.ts < observedFrom) observedFrom = s.ts;
    if (observedTo === null || s.ts > observedTo) observedTo = s.ts;
  }

  const timelineAll = list.map((s) => ({ ts: s.ts, tid: s.tid, target: s.target, arg: s.arg ?? '', ret: s.ret ?? '' }));
  const timeline = timelineAll.slice(-maxTimeline);   // newest window is what an analyst reads first
  if (timelineAll.length > timeline.length) notes.push(`timeline shows the newest ${timeline.length} of ${timelineAll.length} events`);
  if (!list.length) notes.push('no JAVA_HOOK events for these hooks: trigger the target (or wait for natural traffic), then digest again');
  if (list.some((s) => s.error)) notes.push('at least one call threw or failed: see methods[].errorCount/lastError');
  const withStack = list.filter((s) => s.stack).length;
  if (withStack && withStack < list.length) notes.push(`caller chains are only available for ${withStack} of ${list.length} events (install with stack:true)`);

  return {
    samples: list.length,
    methods: [...methodMap.values()].sort((a, b) => b.count - a.count).slice(0, maxMethods),
    timeline,
    callers: [...callerMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, maxCallers).map(([caller, count]) => ({ caller, count })),
    observedFrom,
    observedTo,
    notes,
  };
}

export interface JavaTraceStart {
  action: 'start';
  hookIds: number[];
  matched: number;
  partial: boolean;
  limit: number;
  cursor: number;
}

export interface JavaTraceStop {
  action: 'stop';
  unhooked: number[];
  failures: { hookId: number; error: string }[];
}

export interface JavaTraceDigestResult {
  action: 'digest';
  hookIds: number[];
  digest: JavaTraceDigest;
}

function maxCaptureId(session: string): number {
  let max = 0;
  for (const c of captures) if ((c as any).sessionId === session && Number(c.id) > max) max = Number(c.id);
  return max;
}

export async function javaTraceStart(session: string, opts: { className: string; method?: string; params?: string; limit?: number; stack?: boolean }): Promise<JavaTraceStart> {
  if (!opts.className) throw new Error('need className');
  const cursor = maxCaptureId(session);
  const install = await sendCmd(session, 'java_hook', {
    action: 'hook_all', className: opts.className, method: opts.method ?? '', params: opts.params ?? '',
    stack: opts.stack ? 'true' : 'false', limit: Number(opts.limit ?? 0),
  }, 30_000);
  if (!install?.ok) throw new Error(install?.error ?? 'hook_all failed');
  const hookIds = Array.isArray(install.hookIds) ? install.hookIds.map((n: any) => Number(n)) : (install.hookId ? [Number(install.hookId)] : []);
  return {
    action: 'start',
    hookIds,
    matched: Number(install.matched ?? hookIds.length),
    partial: install.partial === true,
    limit: Number(install.limit ?? 0),
    cursor,
  };
}

export async function javaTraceDigest(session: string, opts: { hookIds: number[]; maxTimeline?: number; maxMethods?: number; maxCallers?: number }): Promise<JavaTraceDigestResult> {
  const wanted = new Set((opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n)));
  if (!wanted.size) throw new Error('need hookIds (the ids java_trace start returned)');
  // Pull whatever the agent is still holding before reading the local store: the background loop only
  // drains every 1.5s, and "installed + triggered + digest" would otherwise race it.
  try { await sendCmd(session, 'capture_drain', {}, 8_000); } catch { /* the loop will catch up */ }

  const samples: JavaTraceSample[] = [];
  for (const c of captures) {
    const cap: any = c;
    if (cap.sessionId !== session || cap.func !== 'JAVA_HOOK') continue;
    let text = '';
    try { text = Buffer.from(String(cap.hex ?? ''), 'hex').toString('utf8'); } catch { text = ''; }
    if (!text) continue;
    let event: any = null;
    try { event = JSON.parse(text); } catch { continue; }
    const hookId = Number(event.hookId);
    if (!wanted.has(hookId)) continue;
    samples.push({
      hookId,
      target: String(event.target ?? `hook#${hookId}`),
      ts: Number(cap.ts ?? 0),
      tid: Number(cap.tid ?? 0),
      arg: String(event.arg ?? ''),
      ret: String(event.ret ?? ''),
      error: String(event.error ?? ''),
      ...(event.stack ? { stack: String(event.stack) } : {}),
    });
  }
  const digest = digestJavaTrace(samples, opts);
  return { action: 'digest', hookIds: [...wanted].sort((a, b) => a - b), digest };
}

export async function javaTraceStop(session: string, opts: { hookIds: number[] }): Promise<JavaTraceStop> {
  const ids = (opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n));
  if (!ids.length) throw new Error('need hookIds');
  const unhooked: number[] = [];
  const failures: { hookId: number; error: string }[] = [];
  for (const id of ids) {
    try {
      const r = await sendCmd(session, 'java_hook', { action: 'unhook', hookId: id }, 20_000);
      if (r?.ok) unhooked.push(id); else failures.push({ hookId: id, error: String(r?.error ?? 'unhook failed') });
    } catch (e) {
      failures.push({ hookId: id, error: (e as Error).message });
    }
  }
  return { action: 'stop', unhooked, failures };
}
// Class-level Java tracing: hook a whole class (or one method with all its overloads) and turn the
// resulting JAVA_HOOK events into "what ran, in what order, with which arguments".
//
// Three explicit actions instead of one magic call, because the interesting traffic usually has to be
// triggered by the operator or by another tool in between:
//   start  -> java_hook hook_all, hooks stay installed, returns hookIds + matched + a capture cursor
//   digest -> drain the agent ring THROUGH drainSession (the drain is pop-semantics: only the code
//             that ingests the records into the local store may send it) and digest those hook ids
//   stop   -> unhook exactly those ids; id 0 would mean "all hooks" and is refused
import { captures as stateCaptures, capStats, storeLossNote } from './state.ts';
import { sendCmd as serviceSendCmd, drainSession as serviceDrainSession } from './service.ts';
import { ringNote, type RingHealth } from './syscall_digest.ts';

export interface JavaTraceSample {
  hookId: number;
  target: string;
  ts: number;
  /** Agent-side event time in ns; the drain timestamp is identical for a whole batch. */
  tsNs: number;
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
  empty: boolean;
  complete: boolean;
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
  // The bridge writes this when the walk itself failed; it is not a caller.
  if (!first || first.startsWith('<stack capture failed')) return null;
  // Normalise "pkg.Cls#m:12" and hidden-class forms "pkg.Cls$$Lambda$1/0x1234#m:12".
  const m = /^([A-Za-z0-9_.$]+)(\/0x[0-9a-f]+)?#([A-Za-z0-9_$<>]+)(?::\d+)?$/i.exec(first);
  if (m) return `${m[1]}#${m[3]}`;
  return first.length > 120 ? first.slice(0, 120) + '...' : first;
}

function sampleOrderKey(s: JavaTraceSample): number {
  // Agent time first (a drain batch shares one drain timestamp, so ts alone cannot order events),
  // then the drain timestamp, then the hook id as a last resort.
  if (Number.isFinite(s.tsNs) && s.tsNs > 0) return s.tsNs;
  return s.ts > 0 ? s.ts * 1e6 : s.hookId;
}

export function digestJavaTrace(samples: JavaTraceSample[], opts: { maxTimeline?: number; maxMethods?: number; maxCallers?: number; maxTids?: number } = {}): JavaTraceDigest {
  const maxTimeline = Math.max(1, Math.min(500, opts.maxTimeline ?? 100));
  const maxMethods = Math.max(1, Math.min(100, opts.maxMethods ?? 50));
  const maxCallers = Math.max(1, Math.min(50, opts.maxCallers ?? 20));
  const maxTids = Math.max(1, Math.min(16, opts.maxTids ?? 6));
  const notes: string[] = [];
  const list = (Array.isArray(samples) ? samples : []).filter((s) => s && typeof s === 'object')
    .slice()
    .sort((a, b) => sampleOrderKey(a) - sampleOrderKey(b));

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
  const timeline = timelineAll.slice(-maxTimeline);   // newest window first: that is what an analyst reads
  if (timelineAll.length > timeline.length) notes.push(`timeline shows the newest ${timeline.length} of ${timelineAll.length} events`);
  if (methodMap.size > maxMethods) notes.push(`methods: showing the top ${maxMethods} of ${methodMap.size} by hit count`);
  if (callerMap.size > maxCallers) notes.push(`callers: showing the top ${maxCallers} of ${callerMap.size}`);
  if (!list.length) notes.push('no JAVA_HOOK events for these hooks: trigger the target (or wait for natural traffic), then digest again');
  if (list.some((s) => s.error)) notes.push('at least one call threw or failed: see methods[].errorCount/lastError');
  const withStack = list.filter((s) => s.stack).length;
  if (list.length && !withStack) notes.push('no caller chains in these events: start the trace with stack:true to get them');
  else if (withStack && withStack < list.length) notes.push(`caller chains are only available for ${withStack} of ${list.length} events`);

  return {
    samples: list.length,
    empty: list.length === 0,
    complete: withStack === list.length || list.length === 0,
    methods: [...methodMap.values()].sort((a, b) => b.count - a.count).slice(0, maxMethods),
    timeline,
    callers: [...callerMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, maxCallers).map(([caller, count]) => ({ caller, count })),
    observedFrom,
    observedTo,
    notes,
  };
}

export interface JavaTraceDeps {
  sendCmd: (session: string, op: string, args?: Record<string, unknown>, timeoutMs?: number) => Promise<any>;
  captures: Array<{ id: number; sessionId: string; func: string; tid: number; ts: number; tsNs: number; hex: string }>;
  drainSession: (session: string) => Promise<{ ok: boolean; response?: any; error?: string }>;
}

const defaultDeps: JavaTraceDeps = {
  sendCmd: (session, op, args, timeoutMs) => serviceSendCmd(session, op, args, timeoutMs),
  captures: stateCaptures as any,
  drainSession: (session) => serviceDrainSession(session),
};

export interface JavaTraceStart {
  action: 'start';
  hookIds: number[];
  matched: number;
  partial: boolean;
  limit: number;
  /** Capture cursor: pass it to digest as sinceCaptureId so a second digest only sees newer events. */
  cursor: number;
}

export interface JavaTraceStop {
  action: 'stop';
  ok: boolean;
  unhooked: number[];
  failures: { hookId: number; error: string }[];
}

export interface JavaTraceDigestResult {
  action: 'digest';
  hookIds: number[];
  drain: { ok: boolean; error?: string };
  /** Capture-ring health: a trace taken while the ring was dropping is incomplete. */
  ring: RingHealth | null;
  digest: JavaTraceDigest;
}

function maxCaptureId(session: string, deps: JavaTraceDeps): number {
  let max = 0;
  for (const c of deps.captures) if (c.sessionId === session && Number(c.id) > max) max = Number(c.id);
  return max;
}

export async function javaTraceStart(session: string, opts: { className: string; method?: string; params?: string; limit?: number; stack?: boolean }, deps: JavaTraceDeps = defaultDeps): Promise<JavaTraceStart> {
  if (!opts.className) throw new Error('need className');
  const cursor = maxCaptureId(session, deps);
  const install = await deps.sendCmd(session, 'java_hook', {
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

export async function javaTraceDigest(session: string, opts: { hookIds: number[]; sinceCaptureId?: number; maxTimeline?: number; maxMethods?: number; maxCallers?: number }, deps: JavaTraceDeps = defaultDeps): Promise<JavaTraceDigestResult> {
  const wanted = new Set((opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n) && n > 0));
  if (!wanted.size) throw new Error('need hookIds (the ids java_trace start returned); id 0 would mean every hook');
  // The agent ring is pop-semantics: only drainSession may take records out of it, because only that
  // path ingests them into the local store. Sending capture_drain directly here would delete the very
  // events this digest is about (plus every other capture in the same batch).
  const drain = await deps.drainSession(session);

  const since = Number.isFinite(Number(opts.sinceCaptureId)) ? Number(opts.sinceCaptureId) : 0;
  const samples: JavaTraceSample[] = [];
  for (const cap of deps.captures) {
    if (cap.sessionId !== session || cap.func !== 'JAVA_HOOK') continue;
    if (since && Number(cap.id) <= since) continue;
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
      tsNs: Number(cap.tsNs ?? 0),
      tid: Number(cap.tid ?? 0),
      arg: String(event.arg ?? ''),
      ret: String(event.ret ?? ''),
      error: String(event.error ?? ''),
      ...(event.stack ? { stack: String(event.stack) } : {}),
    });
  }
  const digest = digestJavaTrace(samples, opts);
  if (!drain.ok) digest.notes.push(`capture drain failed (${drain.error ?? 'unknown'}): the digest reads whatever the store already holds`);
  const stat = capStats.get(session) ?? null;
  const ring = stat
    ? { seq: stat.seq, emitted: stat.emitted, dropped: stat.dropped, backlog: stat.backlog, complete: stat.complete }
    : null;
  // The store cap is the second loss source (v4.96): the agent ring note above says nothing about
  // records the daemon already evicted from its own list. This digest windows by capture id.
  const storeNote = storeLossNote(session, { sinceCaptureId: since || null });
  if (storeNote) digest.notes.push(storeNote);
  const lossy = ringNote(ring, 'the trace may be missing events');
  if (lossy) digest.notes.push(lossy);
  return { action: 'digest', hookIds: [...wanted].sort((a, b) => a - b), drain: { ok: drain.ok, ...(drain.error ? { error: drain.error } : {}) }, ring, digest };
}

export async function javaTraceStop(session: string, opts: { hookIds: number[] }, deps: JavaTraceDeps = defaultDeps): Promise<JavaTraceStop> {
  const raw = (opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n));
  // id 0 is "unhook EVERY Java hook" in the agent protocol - never let a batch tool trigger that.
  const bad = raw.filter((n) => n <= 0);
  if (bad.length) throw new Error(`refusing to unhook hookId ${bad[0]}: id 0 means every hook; pass the explicit ids from start`);
  const ids = [...new Set(raw)];
  if (!ids.length) throw new Error('need hookIds');
  const unhooked: number[] = [];
  const failures: { hookId: number; error: string }[] = [];
  for (const id of ids) {
    try {
      const r = await deps.sendCmd(session, 'java_hook', { action: 'unhook', hookId: id }, 20_000);
      if (r?.ok) unhooked.push(id); else failures.push({ hookId: id, error: String(r?.error ?? 'unhook failed') });
    } catch (e) {
      failures.push({ hookId: id, error: (e as Error).message });
    }
  }
  return { action: 'stop', ok: failures.length === 0, unhooked, failures };
}
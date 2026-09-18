// One-shot syscall tracing: watch -> digest -> stop, with the static attribution threaded from the
// watch into the digest by the tool instead of by hand.
//
// Three phases, same shape as java_trace, because the traffic usually has to be triggered between
// them. The value over calling syscall_watch/syscall_digest/native_hook by hand: `expected`
// {hookId: syscallNr} is built from the watch response (so a mis-attribution shows up as a mismatch
// instead of being copied wrong), the digest goes through the shared drainSession, and stop unhooks
// exactly the ids this run installed.
import { watchSyscalls, type SyscallWatchOptions } from './syscall_watch.ts';
import { syscallDigest, type SyscallDigestResult } from './syscall_digest.ts';
import { nativeUnhookAll } from './native_hook_all.ts';

export interface SyscallTraceDeps {
  watch: (session: string, opts: SyscallWatchOptions) => Promise<any>;
  digest: (session: string, opts: { hookIds: number[]; expected: Record<number, number>; sinceMs?: number; decode?: boolean; decodeLimit?: number; maxGroups?: number }) => Promise<SyscallDigestResult>;
  unhook: (session: string, hookIds: number[]) => Promise<{ unhooked: number[]; failures: { hookId: number; error: string }[] }>;
}

const defaultDeps: SyscallTraceDeps = {
  watch: (session, opts) => watchSyscalls(session, opts),
  digest: (session, opts) => syscallDigest(session, opts),
  unhook: (session, hookIds) => nativeUnhookAll(session, hookIds),
};

export interface SyscallTraceStart {
  action: 'start';
  module: string;
  hookIds: number[];
  expected: Record<number, number>;
  installedCount: number;
  matchedCount: number;
  svcCount: number;
  unattributed: string[];
  note: string;
}

export async function syscallTraceStart(session: string, opts: SyscallWatchOptions, deps: SyscallTraceDeps = defaultDeps): Promise<SyscallTraceStart> {
  const watch = await deps.watch(session, opts);
  const hooks: any[] = Array.isArray(watch?.hooks) ? watch.hooks : [];
  const hookIds: number[] = [];
  const expected: Record<number, number> = {};
  const unattributed: string[] = [];
  for (const h of hooks) {
    const id = Number(h?.hookId);
    if (!Number.isFinite(id) || id <= 0) continue;
    hookIds.push(id);
    const nr = Number(h?.syscall?.nr);
    if (Number.isFinite(nr)) expected[id] = nr;
    else unattributed.push(String(h?.addr ?? `hook#${id}`));
  }
  if (!hookIds.length) throw new Error('no hook was installed: the module has no matching svc site (check module/syscalls filter)');
  const notes: string[] = [];
  if (unattributed.length) notes.push(`${unattributed.length} site(s) had no statically attributed number: their events still report the runtime x8, but a filter-based attribution cannot be checked for them`);
  if (watch?.scanTruncated) notes.push('the static scanner hit its site cap: later svc sites were not examined');
  if (Number(watch?.throttleMs) > 0) notes.push(`each hook emits at most one event per ${Number(watch.throttleMs)} ms: the digest counts every hit through status (hits - throttled), so a thinned stream is visible instead of looking like a quiet target`);
  return {
    action: 'start',
    module: String(watch?.module ?? opts.module),
    hookIds,
    expected,
    installedCount: Number(watch?.installedCount ?? hookIds.length),
    matchedCount: Number(watch?.matchedCount ?? hookIds.length),
    svcCount: Number(watch?.svcCount ?? 0),
    unattributed,
    note: notes.join('; ') || 'hooks installed; trigger the target or wait for natural traffic, then call action:digest',
  };
}

export async function syscallTraceDigest(session: string, opts: { hookIds: number[]; expected?: Record<string, number> | Record<number, number>; sinceMs?: number; decode?: boolean; decodeLimit?: number; maxGroups?: number }, deps: SyscallTraceDeps = defaultDeps): Promise<{ action: 'digest'; digest: SyscallDigestResult }> {
  const ids = [...new Set((opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n) && n > 0))];
  if (!ids.length) throw new Error('need hookIds (the ids syscall_trace start returned)');
  const expected: Record<number, number> = {};
  for (const [k, v] of Object.entries(opts.expected ?? {})) {
    const id = Number(k), nr = Number(v);
    if (Number.isFinite(id) && Number.isFinite(nr)) expected[id] = nr;
  }
  const digest = await deps.digest(session, { hookIds: ids, expected, sinceMs: opts.sinceMs, decode: opts.decode, decodeLimit: opts.decodeLimit, maxGroups: opts.maxGroups });
  return { action: 'digest', digest };
}

export async function syscallTraceStop(session: string, opts: { hookIds: number[] }, deps: SyscallTraceDeps = defaultDeps): Promise<{ action: 'stop'; ok: boolean; unhooked: number[]; failures: { hookId: number; error: string }[] }> {
  const ids = [...new Set((opts.hookIds ?? []).map((n) => Number(n)).filter((n) => Number.isFinite(n) && n > 0))];
  if (!ids.length) throw new Error('need hookIds; a bare unhook-all is intentionally not part of this tool');
  const r = await deps.unhook(session, ids);
  return { action: 'stop', ok: r.failures.length === 0, unhooked: r.unhooked, failures: r.failures };
}
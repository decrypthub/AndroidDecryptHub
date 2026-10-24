// Read-only procfs diagnostics independent of agent transport. A frozen agent
// cannot answer commands; it must not be diagnosed by sending it another RPC.
import { posix } from 'node:path';
import { rootAdb, selectRootSerial } from './root_watch.ts';
import { parseProcStat, normalizeStarttimeTicks } from './proc_identity.ts';
export { parseProcStat } from './proc_identity.ts';

export type RuntimeTarget = { sessionId: string; pid: number; uid: number; package: string; process?: string; starttimeTicks?: string };
type ProcSnapshot = { exists: boolean | null; status?: string; stat?: string; cmdline?: string; wchan?: string };
type ThreadSnapshot = { tid: number; status?: string; stat?: string; wchan?: string };
type FreezeFile = { path: string; kind: 'events' | 'request' | 'v1'; text?: string };
type RuntimeState = 'process-exited' | 'identity-mismatch' | 'frozen' | 'traced' | 'running' | 'unknown';
type DiagnosticDeps = { selectSerial: typeof selectRootSerial; adb: typeof rootAdb };
const defaults: DiagnosticDeps = { selectSerial: selectRootSerial, adb: rootAdb };

function int(n: unknown, fallback: number, low: number, high: number, name: string) {
  const value = n === undefined ? fallback : n;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < low || value > high) throw new Error(`${name} must be an integer ${low}..${high}`);
  return value;
}
export function normalizeRuntimeDiagnostics(target: RuntimeTarget, a: Record<string, any> = {}) {
  int(target.pid, 0, 1, 0x7fffffff, 'target pid');
  int(target.uid, -1, 0, 0x7fffffff, 'target uid');
  const processName = target.process || target.package;
  if (typeof processName !== 'string' || !processName || processName.length > 256 || /[\0\r\n]/.test(processName)) throw new Error('target process/package must be an exact process name');
  if (target.starttimeTicks !== undefined && normalizeStarttimeTicks(target.starttimeTicks) === undefined) throw new Error('target starttimeTicks must be decimal procfs ticks');
  if (a.serial !== undefined && (typeof a.serial !== 'string' || !a.serial || /[\0\r\n]/.test(a.serial))) throw new Error('serial must be a nonempty ADB serial');
  return { processName, afterTid: int(a.afterTid, 0, 0, 0x7fffffff, 'afterTid'),
    limit: int(a.limit, 64, 1, 256, 'limit'), timeoutMs: int(a.timeoutMs, 10000, 1000, 20000, 'timeoutMs') };
}
export function parseProcStatus(text?: string) {
  const field = (key: string) => new RegExp(`^${key}:\\s*([^\\r\\n]*)`, 'm').exec(text ?? '')?.[1];
  const numeric = (key: string) => { const v = field(key)?.split(/\s+/)[0]; return v !== undefined && /^\d+$/.test(v) ? Number(v) : null; };
  return { name: field('Name') ?? null, state: field('State')?.split(/\s+/)[0] ?? null,
    pid: numeric('Pid'), tgid: numeric('Tgid'), uid: numeric('Uid'), tracerPid: numeric('TracerPid'), threads: numeric('Threads') };
}
function identity(target: RuntimeTarget, snapshot: ProcSnapshot) {
  const status = parseProcStatus(snapshot.status), stat = parseProcStat(snapshot.stat);
  const processName = snapshot.cmdline?.split('\0')[0];
  const expected = target.process || target.package;
  const mismatches: string[] = [];
  if (status.pid !== null && status.pid !== target.pid) mismatches.push('status PID differs');
  if (status.tgid !== null && status.tgid !== target.pid) mismatches.push('status Tgid differs');
  if (status.uid !== null && status.uid !== target.uid) mismatches.push('UID differs');
  if (stat && stat.pid !== target.pid) mismatches.push('stat PID differs');
  if (stat && target.starttimeTicks !== undefined && stat.starttime !== target.starttimeTicks) mismatches.push('starttime differs from session generation');
  if (processName !== undefined && processName !== expected && !['Z', 'X', 'x'].includes(status.state ?? '')) mismatches.push('cmdline differs');
  return { status, stat, processName, mismatches, verified: !mismatches.length && snapshot.exists === true && status.pid === target.pid &&
    status.tgid === target.pid && status.uid === target.uid && stat?.pid === target.pid && processName === expected };
}
function frozenWchan(text?: string) { return /^(?:do_freezer_trap|__refrigerator|refrigerator)$/.test(text?.trim() ?? ''); }

// A cgroup path is never used as a shell fragment. Only known freezer mounts,
// absolute paths, and descendants without '..' or control characters qualify.
export function runtimeFreezeFiles(cgroup: string, mountinfo: string): FreezeFile[] {
  const decode = (s: string) => s.replace(/\\([0-7]{3})/g, (_, n) => String.fromCharCode(parseInt(n, 8)));
  const safe = (s: string) => s.startsWith('/') && !/[\x00-\x1f\x7f]/.test(s) && !s.split('/').includes('..');
  const groups = cgroup.split(/\r?\n/).map(line => /^(\d+):([^:]*):(\/.*)$/.exec(line)).filter(Boolean);
  const result: FreezeFile[] = [];
  for (const line of mountinfo.split(/\r?\n/)) {
    const [left, right] = line.split(' - '); if (!right) continue;
    const fields = left.split(' '), fs = right.split(' ');
    const v2 = fs[0] === 'cgroup2';
    if (!v2 && !(fs[0] === 'cgroup' && fs[2]?.split(',').includes('freezer'))) continue;
    const root = decode(fields[3] ?? ''), mount = decode(fields[4] ?? '');
    if (!safe(root) || !safe(mount) || !(mount === '/dev/freezer' || mount.startsWith('/dev/freezer/') || mount === '/sys/fs/cgroup' || mount.startsWith('/sys/fs/cgroup/'))) continue;
    for (const group of groups) {
      if (v2 ? group[2] !== '' : !group[2].split(',').includes('freezer')) continue;
      const path = decode(group[3]);
      if (!safe(path) || !(root === '/' || path === root || path.startsWith(root + '/'))) continue;
      const directory = posix.join(mount, root === '/' ? path : path.slice(root.length));
      if (v2) result.push({ path: posix.join(directory, 'cgroup.events'), kind: 'events' }, { path: posix.join(directory, 'cgroup.freeze'), kind: 'request' });
      else result.push({ path: posix.join(directory, 'freezer.state'), kind: 'v1' });
    }
  }
  return [...new Map(result.map(file => [file.path, file])).values()].slice(0, 16);
}

export function classifyRuntime(target: RuntimeTarget, before: ProcSnapshot, after: ProcSnapshot,
  threads: ThreadSnapshot[] = [], files: FreezeFile[] = []) {
  const first = identity(target, before), last = identity(target, after);
  const reasons = [...first.mismatches, ...last.mismatches];
  const reused = first.stat && last.stat && first.stat.starttime !== last.stat.starttime;
  if (reused) reasons.push('PID starttime changed during observation');
  const threadFacts = threads.map(thread => {
    const status = parseProcStatus(thread.status), stat = parseProcStat(thread.stat);
    return { tid: thread.tid, ...status, starttime: stat?.starttime ?? null, wchan: thread.wchan?.trim() ?? null,
      frozen: frozenWchan(thread.wchan), eligibleForRootWatch: status.pid === thread.tid && status.tgid === target.pid &&
        status.uid === target.uid && stat?.pid === thread.tid && !['Z', 'X', 'x'].includes(status.state ?? '') };
  });
  const freezeEvidence: string[] = [];
  if (frozenWchan(after.wchan)) freezeEvidence.push(`process wchan=${after.wchan.trim()}`);
  for (const thread of threadFacts) if (thread.eligibleForRootWatch && thread.frozen) freezeEvidence.push(`TID ${thread.tid} wchan=${thread.wchan}`);
  let requested = false, requestObserved = false, thawed = false;
  for (const file of files) {
    if ((file.kind === 'events' && /^frozen\s+1\s*$/m.test(file.text ?? '')) || (file.kind === 'v1' && file.text?.trim() === 'FROZEN')) freezeEvidence.push(`${file.path}: frozen`);
    if ((file.kind === 'request' && file.text?.trim() === '1') || (file.kind === 'v1' && ['FREEZING', 'FROZEN'].includes(file.text?.trim() ?? ''))) requested = true;
    if ((file.kind === 'request' && /^[01]$/.test(file.text?.trim() ?? '')) || (file.kind === 'v1' && ['FROZEN', 'FREEZING', 'THAWED'].includes(file.text?.trim() ?? ''))) requestObserved = true;
    if ((file.kind === 'events' && /^frozen\s+0\s*$/m.test(file.text ?? '')) || (file.kind === 'v1' && file.text?.trim() === 'THAWED')) thawed = true;
  }
  const tracerPids = [...new Set([last.status.tracerPid, ...threadFacts.filter(thread => thread.eligibleForRootWatch).map(thread => thread.tracerPid)].filter((pid): pid is number => pid !== null && pid > 0))];
  const dead = after.exists === false || ['Z', 'X', 'x'].includes(last.status.state ?? '');
  let state: RuntimeState;
  if (reasons.length) state = 'identity-mismatch';
  else if (dead || before.exists === false) state = 'process-exited';
  else if (!first.verified || !last.verified) state = 'unknown';
  else if (freezeEvidence.length) state = 'frozen';
  else if (tracerPids.length) state = 'traced';
  else if (requested || ['T', 't'].includes(last.status.state ?? '')) state = 'unknown';
  else state = 'running';
  const suggestions: Record<RuntimeState, string[]> = {
    'process-exited': ['Refresh process_list and select the current exact process; this observation did not restart it.'],
    'identity-mismatch': ['Refresh the session and PID/UID identity before reading memory or arming root_watch.'],
    frozen: ['One or more observed tasks are frozen; the agent command thread may be among them. If interaction is intended, bring the app to the foreground explicitly, then diagnose again.'],
    traced: ['Inspect the reported TracerPid before attaching another tracer; no ptrace operation was performed.'],
    running: ['Use an existing eligible TID for root_watch and trigger the intended call on that same thread. A live process does not prove agent responsiveness.'],
    unknown: ['Read the missing facts/errors first; a pending freezer request, stopped task, or unreadable procfs is not proof of a hung agent.'],
  };
  const identityVerified = first.verified && last.verified && !reused && reasons.length === 0;
  return { state, identityVerified, identity: { expected: { pid: target.pid, uid: target.uid, process: target.process || target.package, starttimeTicks: target.starttimeTicks ?? null },
    observed: { pid: last.status.pid, uid: last.status.uid, process: last.processName ?? null, starttime: last.stat?.starttime ?? null }, reasons },
    facts: { schedulerState: last.status.state, wchan: after.wchan?.trim() ?? null, tracerPids,
      frozen: freezeEvidence.length > 0 ? true : thawed ? false : null, freezeRequested: requestObserved ? requested : null, freezeEvidence,
      reportedThreads: last.status.threads, agentResponsive: null },
    threads: identityVerified ? threadFacts : [], freezer: identityVerified ? files.map(file => ({ ...file, readable: file.text !== undefined })) : [], suggestions: suggestions[state],
    scope: 'Read-only, non-atomic procfs snapshot of existing threads. No agent RPC, ptrace, signals, app lifecycle change, or security-policy change. New threads are not inherited.',
    sessionGenerationVerified: identityVerified && target.starttimeTicks !== undefined,
    identityScope: target.starttimeTicks === undefined ? 'PID/UID/cmdline are stable during this snapshot. Without session starttimeTicks, a prior same-identity PID reuse cannot be excluded.' : 'PID/UID/cmdline and process generation match the supplied session starttimeTicks.' };
}

const quote = (s: string) => `'${s.replaceAll("'", "'\\''")}'`;
const prologue = `emit_file() {
  if [ -r "$2" ]; then
    v=$(head -c "$3" "$2" 2>/dev/null | base64 | tr -d '\\r\\n')
    printf 'ADH_DIAG_V1 %s ok %s\\n' "$1" "$v"
  else printf 'ADH_DIAG_V1 %s unreadable -\\n' "$1"; fi
}
emit_value() { v=$(printf '%s' "$2" | base64 | tr -d '\\r\\n'); printf 'ADH_DIAG_V1 %s ok %s\\n' "$1" "$v"; }
emit_status() {
  if [ -r "$2" ]; then
    v=$(grep -E '^(Name|State|Tgid|Pid|TracerPid|Uid|Threads):' "$2" 2>/dev/null | base64 | tr -d '\\r\\n')
    printf 'ADH_DIAG_V1 %s ok %s\\n' "$1" "$v"
  else printf 'ADH_DIAG_V1 %s unreadable -\\n' "$1"; fi
}
`;
function procScript(pid: number) {
  return `if [ -d /proc/${pid} ]; then emit_value exists 1
elif [ -r /proc ] && [ -x /proc ]; then
  entries=$(ls -1 /proc 2>/dev/null); rc=$?
  if [ "$rc" -ne 0 ] || printf '%s\\n' "$entries" | grep -qx ${pid}; then emit_value exists unknown
  else emit_value exists 0; fi
else emit_value exists unknown; fi
emit_status status /proc/${pid}/status
emit_file stat /proc/${pid}/stat 8192
emit_file cmdline /proc/${pid}/cmdline 4096
emit_file wchan /proc/${pid}/wchan 256
`;
}
function decodeWire(text: string) {
  const values: Record<string, string | undefined> = {};
  const unreadable: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('ADH_DIAG_V1 ')) continue;
    const match = /^ADH_DIAG_V1 ([a-z][a-z0-9_]{0,64}) (ok|unreadable) ([A-Za-z0-9+/=]*|-)\s*$/.exec(line);
    if (!match || Object.hasOwn(values, match[1])) throw new Error('Malformed or duplicate runtime diagnostic record');
    const [, key, status, value] = match;
    if (status === 'ok') values[key] = Buffer.from(value, 'base64').toString('utf8');
    else { values[key] = undefined; unreadable.push(key); }
  }
  return { values, unreadable };
}
function procFromWire(values: Record<string, string | undefined>): ProcSnapshot {
  return { exists: values.exists === '1' ? true : values.exists === '0' ? false : null,
    status: values.status, stat: values.stat, cmdline: values.cmdline, wchan: values.wchan };
}

export async function diagnoseRuntime(target: RuntimeTarget, a: Record<string, any> = {}, deps: DiagnosticDeps = defaults) {
  const spec = normalizeRuntimeDiagnostics(target, a), serial = await deps.selectSerial(a.serial);
  const observedAt = new Date().toISOString();
  // adb shell rebuilds a remote shell command from argv. Quote the complete
  // script for that shell so metacharacters/functions reach su -c as ONE arg.
  const root = (script: string) => deps.adb(serial, ['shell', 'su', '-c', quote(script)], spec.timeoutMs);
  // Root is checked before inspecting another UID. No executable/helper is uploaded.
  if ((await root('id -u')).trim() !== '0') throw new Error('runtime_diagnostics requires root for exact cross-UID procfs reads; no device state was changed');
  const initial = decodeWire(await root(prologue + procScript(target.pid) +
    `emit_file cgroup /proc/${target.pid}/cgroup 8192\nemit_file mountinfo /proc/self/mountinfo 131072\n`));
  const before = procFromWire(initial.values), first = identity(target, before);
  if (!first.verified) return { session: target.sessionId, serial, observedAt, ...classifyRuntime(target, before, before), errors: initial.unreadable,
    page: { afterTid: spec.afterTid, nextTid: spec.afterTid, hasMore: false, returned: 0, observedEntries: null } };
  const files = runtimeFreezeFiles(initial.values.cgroup ?? '', initial.values.mountinfo ?? '');
  let script = prologue + 'count=0; emitted=0; more=0\n';
  script += `for tid in $(ls -1 /proc/${target.pid}/task 2>/dev/null | sort -n); do
  case "$tid" in ''|*[!0-9]*) continue;; esac
  count=$((count+1))
  [ "$tid" -gt ${spec.afterTid} ] || continue
  if [ "$emitted" -ge ${spec.limit} ]; then more=1; continue; fi
  emitted=$((emitted+1))
  emit_status tstatus_$tid /proc/${target.pid}/task/$tid/status
  emit_file tstat_$tid /proc/${target.pid}/task/$tid/stat 2048
  emit_file twchan_$tid /proc/${target.pid}/task/$tid/wchan 256
done
emit_value threads_count "$count"
emit_value threads_more "$more"
`;
  files.forEach((file, index) => { script += `emit_file freeze_${index} ${quote(file.path)} 4096\n`; });
  script += procScript(target.pid) + `emit_file cgroup /proc/${target.pid}/cgroup 8192\n`;
  let detail: ReturnType<typeof decodeWire>;
  try { detail = decodeWire(await root(script)); }
  catch (error) { return { session: target.sessionId, serial, observedAt, ...classifyRuntime(target, before, { exists: null }),
    errors: [...initial.unreadable, String(error)], page: { afterTid: spec.afterTid, nextTid: spec.afterTid, hasMore: false, returned: 0, observedEntries: null } }; }
  const values = detail.values;
  const threads = Object.keys(values).filter(key => /^tstatus_\d+$/.test(key)).map(key => Number(key.slice(8))).sort((a, b) => a - b)
    .map(tid => ({ tid, status: values[`tstatus_${tid}`], stat: values[`tstat_${tid}`], wchan: values[`twchan_${tid}`] }));
  const cgroupChanged = values.cgroup !== initial.values.cgroup;
  files.forEach((file, index) => { file.text = cgroupChanged ? undefined : values[`freeze_${index}`]; });
  const result = classifyRuntime(target, before, procFromWire(values), threads, files);
  return { session: target.sessionId, serial, observedAt, ...result, errors: [...initial.unreadable, ...detail.unreadable,
    ...(cgroupChanged ? ['cgroup changed during observation; freezer-file evidence discarded'] : [])],
    page: { afterTid: spec.afterTid, nextTid: threads.at(-1)?.tid ?? spec.afterTid, hasMore: values.threads_more === '1',
      returned: result.threads.length, observedEntries: /^\d+$/.test(values.threads_count ?? '') ? Number(values.threads_count) : null } };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { normalizeRuntimeDiagnostics, parseProcStatus, parseProcStat, runtimeFreezeFiles,
  classifyRuntime, diagnoseRuntime } from '../src/runtime_diagnostics.ts';

const archive = JSON.parse(readFileSync(new URL('./fixtures/runtime_diagnostics.json', import.meta.url), 'utf8'));
const { target, process: live, thread } = archive;

test('proc archive parses state/identity and stat comm containing spaces and parentheses', () => {
  const status = parseProcStatus(live.status);
  assert.equal(status.uid, target.uid);
  assert.equal(status.tracerPid, 0);
  assert.equal(status.threads, 3);
  assert.deepEqual(parseProcStat(thread.stat), { pid: 102, state: 'D', starttime: '123460' });
  assert.equal(parseProcStat('101 (broken) S 1 2'), null);
  assert.equal(parseProcStatus('not readable').uid, null);
});

test('runtime diagnosis rejects ambiguous identities and unsafe or unbounded parameters', () => {
  assert.deepEqual(normalizeRuntimeDiagnostics(target), { processName: target.package, afterTid: 0, limit: 64, timeoutMs: 10000 });
  for (const patch of [{ pid: 0 }, { pid: '101' }, { uid: -1 }, { process: 'bad\0name' }, { package: '' }, { starttimeTicks: 123456 }, { starttimeTicks: '12;id' }])
    assert.throws(() => normalizeRuntimeDiagnostics({ ...target, ...patch }));
  for (const patch of [{ limit: 257 }, { limit: 0 }, { afterTid: -1 }, { afterTid: '102' }, { timeoutMs: 999 }, { serial: '' }, { serial: 'a\nb' }])
    assert.throws(() => normalizeRuntimeDiagnostics(target, patch));
});

test('freezer detection uses observed thread/cgroup facts and does not label ordinary sleeping tasks frozen', () => {
  const normal = classifyRuntime(target, live, live);
  assert.equal(normal.state, 'running');
  assert.equal(normal.facts.frozen, null);
  assert.equal(normal.facts.agentResponsive, null);
  assert.equal(normal.sessionGenerationVerified, false);
  assert.equal(classifyRuntime({ ...target, starttimeTicks: '123456' }, live, live).sessionGenerationVerified, true);
  const frozen = classifyRuntime(target, live, live, [thread]);
  assert.equal(frozen.state, 'frozen');
  assert.equal(frozen.threads[0].eligibleForRootWatch, true);
  assert.match(frozen.facts.freezeEvidence[0], /102.*do_freezer_trap/);
  const files = runtimeFreezeFiles(archive.cgroup, archive.mountinfo);
  assert.deepEqual(files.map(file => file.path), ['/sys/fs/cgroup/uid_10234/pid_101/cgroup.events', '/sys/fs/cgroup/uid_10234/pid_101/cgroup.freeze']);
  const evidence = files.map(file => ({ ...file, text: file.kind === 'events' ? 'populated 1\nfrozen 1\n' : '1\n' }));
  assert.equal(classifyRuntime(target, live, live, [], evidence).state, 'frozen');
  assert.equal(classifyRuntime(target, live, live, [], [{ ...files[1], text: '1\n' }]).state, 'unknown', 'requested is not completed');
  assert.equal(classifyRuntime(target, live, live, [], [{ ...files[0], text: 'frozen 0\n' }]).facts.frozen, false);
});

test('identity mismatch, PID reuse, exit, tracing, stopped state and unreadable data remain distinct', () => {
  const changed = { ...live, stat: live.stat.replace('123456 ', '123457 ') };
  assert.equal(classifyRuntime(target, live, changed, [thread]).state, 'identity-mismatch');
  assert.equal(classifyRuntime(target, live, changed, [thread]).threads.length, 0);
  assert.equal(classifyRuntime({ ...target, starttimeTicks: '123455' }, live, live).state, 'identity-mismatch');
  assert.equal(classifyRuntime(target, live, { ...live, status: live.status.replace(/10234/g, '10345') }).state, 'identity-mismatch');
  assert.equal(classifyRuntime(target, live, { ...live, cmdline: 'com.example.other\0' }).state, 'identity-mismatch');
  assert.equal(classifyRuntime(target, live, { exists: false }).state, 'process-exited');
  assert.equal(classifyRuntime(target, { exists: null }, { exists: null }).state, 'unknown');
  assert.equal(classifyRuntime(target, live, { ...live, status: live.status.replace('TracerPid:\t0', 'TracerPid:\t777') }).state, 'traced');
  assert.equal(classifyRuntime(target, live, { ...live, status: live.status.replace('State:\tS', 'State:\tT') }).state, 'unknown');
  const unrelated = { ...thread, status: thread.status.replace('Tgid:\t101', 'Tgid:\t999') };
  assert.equal(classifyRuntime(target, live, live, [unrelated]).state, 'running', 'unverified thread cannot establish freezer evidence');
  assert.equal(classifyRuntime(target, live, live, [unrelated]).threads[0].eligibleForRootWatch, false);
});

test('freezer mount parsing respects v1, mount roots, and confines paths without guessing', () => {
  assert.deepEqual(runtimeFreezeFiles('5:cpu,freezer:/apps/pid_101\n', '36 29 0:29 /apps /dev/freezer rw - cgroup freezer rw,cpu,freezer\n'), [
    { path: '/dev/freezer/pid_101/freezer.state', kind: 'v1' },
  ]);
  for (const path of ['/../escape', '/apps/../../escape', '/apps/evil\u0001'])
    assert.deepEqual(runtimeFreezeFiles(`0::${path}\n`, archive.mountinfo), []);
  assert.deepEqual(runtimeFreezeFiles(archive.cgroup, archive.mountinfo.replace('/sys/fs/cgroup', '/arbitrary/mount')), []);
  assert.equal(classifyRuntime(target, live, live, [], [{ path: '/dev/freezer/apps/freezer.state', kind: 'v1', text: 'FROZEN\n' }]).state, 'frozen');
});

function wire(values: Record<string, any>) {
  return Object.entries(values).map(([key, value]) => value === undefined ? `ADH_DIAG_V1 ${key} unreadable -\n` :
    `ADH_DIAG_V1 ${key} ok ${Buffer.from(String(value)).toString('base64')}\n`).join('');
}
function snapshotWire(snapshot: any) {
  return { exists: snapshot.exists ? '1' : '0', status: snapshot.status, stat: snapshot.stat, cmdline: snapshot.cmdline, wchan: snapshot.wchan };
}
function fakeDeps(outputs: string[]) {
  const calls: string[] = [];
  return { calls, selectSerial: async (serial?: string) => { assert.equal(serial, 'explicit-device'); return serial; },
    adb: async (serial: string, args: string[], timeout?: number) => {
      assert.equal(serial, 'explicit-device'); assert.equal(timeout, 10000);
      assert.deepEqual(args.slice(0, 3), ['shell', 'su', '-c']);
      calls.push(args[3]);
      assert.ok(args[3].startsWith("'") && args[3].endsWith("'"), 'script must be one quoted remote shell argument');
      assert.doesNotMatch(args[3], /\b(?:kill|ptrace|am|monkey|setenforce|chmod|touch|rm)\b/);
      const script = args[3].slice(1, -1).replaceAll("'\\''", "'");
      const syntax = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8', windowsHide: true });
      assert.equal(syntax.status, 0, syntax.stderr);
      assert.ok(outputs.length, 'unexpected additional ADB read');
      return outputs.shift();
    } };
}

test('offline session diagnosis reads bounded facts without agent RPC and returns thread paging', async () => {
  const deps = fakeDeps(['0\n', wire({ ...snapshotWire(live), cgroup: archive.cgroup, mountinfo: archive.mountinfo }),
    wire({ ...snapshotWire(live), cgroup: archive.cgroup, tstatus_102: thread.status, tstat_102: thread.stat, twchan_102: thread.wchan,
      threads_count: 3, threads_more: 1, freeze_0: 'frozen 1\n', freeze_1: '1\n' })]);
  const result = await diagnoseRuntime(target, { serial: 'explicit-device', afterTid: 101, limit: 1 }, deps);
  assert.equal(result.state, 'frozen');
  assert.equal(result.identityVerified, true);
  assert.deepEqual(result.page, { afterTid: 101, nextTid: 102, hasMore: true, returned: 1, observedEntries: 3 });
  assert.equal(deps.calls.length, 3);
  assert.match(deps.calls[2], /-gt 101/);
  assert.match(deps.calls[2], /-ge 1/);
  assert.match(result.scope, /No agent RPC/);
});

test('identity mismatch or missing root prevents collecting thread data; mid-observation reuse discards it', async () => {
  const wrong = fakeDeps(['0\n', wire({ ...snapshotWire(live), cmdline: 'com.example.other\0' })]);
  assert.equal((await diagnoseRuntime(target, { serial: 'explicit-device' }, wrong)).state, 'identity-mismatch');
  assert.equal(wrong.calls.length, 2);
  const staleGeneration = fakeDeps(['0\n', wire(snapshotWire(live))]);
  assert.equal((await diagnoseRuntime({ ...target, starttimeTicks: '123455' }, { serial: 'explicit-device' }, staleGeneration)).state, 'identity-mismatch');
  assert.equal(staleGeneration.calls.length, 2);
  const noRoot = fakeDeps(['2000\n']);
  await assert.rejects(diagnoseRuntime(target, { serial: 'explicit-device' }, noRoot), /requires root/);
  assert.equal(noRoot.calls.length, 1);
  const reused = fakeDeps(['0\n', wire(snapshotWire(live)), wire({ ...snapshotWire(live), stat: live.stat.replace('123456 ', '123457 '),
    tstatus_102: thread.status, tstat_102: thread.stat, twchan_102: thread.wchan, threads_count: 1, threads_more: 0 })]);
  const result = await diagnoseRuntime(target, { serial: 'explicit-device' }, reused);
  assert.equal(result.state, 'identity-mismatch');
  assert.equal(result.threads.length, 0);
});

test('cgroup migration invalidates stale freezer evidence and malformed detail is reported as unknown', async () => {
  const moved = fakeDeps(['0\n', wire({ ...snapshotWire(live), cgroup: archive.cgroup, mountinfo: archive.mountinfo }),
    wire({ ...snapshotWire(live), cgroup: '0::/other\n', freeze_0: 'frozen 1\n', freeze_1: '1\n', threads_count: 0, threads_more: 0 })]);
  const result = await diagnoseRuntime(target, { serial: 'explicit-device' }, moved);
  assert.equal(result.state, 'running');
  assert.equal(result.facts.frozen, null);
  assert.match(result.errors.join(' '), /cgroup changed/);
  const bad = fakeDeps(['0\n', wire(snapshotWire(live)), 'ADH_DIAG_V1 status ok !!!\n']);
  const unknown = await diagnoseRuntime(target, { serial: 'explicit-device' }, bad);
  assert.equal(unknown.state, 'unknown');
  assert.match(unknown.errors.join(' '), /Malformed/);
});

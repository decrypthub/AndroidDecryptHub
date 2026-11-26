// App control has two channels; these tests pin the policy between them.
//   device channel first (CAS on process identity + device state revision),
//   adb only when the channel cannot answer, never after a write that may have executed.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  coldStartPackage, mayLaunchPackage, pickPackagePid, processIdentities,
  runningPid, startPackage, stopPackage, type ControlChannel, type ProcessIdentity,
} from '../src/app_launch.ts';
import { DeviceError } from '../src/device_protocol.ts';

const PKG = 'com.adh.sandbox.filelab';
const ROWS: ProcessIdentity[] = [
  { pid: 4210, uid: 10210, starttimeTicks: '9001' },
  { pid: 4100, uid: 10210, starttimeTicks: '8001' },
];

function fakeChannel(patch: Partial<ControlChannel> = {}) {
  const calls: { action: string; expected: ProcessIdentity[]; revision: number }[] = [];
  let processRows: any[] = ROWS.map(r => ({ ...r, process: PKG, package: PKG }));
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: processRows, complete: true, total: processRows.length }; },
    async control(_pkg, action, expected, revision) {
      calls.push({ action, expected, revision });
      return { state: 'succeeded', result: { ok: true, verdict: 'ok', mayHaveExecuted: true } };
    },
    ...patch,
  };
  return { channel, calls, setRows: (rows: any[]) => { processRows = rows; } };
}

function failAdb() {
  const calls: string[][] = [];
  return {
    calls,
    run: async (args: string[]) => { calls.push(args); return { ok: false, stdout: '', stderr: 'adb should not have run' }; },
  };
}

test('stop goes through process.control with the observed identities and state revision', async () => {
  const { channel, calls } = fakeChannel();
  const adb = failAdb();
  const result = await stopPackage(PKG, { channel, adbRun: adb.run });
  assert.equal(result.ok, true);
  assert.equal(result.via, 'device');
  assert.equal(result.mode, 'device:stop');
  assert.equal(result.fallback, undefined);
  assert.equal(adb.calls.length, 0);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].action, 'stop');
  assert.equal(calls[0].revision, 17);
  assert.deepEqual(calls[0].expected, [
    { pid: 4100, uid: 10210, starttimeTicks: '8001' },
    { pid: 4210, uid: 10210, starttimeTicks: '9001' },
  ]);
});

test('open and restart map to the device actions without a stop/start pair', async () => {
  const { channel, calls } = fakeChannel();
  const adb = failAdb();
  assert.equal((await startPackage(PKG, { channel, adbRun: adb.run })).mode, 'device:open');
  const restart = await coldStartPackage(PKG, { channel, adbRun: adb.run });
  assert.equal(restart.mode, 'device:restart');
  assert.deepEqual(calls.map(c => c.action), ['open', 'restart']);
  assert.equal(adb.calls.length, 0);
});

test('an absent channel falls back to adb and says so only when it was tried', async () => {
  const allowed = await stopPackage(PKG, {
    channel: null,
    adbRun: async () => ({ ok: true, stdout: '', stderr: '' }),
  });
  assert.equal(allowed.ok, true);
  assert.equal(allowed.via, 'adb');
  assert.equal(allowed.fallback, undefined, 'forcing the adb path is not a fallback');
  assert.equal(allowed.mode, 'force-stop');

  const unavailable = await startPackage(PKG, {
    channel: fakeChannel({ processes: async () => null }).channel,
    adbRun: async (args) => ({ ok: !args.includes('monkey'), stdout: 'com.adh.sandbox.filelab/.Main', stderr: '' }),
  });
  assert.equal(unavailable.via, 'adb');
  assert.equal(unavailable.fallback, 'channel unavailable');
  assert.match(String(unavailable.mode), /am start -n/);
});

test('a changed process set is re-observed once, then reported, never replayed', async () => {
  let fresh = false;
  const seen: ProcessIdentity[][] = [];
  const channel: ControlChannel = {
    async state() { return { stateRevision: fresh ? 18 : 17 }; },
    async processes() {
      return {
        rows: (fresh ? [{ pid: 5000, uid: 10210, starttimeTicks: '12000' }] : ROWS).map(r => ({ ...r, process: PKG })),
        complete: true, total: 1,
      };
    },
    async control(_pkg, _action, expected) {
      seen.push(expected);
      if (!fresh) { fresh = true; throw new DeviceError('TARGET_CHANGED', 'process generations changed'); }
      return { state: 'succeeded', result: { ok: true, verdict: 'ok' } };
    },
  };
  const result = await stopPackage(PKG, { channel, adbRun: failAdb().run });
  assert.equal(result.ok, true);
  assert.equal(result.via, 'device');
  assert.equal(seen.length, 2, 'the second dispatch must carry the refreshed identities');
  assert.deepEqual(seen[1], [{ pid: 5000, uid: 10210, starttimeTicks: '12000' }]);
});

test('an unverifiable process set retries once, then runs adb with the reason recorded', async () => {
  let controlCalls = 0;
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: ROWS, complete: true, total: ROWS.length }; },
    async control() { controlCalls++; throw new DeviceError('IDENTITY_UNVERIFIED', 'cannot verify all current package processes'); },
  };
  const result = await startPackage(PKG, {
    channel,
    adbRun: async () => ({ ok: true, stdout: 'com.adh.sandbox.filelab/.Main', stderr: '' }),
  });
  assert.equal(controlCalls, 2, 'the precondition is re-read once, the write is not replayed blindly');
  assert.equal(result.ok, true);
  assert.equal(result.via, 'adb');
  assert.match(String(result.fallback), /IDENTITY_UNVERIFIED/);
});

test('a process set that keeps changing is reported, not pushed to adb', async () => {
  const adb = failAdb();
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: ROWS, complete: true, total: ROWS.length }; },
    async control() { throw new DeviceError('TARGET_CHANGED', 'process generations changed'); },
  };
  const result = await stopPackage(PKG, { channel, adbRun: adb.run });
  assert.equal(result.ok, false);
  assert.equal(result.via, 'device');
  assert.match(String(result.error), /TARGET_CHANGED/);
  assert.equal(adb.calls.length, 0);
});

test('a write with no reply is reported as uncertain and never falls back to adb', async () => {
  const adb = failAdb();
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: ROWS, complete: true, total: ROWS.length }; },
    async control() { throw new DeviceError('DEVICE_RPC_TIMEOUT', 'reply deadline expired', true); },
  };
  const result = await stopPackage(PKG, { channel, adbRun: adb.run });
  assert.equal(result.ok, false);
  assert.equal(result.via, 'device');
  assert.match(String(result.error), /不重试也不回退 adb/);
  assert.equal(adb.calls.length, 0);
});

test('a device verdict is final: denied does not become an adb attempt', async () => {
  const adb = failAdb();
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: ROWS, complete: true, total: ROWS.length }; },
    async control() { return { state: 'succeeded', result: { ok: false, verdict: 'denied' } }; },
  };
  const result = await coldStartPackage(PKG, { channel, adbRun: adb.run });
  assert.equal(result.ok, false);
  assert.equal(result.via, 'device');
  assert.match(String(result.error), /denied/);
  assert.equal(adb.calls.length, 0);
});

test('an unsupported method on an older module build falls back to adb', async () => {
  const channel: ControlChannel = {
    async state() { return { stateRevision: 17 }; },
    async processes() { return { rows: ROWS, complete: true, total: ROWS.length }; },
    async control() { throw new DeviceError('UNSUPPORTED_METHOD', 'device capability is not implemented'); },
  };
  const result = await stopPackage(PKG, { channel, adbRun: async () => ({ ok: true, stdout: '', stderr: '' }) });
  assert.equal(result.ok, true);
  assert.equal(result.via, 'adb');
  assert.match(String(result.fallback), /UNSUPPORTED_METHOD/);
});

test('system and agent packages are refused before any channel is touched', async () => {
  for (const pkg of ['com.adh.daemon', 'com.adh.manager', 'android', 'com.android.systemui', 'nodots']) {
    assert.equal(mayLaunchPackage(pkg), false);
  }
  let touched = false;
  const channel: ControlChannel = {
    async state() { touched = true; return { stateRevision: 1 }; },
    async processes() { touched = true; return null; },
    async control() { touched = true; return null; },
  };
  const result = await stopPackage('android', { channel, adbRun: failAdb().run });
  assert.equal(result.ok, false);
  assert.equal(result.mode, 'denied');
  assert.equal(touched, false);
});

test('identities drop malformed rows instead of sending a set the device will reject', () => {
  assert.deepEqual(processIdentities([
    { pid: 7, uid: 1000, starttimeTicks: '42' },
    { pid: 0, uid: 1000, starttimeTicks: '42' },
    { pid: 8, uid: -1, starttimeTicks: '42' },
    { pid: 9, uid: 1000, starttimeTicks: 'abc' },
    { pid: 6, uid: 1000, starttimeTicks: '41' },
  ]), [
    { pid: 6, uid: 1000, starttimeTicks: '41' },
    { pid: 7, uid: 1000, starttimeTicks: '42' },
  ]);
});

test('running pid prefers the main process over a lower secondary pid', async () => {
  assert.equal(pickPackagePid([
    { pid: 4100, uid: 10210, starttimeTicks: '1', process: `${PKG}:core` },
    { pid: 4210, uid: 10210, starttimeTicks: '2', process: PKG },
  ], PKG), 4210);

  const channel: ControlChannel = {
    async state() { return { stateRevision: 1 }; },
    async processes() { return { rows: [{ ...ROWS[0], process: PKG } as any], complete: true, total: 1 }; },
    async control() { return null; },
  };
  assert.equal(await runningPid(PKG, { channel, adbRun: failAdb().run }), 4210);
});

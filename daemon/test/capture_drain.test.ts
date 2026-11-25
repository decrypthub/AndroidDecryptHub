import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

const realExec = cp.execFile;
const realSpawn = cp.spawn;
cp.execFile = (() => { throw Error('ADB/device calls forbidden in capture drain fixture'); }) as unknown as typeof cp.execFile;
cp.spawn = (() => { throw Error('child execution forbidden in capture drain fixture'); }) as unknown as typeof cp.spawn;
syncBuiltinESMExports();

const { drainSession, forgetCaptureSession, startCaptureLoop } = await import('../src/service.ts');
const { agentSockets, capStats, captureTimers, captures, pending, sessions } = await import('../src/state.ts');

after(() => {
  cp.execFile = realExec; cp.spawn = realSpawn; syncBuiltinESMExports();
  for (const timer of captureTimers.values()) clearInterval(timer);
  captureTimers.clear(); agentSockets.clear(); sessions.clear(); capStats.clear(); captures.length = 0;
});

test('ring-full warning is emitted once for a cumulative drop counter, not on every drain', async () => {
  const sid = 'capture-drop-fixture';
  captureTimers.clear(); capStats.delete(sid); captures.length = 0;
  sessions.set(sid, { sessionId: sid, online: true, package: 'com.example.fixture', process: 'com.example.fixture', pid: 1, uid: 10001, starttimeTicks: '1' } as any);
  agentSockets.set(sid, { destroyed: false, write(frame: Buffer) {
    const msg = JSON.parse(frame.subarray(5).toString('utf8'));
    queueMicrotask(() => pending.get(msg.id)?.resolve({
      ok: true, jcaptures: [], captures: [], count: 0, complete: false,
      seq: 20, dropped: 7, jdropped: 0, backlog: 0, drained: 13,
    }));
    return true;
  } } as any);
  startCaptureLoop(sid, { skipArm: true });

  const lines: string[] = [];
  const realLog = console.log;
  console.log = (...args: unknown[]) => { lines.push(args.map(String).join(' ')); };
  try {
    assert.equal((await drainSession(sid)).ok, true);
    assert.equal((await drainSession(sid)).ok, true);
  } finally {
    console.log = realLog;
  }
  assert.equal(lines.filter((line) => line.includes('DROPPING')).length, 1);

  const timer = captureTimers.get(sid);
  if (timer) clearInterval(timer);
  captureTimers.delete(sid); forgetCaptureSession(sid); sessions.delete(sid); agentSockets.delete(sid); capStats.delete(sid);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { callerOfStack, digestJavaTrace, javaTraceDigest, javaTraceStop } from '../src/java_trace.ts';

const sample = (hookId, target, ts, tid, arg, ret, extra = {}) => ({ hookId, target, ts, tid, arg, ret, error: '', ...extra });

// --- the three-phase assembly (the pure digest alone let the drain bug slip through) ---------
function fakeDeps({ captures = [], drain = { ok: true }, send = [] } = {}) {
  return {
    deps: {
      sendCmd: async (session, op, args) => { send.push({ session, op, args }); return { ok: true, hookId: 1, hookIds: [1], matched: 1 }; },
      captures,
      drainSession: async (session) => { send.push({ session, op: 'drainSession' }); return drain; },
    },
    send,
  };
}
const capRow = (id, hookId, tsNs, arg = '') => ({
  id, sessionId: 's1', func: 'JAVA_HOOK', tid: 7, ts: 1000, tsNs,
  hex: Buffer.from(JSON.stringify({ hookId, target: 'com.pkg.C#m()', arg, ret: 'r', error: '' }), 'utf8').toString('hex'),
});

test('digest goes through the shared drainSession and never sends a raw capture_drain', async () => {
  const { deps, send } = fakeDeps({ captures: [capRow(5, 1, 10)] });
  const r = await javaTraceDigest('s1', { hookIds: [1] }, deps);
  assert.ok(send.some((s) => s.op === 'drainSession'), 'drainSession must be used');
  assert.ok(!send.some((s) => s.op === 'capture_drain'), 'a raw capture_drain would pop records without ingesting them');
  assert.equal(r.digest.samples, 1);
  assert.equal(r.drain.ok, true);
});

test('a failed drain is reported instead of looking like an empty trace', async () => {
  const { deps } = fakeDeps({ captures: [], drain: { ok: false, error: 'agent wedged' } });
  const r = await javaTraceDigest('s1', { hookIds: [1] }, deps);
  assert.equal(r.drain.ok, false);
  assert.ok(r.digest.notes.some((n) => n.includes('capture drain failed (agent wedged)')));
});

test('the cursor filters out events from before start', async () => {
  const { deps } = fakeDeps({ captures: [capRow(3, 1, 10), capRow(9, 1, 20), capRow(11, 1, 30)] });
  const r = await javaTraceDigest('s1', { hookIds: [1], sinceCaptureId: 9 }, deps);
  assert.equal(r.digest.samples, 1);
  assert.equal(r.digest.timeline[0].ts, 1000);
});

test('events are ordered by the agent timestamp, not by the shared drain timestamp', async () => {
  // Same drain ts (1000) for both rows: only tsNs can say which ran first.
  const { deps } = fakeDeps({ captures: [capRow(1, 7, 500, 'second'), capRow(2, 3, 100, 'first')] });
  const r = await javaTraceDigest('s1', { hookIds: [3, 7] }, deps);
  assert.deepEqual(r.digest.timeline.map((t) => t.arg), ['first', 'second']);
});

test('stop refuses hookId 0, which would unhook every Java hook', async () => {
  const { deps, send } = fakeDeps({});
  await assert.rejects(() => javaTraceStop('s1', { hookIds: [0] }, deps), /id 0 means every hook/);
  await assert.rejects(() => javaTraceStop('s1', { hookIds: [-3] }, deps), /refusing to unhook/);
  assert.equal(send.length, 0, 'nothing may be sent to the agent');
});

test('stop dedupes ids and reports per-id failures without aborting the rest', async () => {
  const sent = [];
  const deps = {
    captures: [],
    drainSession: async () => ({ ok: true }),
    sendCmd: async (session, op, args) => { sent.push(args.hookId); return args.hookId === 2 ? { ok: false, error: 'gone' } : { ok: true }; },
  };
  const r = await javaTraceStop('s1', { hookIds: [1, 1, 2] }, deps);
  assert.deepEqual(sent, [1, 2]);
  assert.deepEqual(r.unhooked, [1]);
  assert.equal(r.failures.length, 1);
  assert.equal(r.ok, false);
});

test('callerOfStack ignores the bridge failure marker and normalises hidden classes', () => {
  assert.equal(callerOfStack('<stack capture failed: boom>'), null);
  assert.equal(callerOfStack('com.pkg.C$$Lambda$1/0x1234#run:7 <- com.pkg.C#m:1'), 'com.pkg.C$$Lambda$1#run');
});

test('a trace without stack data says so instead of showing an empty caller list', () => {
  const d = digestJavaTrace([sample(1, 'com.pkg.C#m()', 1, 1, '', '')]);
  assert.equal(d.callers.length, 0);
  assert.equal(d.complete, false);
  assert.ok(d.notes.some((n) => n.includes('start the trace with stack:true')));
});
test('callerOfStack takes the innermost frame and drops the line number', () => {
  assert.equal(callerOfStack('com.adh.sandbox.HookProbe#stackMiddle:33 <- com.adh.sandbox.HookProbe#stackOuter:36'),
    'com.adh.sandbox.HookProbe#stackMiddle');
  assert.equal(callerOfStack(''), null);
  assert.equal(callerOfStack(undefined), null);
});

test('groups by method with counts, window, threads and last values', () => {
  const d = digestJavaTrace([
    sample(1, 'com.pkg.Crypto#encrypt([B)', 100, 11, 'A', 'x'),
    sample(2, 'com.pkg.Crypto#encrypt([B)', 200, 11, 'B', 'y'),
    sample(1, 'com.pkg.Crypto#encrypt([B)', 300, 12, 'C', 'z'),
    sample(3, 'com.pkg.Crypto#digest()', 400, 12, '', 'h'),
  ]);
  assert.equal(d.samples, 4);
  const enc = d.methods.find((m) => m.target.includes('encrypt'));
  assert.equal(enc.count, 3);
  assert.equal(enc.firstTs, 100);
  assert.equal(enc.lastTs, 300);
  assert.deepEqual(enc.tids, [11, 12]);
  assert.equal(enc.lastArg, 'C');
  assert.equal(enc.lastReturn, 'z');
  assert.equal(d.methods[0].count, 3);        // busiest first
  assert.equal(d.observedFrom, 100);
  assert.equal(d.observedTo, 400);
});

test('the timeline is chronological and keeps the newest window', () => {
  const samples = [];
  for (let i = 0; i < 10; i++) samples.push(sample(1, 'com.pkg.C#m()', i * 10, 1, String(i), String(i)));
  const d = digestJavaTrace(samples, { maxTimeline: 3 });
  assert.deepEqual(d.timeline.map((t) => t.ts), [70, 80, 90]);
  assert.ok(d.notes.some((n) => n.includes('newest 3 of 10')));
});

test('counts callers from stack-carrying events and says when chains are missing', () => {
  const d = digestJavaTrace([
    sample(1, 'com.pkg.C#m()', 1, 1, '', '', { stack: 'com.pkg.Caller#a:10' }),
    sample(1, 'com.pkg.C#m()', 2, 1, '', '', { stack: 'com.pkg.Caller#a:11' }),
    sample(1, 'com.pkg.C#m()', 3, 1, '', '', { stack: 'com.pkg.Other#b:1' }),
    sample(1, 'com.pkg.C#m()', 4, 1, '', '', {}),
  ]);
  assert.deepEqual(d.callers, [{ caller: 'com.pkg.Caller#a', count: 2 }, { caller: 'com.pkg.Other#b', count: 1 }]);
  assert.ok(d.notes.some((n) => n.includes('only available for 3 of 4')));
});

test('errors are surfaced per method, not swallowed', () => {
  const d = digestJavaTrace([
    sample(1, 'com.pkg.C#m()', 1, 1, '', '', { error: 'boom' }),
    sample(1, 'com.pkg.C#m()', 2, 1, '', 'ok'),
  ]);
  const m = d.methods[0];
  assert.equal(m.errorCount, 1);
  assert.equal(m.lastError, 'boom');
  assert.equal(m.lastReturn, 'ok');
  assert.ok(d.notes.some((n) => n.includes('at least one call threw')));
});

test('an empty trace tells the operator what to do next', () => {
  const d = digestJavaTrace([]);
  assert.equal(d.samples, 0);
  assert.equal(d.methods.length, 0);
  assert.ok(d.notes.some((n) => n.includes('trigger the target')));
});

test('out-of-order input is sorted before grouping', () => {
  const d = digestJavaTrace([
    sample(1, 'com.pkg.C#m()', 300, 1, 'c', ''),
    sample(1, 'com.pkg.C#m()', 100, 1, 'a', ''),
    sample(1, 'com.pkg.C#m()', 200, 1, 'b', ''),
  ]);
  assert.equal(d.observedFrom, 100);
  assert.deepEqual(d.timeline.map((t) => t.arg), ['a', 'b', 'c']);
});
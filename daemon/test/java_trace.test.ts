import test from 'node:test';
import assert from 'node:assert/strict';
import { callerOfStack, digestJavaTrace } from '../src/java_trace.ts';

const sample = (hookId, target, ts, tid, arg, ret, extra = {}) => ({ hookId, target, ts, tid, arg, ret, error: '', ...extra });

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
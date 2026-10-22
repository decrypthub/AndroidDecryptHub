import test from 'node:test';
import assert from 'node:assert/strict';
import { failPendingFor, pending } from '../src/state.ts';

// A command whose target dies mid-flight must fail with a REASON, not sit out the timeout. Measured on a
// real target: a trace of code that dereferences freed memory killed the process, and the caller waited
// 60 s for "command timeout" - which reads exactly like a slow target.
test('a disconnect fails only the commands that session owned, and clears their timers', async () => {
  pending.clear();
  const settled: string[] = [];
  const make = (id: string, sessionId: string) => {
    const timer = setTimeout(() => {}, 10_000);   // would keep the process alive if not cleared
    pending.set(id, {
      resolve: () => settled.push(`resolved:${id}`),
      reject: (e: Error) => settled.push(`rejected:${id}:${e.message}`),
      timer,
      sessionId,
    });
    return timer;
  };
  const t1 = make('c1', 's_a');
  const t2 = make('c2', 's_a');
  const t3 = make('c3', 's_b');
  const failed = failPendingFor('s_a', 'the target disconnected while this command was running (it may have crashed)');
  assert.equal(failed, 2);
  assert.deepEqual(settled.sort(), [
    'rejected:c1:the target disconnected while this command was running (it may have crashed)',
    'rejected:c2:the target disconnected while this command was running (it may have crashed)',
  ]);
  // Only the dead session's entries are gone; the other session's command is untouched.
  assert.equal(pending.has('c1'), false);
  assert.equal(pending.has('c2'), false);
  assert.equal(pending.has('c3'), true);
  clearTimeout(pending.get('c3')!.timer);
  clearTimeout(t1);
  clearTimeout(t2);
  clearTimeout(t3);
  pending.clear();
});

test('a session with nothing in flight reports zero', () => {
  pending.clear();
  assert.equal(failPendingFor('s_none', 'x'), 0);
});

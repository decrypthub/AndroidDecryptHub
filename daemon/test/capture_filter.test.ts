import test from 'node:test';
import assert from 'node:assert/strict';
import { filterLiveCaptures } from '../src/state.ts';

// live_captures used to filter by category only, so the sandbox self-check records and a real
// target's records arrived as one undifferentiated stream and the only way to tell them apart was
// reading every record. http_exchanges already filtered by session/package; this is the same
// filter, on the store every other capture consumer reads.

type Rec = { category: string; package?: string; sessionId: string };
const store: Rec[] = [
  { category: 'crypto', package: 'com.adh.sandbox', sessionId: 's1' },
  { category: 'crypto', package: 'com.jingdong.app.mall', sessionId: 's2' },
  { category: 'system', package: 'com.jingdong.app.mall', sessionId: 's2' },
  { category: 'crypto', package: '', sessionId: 'gone' },   // no stamp, session pruned: unattributable
];

test('category alone behaves as before', () => {
  assert.equal(filterLiveCaptures(store, { category: 'crypto' }).length, 3);
});

test('package separates the target from the sandbox self-check', () => {
  const jd = filterLiveCaptures(store, { category: 'crypto', package: 'com.jingdong.app.mall' });
  assert.equal(jd.length, 1);
  assert.equal(jd[0].sessionId, 's2');
});

test('session narrows to one process', () => {
  assert.equal(filterLiveCaptures(store, { session: 's1' }).length, 1);
  assert.equal(filterLiveCaptures(store, { session: 's1', category: 'system' }).length, 0);
});

test('a record with no package stamp and no live session is not attributed by guessing', () => {
  assert.equal(filterLiveCaptures(store, { package: 'com.jingdong.app.mall' }).length, 2);
  assert.equal(filterLiveCaptures(store, { package: 'gone' }).length, 0);
});

test('no filter returns the store untouched, and filtering never mutates it', () => {
  const before = store.length;
  assert.equal(filterLiveCaptures(store, {}).length, before);
  filterLiveCaptures(store, { package: 'com.adh.sandbox' });
  assert.equal(store.length, before);
});

// The reason hookId exists: `seq` is numbered PER HOOK, so two hooks both have a seq=1 record. A
// consumer that pairs a register event with its memory copy by seq alone silently joins two
// different hooks - that produced two wrong conclusions during the jdgs analysis before anyone
// noticed. The filter is what makes the correct pairing expressible.
type HookRec = { category: string; sessionId: string; hookId?: number; seq?: number; phase?: string };
const hookStore: HookRec[] = [
  { category: 'system', sessionId: 's1', hookId: 1, seq: 1 },                  // hook 1, register event
  { category: 'system', sessionId: 's1', hookId: 1, seq: 1 },                  // hook 1, its memory copy
  { category: 'system', sessionId: 's1', hookId: 2, seq: 1 },                  // hook 2, SAME seq
  { category: 'system', sessionId: 's1', hookId: 2, seq: 2, phase: 'after' },  // hook 2, post-call
  { category: 'system', sessionId: 's1' },                                     // not a hook record at all
];

test('hookId separates two hooks that both use seq 1', () => {
  assert.equal(filterLiveCaptures(hookStore, { hookId: 1 }).length, 2);
  assert.equal(filterLiveCaptures(hookStore, { hookId: 2 }).length, 2);
  const after = filterLiveCaptures(hookStore, { hookId: 2 }).filter((r) => r.phase === 'after');
  assert.equal(after.length, 1);
  assert.equal(after[0].seq, 2);
});

test('hookId 0 selects nothing instead of falling back to "all"', () => {
  // Ids start at 1, so 0 is a caller mistake; returning the whole store would hide it.
  assert.equal(filterLiveCaptures(hookStore, { hookId: 0 }).length, 0);
  assert.equal(filterLiveCaptures(hookStore, { hookId: undefined }).length, hookStore.length);
});

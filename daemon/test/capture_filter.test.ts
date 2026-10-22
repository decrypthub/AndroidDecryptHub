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

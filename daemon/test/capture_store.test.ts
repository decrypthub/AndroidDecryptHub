import test from 'node:test';
import assert from 'node:assert/strict';
import { captures, pushCapture, captureStoreStats, storeLossNote, settings } from '../src/state.ts';

test('the capture store counts what it evicted instead of forgetting it', () => {
  const savedRetain = settings.capture.retain;
  const savedLength = captures.length;
  try {
    settings.capture.retain = 50;
    const before = captureStoreStats();
    for (let i = 0; i < 70; i++) {
      pushCapture({ id: before.pushed + i + 1, sessionId: 'store-test', ts: 1000 + i, source: 'agent', category: 'net', algo: 'x', op: 'o', func: 'f', hex: '' } as any);
    }
    const after = captureStoreStats();
    assert.equal(after.retain, 50);
    assert.equal(after.retained, 50, 'the list is capped at retain');
    assert.ok(after.pushed - before.pushed === 70, 'every push is counted');
    assert.ok(after.evicted - before.evicted >= 20, 'evictions are counted, not silently dropped');
    assert.ok(after.oldestTs >= 1000, 'the oldest retained record carries its timestamp');
  } finally {
    settings.capture.retain = savedRetain;
    captures.length = savedLength;    // leave the shared store the way the test found it
  }
});

test('the store-loss note only fires when the window is actually affected', () => {
  const savedRetain = settings.capture.retain;
  const savedLength = captures.length;
  try {
    settings.capture.retain = 50;
    const session = 'store-note-test';
    for (let i = 0; i < 60; i++) {
      pushCapture({ id: 10000 + i, sessionId: session, ts: 5000 + i, source: 'agent', category: 'net', algo: 'x', op: 'o', func: 'f', hex: '' } as any);
    }
    const stats = captureStoreStats(session);
    assert.ok(stats.evicted >= 10, 'this session had records evicted');
    assert.ok(stats.oldestTs > 0 && stats.oldestId > 0);
    // A time window that starts at (or after) the oldest retained record is intact.
    assert.equal(storeLossNote(session, { sinceMs: stats.oldestTs }), null);
    // A window that reaches back before it may be missing events, and says so.
    assert.match(String(storeLossNote(session, { sinceMs: stats.oldestTs - 1000 })), /evicted/);
    // Same for an id cursor older than the oldest retained record.
    assert.equal(storeLossNote(session, { sinceCaptureId: stats.oldestId }), null);
    assert.match(String(storeLossNote(session, { sinceCaptureId: stats.oldestId - 1 })), /evicted/);
    assert.match(String(storeLossNote(session)), /evicted/);          // no window at all = everything
    assert.equal(storeLossNote('never-seen-session', { sinceMs: null }), null);
  } finally {
    settings.capture.retain = savedRetain;
    captures.length = savedLength;
  }
});

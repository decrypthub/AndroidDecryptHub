import test from 'node:test';
import assert from 'node:assert/strict';
import { captures, pushCapture, captureStoreStats, settings } from '../src/state.ts';

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

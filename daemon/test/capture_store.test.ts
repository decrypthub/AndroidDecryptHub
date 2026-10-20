import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { captures, pushCapture, captureStoreStats, storeLossNote, settings, knownApps, sessions, eventPackage, DATA_DIR } from '../src/state.ts';

test('the capture store counts what it evicted instead of forgetting it', () => {
  const savedRetain = settings.capture.retain;
  const saved = captures.slice();
  try {
    captures.length = 0;
    settings.capture.retain = 50;
    const before = captureStoreStats();
    for (let i = 0; i < 70; i++) {
      pushCapture({
        id: before.pushed + i + 1, sessionId: 'store-test', package: 'com.test.retain',
        ts: 1000 + i, source: 'native', category: 'net', algo: 'x', op: 'o', func: 'f', hex: '',
      } as any);
    }
    const after = captureStoreStats();
    const mine = captures.filter(c => c.package === 'com.test.retain');
    assert.equal(after.retain, 50);
    assert.equal(mine.length, 50, 'each package is capped at retain');
    assert.ok(after.pushed - before.pushed === 70, 'every push is counted');
    assert.ok(after.evicted - before.evicted >= 20, 'evictions are counted, not silently dropped');
    assert.ok(mine[0].ts >= 1000, 'the oldest retained record carries its timestamp');
  } finally {
    settings.capture.retain = savedRetain;
    captures.length = 0;
    for (const c of saved) captures.push(c);
    const pkgDir = join(DATA_DIR, 'packages', 'com.test.retain');
    if (existsSync(pkgDir)) rmSync(pkgDir, { recursive: true, force: true });
  }
});

test('the store-loss note only fires when the window is actually affected', () => {
  const savedRetain = settings.capture.retain;
  const saved = captures.slice();
  try {
    captures.length = 0;
    settings.capture.retain = 50;
    const session = 'store-note-test';
    for (let i = 0; i < 60; i++) {
      pushCapture({
        id: 10000 + i, sessionId: session, package: 'com.test.note',
        ts: 5000 + i, source: 'native', category: 'net', algo: 'x', op: 'o', func: 'f', hex: '',
      } as any);
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
    captures.length = 0;
    for (const c of saved) captures.push(c);
    const pkgDir = join(DATA_DIR, 'packages', 'com.test.note');
    if (existsSync(pkgDir)) rmSync(pkgDir, { recursive: true, force: true });
  }
});

test('an app stays listed from its captures after the session is gone', () => {
  const savedLength = captures.length;
  const sid = 'app-view-session';
  try {
    sessions.set(sid, { sessionId: sid, package: 'com.example.kept', pid: 9, online: false, connectedAt: 1, lastSeen: 2 } as any);
    pushCapture({ id: 880001, sessionId: sid, package: 'com.example.kept', ts: 880001, source: 'native', category: 'system', algo: 'Java Hook', op: '方法调用', func: 'JAVA_HOOK', hex: '' } as any);
    sessions.delete(sid);
    const hit = knownApps().find(a => a.package === 'com.example.kept');
    assert.ok(hit, 'package remains selectable from retained captures');
    assert.equal(hit?.online, false);
    assert.equal(eventPackage({ sessionId: 'missing', package: 'com.example.kept' }), 'com.example.kept');
    assert.equal(eventPackage({ sessionId: sid }), '');
  } finally {
    captures.length = savedLength;
    sessions.delete(sid);
    const pkgDir = join(DATA_DIR, 'packages', 'com.example.kept');
    if (existsSync(pkgDir)) rmSync(pkgDir, { recursive: true, force: true });
  }
});

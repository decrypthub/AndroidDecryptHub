import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  appendCaptureLine, clearAllPersistedCaptures, clearPackagePersistedCaptures,
  evictPackageFromMemory, listPackageCaptureStats, loadCapturesFromDisk,
  pruneCapturesOlderThan, readPackageCapturesJsonl, safePackageDirName,
  trimPackageCapturesFile,
} from '../src/capture_persist.ts';

function sample(id: number, pkg: string) {
  return {
    id, sessionId: 's', source: 'native', func: 'SSL_write', algo: 'TLS', op: '写',
    category: 'net', inl: 1, tid: 1, tsNs: id, ts: id, hex: '41', preview: 'A', package: pkg,
  };
}

test('rejects unsafe package directory names', () => {
  assert.equal(safePackageDirName('com.example.app'), 'com.example.app');
  assert.equal(safePackageDirName('../etc'), null);
  assert.equal(safePackageDirName('a/b'), null);
  assert.equal(safePackageDirName(''), null);
  assert.equal(safePackageDirName('?'), null);
});

test('append + load + trim keeps newest per package across restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adh-cap-'));
  try {
    for (let i = 1; i <= 5; i++) appendCaptureLine(dir, sample(i, 'com.a'));
    for (let i = 10; i <= 12; i++) appendCaptureLine(dir, sample(i, 'com.b'));
    trimPackageCapturesFile(dir, 'com.a', 3);
    const loaded = loadCapturesFromDisk(dir, 100);
    const a = loaded.filter(c => c.package === 'com.a').map(c => c.id);
    const b = loaded.filter(c => c.package === 'com.b').map(c => c.id);
    assert.deepEqual(a, [3, 4, 5]);
    assert.deepEqual(b, [10, 11, 12]);
    const path = join(dir, 'packages', 'com.a', 'captures.jsonl');
    assert.equal(readFileSync(path, 'utf8').trim().split('\n').length, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('clear removes the packages tree', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adh-cap-'));
  try {
    appendCaptureLine(dir, sample(1, 'com.x'));
    assert.ok(existsSync(join(dir, 'packages', 'com.x', 'captures.jsonl')));
    assert.deepEqual(clearAllPersistedCaptures(dir), []);
    assert.equal(existsSync(join(dir, 'packages')), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('stats export clear and age prune', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adh-cap-'));
  try {
    appendCaptureLine(dir, { ...sample(1, 'com.age'), ts: Date.now() - 40 * 86400000 });
    appendCaptureLine(dir, { ...sample(2, 'com.age'), ts: Date.now() });
    const dropped = pruneCapturesOlderThan(dir, 14);
    assert.equal(dropped, 1);
    const stats = listPackageCaptureStats(dir);
    assert.equal(stats.length, 1);
    assert.equal(stats[0].lines, 1);
    const text = readPackageCapturesJsonl(dir, 'com.age');
    assert.ok(text && text.includes('"id":2'));
    assert.deepEqual(clearPackagePersistedCaptures(dir, 'com.age'), []);
    assert.equal(readPackageCapturesJsonl(dir, 'com.age'), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('one package eviction does not remove another package from memory', () => {
  const list = [
    sample(1, 'com.a'), sample(2, 'com.b'), sample(3, 'com.a'), sample(4, 'com.a'),
  ];
  const evicted = evictPackageFromMemory(list, 'com.a', 2);
  assert.equal(evicted.length, 1);
  assert.equal(evicted[0].id, 1);
  assert.deepEqual(list.map(c => c.id), [2, 3, 4]);
  assert.ok(list.some(c => c.package === 'com.b'));
});

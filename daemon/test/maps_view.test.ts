import test from 'node:test';
import assert from 'node:assert/strict';

import { isAnonymousPath, mapsView, summarizeMaps } from '../src/maps_view.ts';

// Rows exactly as the agent emits them: bare hex (no 0x), "00000000" file offsets, empty path for a
// mapping with nothing behind it, and [label] paths for the kernel's own regions.
const MAPS = [
  { start: '7600000000', end: '7600010000', perms: 'r-xp', offset: '00000000', path: '/data/app/com.x/lib/arm64/libx.so' },
  { start: '7600010000', end: '7600014000', perms: 'r--p', offset: '00010000', path: '/data/app/com.x/lib/arm64/libx.so' },
  { start: '7600100000', end: '7600110000', perms: 'rw-p', offset: '00000000', path: '[anon:dalvik-main space]' },
  { start: '7600200000', end: '7600208000', perms: 'rwxp', offset: '00000000', path: '' },
  { start: '7600300000', end: '7600301000', perms: 'rw-p', offset: '00000000', path: '/dev/ashmem/xyz (deleted)' },
  { start: 'zz', end: '7600401000', perms: 'rw-p', offset: '00000000', path: 'unparseable' },
];

test('a raw agent maps reply becomes sized rows and the aggregates the panel shows', () => {
  const view = mapsView(MAPS);
  // the unparseable line is dropped, never guessed
  assert.equal(view.total, 5);
  assert.equal(view.regions.length, 5);
  assert.deepEqual(view.regions[0], {
    start: '0x7600000000', end: '0x7600010000', size: 0x10000,
    perms: 'r-xp', offset: '0x00000000', path: '/data/app/com.x/lib/arm64/libx.so',
  });
  assert.deepEqual(view.stats, {
    total: 5,
    readable: 5,
    writable: 3,
    executable: 2,
    writableExecutable: 1,
    anonymous: 2,
    anonymousExecutable: 1,
    fileBacked: 3,
    mappedBytes: 0x10000 + 0x4000 + 0x10000 + 0x8000 + 0x1000,
    executableBytes: 0x10000 + 0x8000,
    anonymousExecutableBytes: 0x8000,
  });
});

test('anonymous means no file backing: a device path is not anonymous, an empty path is', () => {
  assert.equal(isAnonymousPath(''), true);
  assert.equal(isAnonymousPath('[anon:dalvik-main space]'), true);
  assert.equal(isAnonymousPath('[stack]'), true);
  // /dev/ashmem is a device, and /data/app/... is a file: both are backed by something
  assert.equal(isAnonymousPath('/dev/ashmem/xyz (deleted)'), false);
  assert.equal(isAnonymousPath('/data/app/com.x/base.apk'), false);
  const stats = summarizeMaps(mapsView([
    { start: '1000', end: '2000', perms: 'rw-p', offset: '0', path: '[anon:stack_and_tls:123]' },
    { start: '2000', end: '3000', perms: 'r--p', offset: '0', path: '/system/lib64/libc.so' },
  ]).regions);
  assert.equal(stats.anonymous, 1);
  assert.equal(stats.fileBacked, 1);
});

test('an empty or missing maps reply is an empty view, not a crash', () => {
  for (const raw of [[], null, undefined]) {
    const view = mapsView(raw as never);
    assert.equal(view.total, 0);
    assert.equal(view.regions.length, 0);
    assert.equal(view.stats.mappedBytes, 0);
    assert.equal(view.stats.executable, 0);
  }
});

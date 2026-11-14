import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeRegion, queryMaps, resolveAddress } from '../src/maps_query.ts';

// regions shaped like the agent's maps reply
const MAPS = [
  { start: '0x7600000000', end: '0x7600010000', perms: 'r-xp', offset: '0x0', path: '/data/app/com.x/lib/arm64/libx.so' },
  { start: '0x7600010000', end: '0x7600014000', perms: 'r--p', offset: '0x10000', path: '/data/app/com.x/lib/arm64/libx.so' },
  { start: '0x7600100000', end: '0x7600120000', perms: 'rw-p', offset: '0x0', path: '[anon:dalvik-main space]' },
  { start: '0x7600200000', end: '0x7600208000', perms: 'r-xp', offset: '0x0', path: '' },
  { start: '0x7600300000', end: '0x7600301000', perms: 'rw-p', offset: '0x0', path: '/dev/ashmem/xyz (deleted)' },
];

test('a full maps list becomes size/perms/offset/path rows', () => {
  const row = normalizeRegion(MAPS[0]);
  assert.deepEqual(row, {
    start: '0x7600000000', end: '0x7600010000', size: 0x10000,
    perms: 'r-xp', offset: '0x0', path: '/data/app/com.x/lib/arm64/libx.so',
  });
  // decimal-looking strings are still parsed as hex, which is what /proc/self/maps emits
  assert.equal(normalizeRegion({ start: '1000', end: '2000', perms: 'rw-p' })?.size, 0x1000);
  assert.equal(normalizeRegion({ start: 'zz', end: '2000' }), null);
});

test('addr resolves the containing region and the module-relative file offset', () => {
  const res = resolveAddress(MAPS.map((r) => normalizeRegion(r)!), '0x7600012340');
  assert.equal(res?.region.path, '/data/app/com.x/lib/arm64/libx.so');
  assert.equal(res?.regionOffset, '0x2340');
  // file offset = region file offset + in-region offset: "which code in libx.so is this"
  assert.equal(res?.fileOffset, '0x12340');
  assert.equal(resolveAddress(MAPS.map((r) => normalizeRegion(r)!), '0x1'), null);
});

test('filters are exact about what they mean', () => {
  const exec = queryMaps(MAPS, { exec: true });
  assert.equal(exec.matched, 2);
  assert.equal(exec.regions[0].perms, 'r-xp');
  // anonymous = no file-backed path; a [anon:...] label counts as anonymous, an empty path too,
  // while /dev/ashmem is a device path (not anonymous, not a module)
  const anon = queryMaps(MAPS, { anon: true });
  assert.equal(anon.matched, 2);
  const file = queryMaps(MAPS, { anon: false });
  assert.equal(file.matched, 3);
  const byPath = queryMaps(MAPS, { path: 'libx.so' });
  assert.equal(byPath.matched, 2);
  const bySize = queryMaps(MAPS, { minSize: 0x10000 });
  assert.equal(bySize.matched, 2);   // 0x10000 and 0x20000
});

test('matched/returned/truncated so a trimmed page is never mistaken for the whole answer', () => {
  const page = queryMaps(MAPS, { limit: 2 });
  assert.equal(page.total, 5);
  assert.equal(page.matched, 5);
  assert.equal(page.returned, 2);
  assert.equal(page.truncated, true);
  const all = queryMaps(MAPS, {});
  assert.equal(all.truncated, false);
  // addr resolution still sees regions outside the returned page
  const withAddr = queryMaps(MAPS, { path: 'nomatch', addr: '0x7600100040' });
  assert.equal(withAddr.regions.length, 0);
  assert.equal(withAddr.resolved?.region.path, '[anon:dalvik-main space]');
});

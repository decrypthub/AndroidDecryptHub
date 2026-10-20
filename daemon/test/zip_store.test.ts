import test from 'node:test';
import assert from 'node:assert/strict';
import { buildStoredZip } from '../src/zip_store.ts';
import { packageSoDirs } from '../src/dump_inventory.ts';

test('stored zip round-trips local file headers', () => {
  const zip = buildStoredZip([
    { name: 'manifest.json', data: Buffer.from('{"ok":true}') },
    { name: 'dex/01_classes.dex', data: Buffer.from('dex\n000') },
  ]);
  assert.equal(zip.readUInt32LE(0), 0x04034b50);
  assert.ok(zip.includes(Buffer.from('manifest.json')));
  assert.ok(zip.includes(Buffer.from('dex/01_classes.dex')));
  // End of central directory signature
  assert.ok(zip.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06])));
});

test('package so dirs include private lib and mapped parents', () => {
  const dirs = packageSoDirs(['/data/app/~~x==/com.ex-y==/lib/arm64/libfoo.so'], 'com.ex');
  assert.ok(dirs.includes('/data/app/~~x==/com.ex-y==/lib/arm64'));
  assert.ok(dirs.includes('/data/data/com.ex/lib'));
  assert.ok(dirs.includes('/data/data/com.ex/files'));
});

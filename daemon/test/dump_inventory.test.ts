import test from 'node:test';
import assert from 'node:assert/strict';
import { contiguousReadable, packageSoDirs, preferMainProcess, processFolderLabel } from '../src/dump_inventory.ts';

const span = (start: string, end: string, perms = 'r--p') => ({ start, end, perms });

test('readable length stops at the first gap and ignores an unreadable page', () => {
  const regions = [
    span('1000', '2000'),
    span('2000', '2800'),
    span('3000', '4000'),
    span('5000', '6000', '---p'),
  ];
  assert.equal(contiguousReadable(regions, '1000', 0x2000), 0x1800);
  assert.equal(contiguousReadable(regions, '5000', 0x100), 0);
  assert.equal(contiguousReadable(regions, '1000', 0x1000), 0x1000);
});

test('package so dirs keep the mapped parent and the private lib/files dirs', () => {
  const dirs = packageSoDirs([
    '/data/app/~~x~~/com.job.android-hash/lib/arm64/libmmkv.so',
    '/data/data/com.job.android/files/libexec.so',
  ], 'com.job.android');
  assert.ok(dirs.includes('/data/app/~~x~~/com.job.android-hash/lib/arm64'));
  assert.ok(dirs.includes('/data/data/com.job.android/files'));
  assert.ok(dirs.includes('/data/data/com.job.android/lib'));
  assert.ok(dirs.includes('/data/user/0/com.job.android/lib'));
  assert.ok(dirs.includes('/data/user/0/com.job.android/files'));
});

test('main process is the one whose name has no colon', () => {
  const rows = [
    { process: 'com.job.android:pushservice', package: 'com.job.android', online: true, pid: 2 },
    { process: 'com.job.android', package: 'com.job.android', online: true, pid: 1 },
    { process: 'com.job.android', package: 'com.job.android', online: false, pid: 3 },
  ];
  assert.equal(preferMainProcess(rows)?.pid, 1);
  assert.equal(preferMainProcess([{ process: 'com.job.android:push', package: 'com.job.android', online: true, pid: 9 }])?.pid, 9);
});

test('process folder label is main or the :suffix', () => {
  assert.equal(processFolderLabel('com.job.android', 'com.job.android'), 'main');
  assert.equal(processFolderLabel('com.job.android:pushservice', 'com.job.android'), 'pushservice');
  assert.equal(processFolderLabel('com.job.android:a/b', 'com.job.android'), 'a_b');
});

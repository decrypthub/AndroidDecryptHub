import test from 'node:test';
import assert from 'node:assert/strict';
import { appOwnedSoModules } from '../src/so_select.ts';

const pkg = 'com.job.android';
const appLib = (name: string, path: string) => ({ name, path });

test('app so: package lib dir and files dir are kept, system and the agent are not', () => {
  const mods = [
    appLib('libexec.so', '/data/data/com.job.android/files/libexec.so'),
    appLib('libmmkv.so', '/data/app/~~x~~/com.job.android-sbdR7==/lib/arm64/libmmkv.so'),
    appLib('libc.so', '/apex/com.android.runtime/lib64/bionic/libc.so'),
    appLib('libart.so', '/system/lib64/libart.so'),
    appLib('libadh_agent.so', '/data/app/~~x~~/com.job.android-sbdR7==/lib/arm64/libadh_agent.so'),
    appLib('base.apk', '/data/app/~~x~~/com.job.android-sbdR7==/base.apk'),
    appLib('libother.so', '/data/data/com.job.android.extra/files/libother.so'),
  ];
  assert.deepEqual(appOwnedSoModules(mods, pkg).map((m) => m.name), ['libexec.so', 'libmmkv.so']);
});

test('app so: an empty or unlabeled package selects nothing', () => {
  const mods = [appLib('libexec.so', '/data/data/com.job.android/files/libexec.so')];
  assert.deepEqual(appOwnedSoModules(mods, ''), []);
  assert.deepEqual(appOwnedSoModules(mods, '?'), []);
  assert.deepEqual(appOwnedSoModules(mods, '   '), []);
});

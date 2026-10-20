import test from 'node:test';
import assert from 'node:assert/strict';
import { parseScopePackages, applicationLabel } from '../src/scope_list.ts';

test('the web switcher is the checked scope list, in file order', () => {
  const raw = `{
    "version": 2,
    "mode": "allowlist",
    "packages": ["com.job.android", "com.uxin.kilaaudio", "com.ss.android.ugc.aweme"]
  }`;
  assert.deepEqual(parseScopePackages(raw), [
    'com.job.android',
    'com.uxin.kilaaudio',
    'com.ss.android.ugc.aweme',
  ]);
});

test('scope noise and the manager package are dropped', () => {
  const raw = "su: warning\n" + JSON.stringify({
    packages: ['com.adh.manager', ' com.example.target ', 'com.example.target', ''],
  });
  assert.deepEqual(parseScopePackages(raw), ['com.example.target']);
  assert.deepEqual(parseScopePackages('   '), []);
});

test('badging prefers the Chinese launcher name', () => {
  const text = [
    "application-label:'Douyin'",
    "application-label-zh-CN:'抖音'",
    "application: label='抖音' icon=''",
  ].join('\n');
  assert.equal(applicationLabel(text), '抖音');
  assert.equal(applicationLabel("application-label:'前程无忧'\n"), '前程无忧');
});

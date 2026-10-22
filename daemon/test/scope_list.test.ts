import test from 'node:test';
import assert from 'node:assert/strict';
import { parseScopePackages, applicationLabel, scopeSwitcherApps, autoArmAllowed } from '../src/scope_list.ts';

test('self-load arms without being in scope; a Zygisk session must be listed', () => {
  const scope = { packages: ['com.example.target'], error: null };
  // entry is how the agent says it was loaded: 'jni_onload' = the process loaded us itself
  // (sandbox / simulated injection), 'start' = Zygisk. Keying on that instead of a package name
  // keeps target identity out of the daemon.
  assert.equal(autoArmAllowed('com.adh.sandbox', 'jni_onload', scope), true);
  assert.equal(autoArmAllowed('com.example.other', 'jni_onload', scope), true);
  assert.equal(autoArmAllowed('com.example.target', 'start', scope), true);
  assert.equal(autoArmAllowed('com.example.other', 'start', scope), false);
  assert.equal(autoArmAllowed('', 'start', scope), false);
  assert.equal(autoArmAllowed('?', 'jni_onload', scope), false);
});

test('a scope that was never read fails open; an empty-but-successful one does not', () => {
  assert.equal(autoArmAllowed('com.example.target', 'start', null), true);
  assert.equal(autoArmAllowed('com.example.target', 'start', { packages: [], error: 'permission denied' }), true);
  assert.equal(autoArmAllowed('com.example.target', 'start', { packages: [], error: null }), false);
});

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

test('a newly checked package is listed before its launcher name is known', () => {
  const labels = new Map([['com.job.android', '前程无忧51Job']]);
  assert.deepEqual(scopeSwitcherApps(['com.job.android', 'com.example.newapp'], labels), [
    { package: 'com.job.android', label: '前程无忧51Job' },
    { package: 'com.example.newapp', label: 'com.example.newapp' },
  ]);
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

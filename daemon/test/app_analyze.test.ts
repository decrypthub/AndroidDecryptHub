import test from 'node:test';
import assert from 'node:assert/strict';

import { mergeScope, parseScopePackages } from '../src/scope_list.ts';
import { analyzePackage, pickAnalysisSession } from '../src/app_analyze.ts';

test('scope merge: add/remove/dedupe and refuse junk before it reaches the inline scope check', () => {
  const start = ['com.a.app', 'com.b.app'];
  assert.deepEqual(mergeScope(start, { add: ['com.c.app', 'com.a.app'] }), ['com.a.app', 'com.b.app', 'com.c.app']);
  assert.deepEqual(mergeScope(start, { remove: ['com.a.app'] }), ['com.b.app']);
  // Same call: remove wins over add, because the operator's explicit removal is the later intent.
  assert.deepEqual(mergeScope(start, { add: ['com.a.app'], remove: ['com.a.app'] }), ['com.b.app']);
  // The scope file is parsed by C++ on a hot path; a malformed name must never be written.
  assert.deepEqual(mergeScope([], { add: ['bad name', 'com..bad', 'com.adh.manager', 'com.ok.app'] }), ['com.ok.app']);
});

test('scope parse drops the manager package and duplicates', () => {
  const raw = JSON.stringify({ version: 2, mode: 'allowlist', packages: ['com.a.app', 'com.a.app', 'com.adh.manager'] });
  assert.deepEqual(parseScopePackages(raw), ['com.a.app']);
});

test('analysis session: the main process wins over a newer companion process', () => {
  const rows = [
    { package: 'com.x.app', process: 'com.x.app:push', online: true, connectedAt: 300 },
    { package: 'com.x.app', process: 'com.x.app', online: true, connectedAt: 100 },
  ];
  assert.equal(pickAnalysisSession(rows)?.process, 'com.x.app');
  // Offline rows are never a target.
  assert.equal(pickAnalysisSession([{ package: 'com.x.app', process: 'com.x.app', online: false, connectedAt: 1 }]), null);
});

test('analyze_package refuses a package that must never be injected, before touching adb', async () => {
  const out = await analyzePackage('com.android.systemui');
  assert.equal(out.ok, false);
  assert.match(String(out.error), /不能分析/);
});

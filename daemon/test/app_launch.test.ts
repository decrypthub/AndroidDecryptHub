import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mayLaunchPackage, pickLauncherComponent, waitForFreshSessions } from '../src/app_launch.ts';

test('pickLauncherComponent finds pkg/activity among resolve-activity noise', () => {
  const out = `priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=true
com.job.android/.SplashActivity
`;
  assert.equal(pickLauncherComponent(out), 'com.job.android/.SplashActivity');
  assert.equal(pickLauncherComponent('nothing here'), null);
});

test('mayLaunchPackage blocks manager and junk', () => {
  assert.equal(mayLaunchPackage('com.job.android'), true);
  assert.equal(mayLaunchPackage('com.adh.manager'), false);
  assert.equal(mayLaunchPackage('../evil'), false);
});

test('waitForFreshSessions settles after the first hit', async () => {
  let n = 0;
  const r = await waitForFreshSessions(
    () => {
      n++;
      return n >= 2 ? [{ connectedAt: 1000 }] : [];
    },
    { sinceMs: 500, timeoutMs: 5_000, settleMs: 50, pollMs: 20 },
  );
  assert.equal(r.ok, true);
  assert.equal(r.sessions.length, 1);
});

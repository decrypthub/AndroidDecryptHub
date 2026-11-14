import test from 'node:test';
import assert from 'node:assert/strict';

import { sessions } from '../src/state.ts';
import { pickSid, sessionForPackage } from '../src/service.ts';

// Field report: pickSid used `.pop()`, so a renderer child could win over the main process and the
// tool then failed with ClassNotFound and no hint about the wrong process. The main process must win.

function put(sessionId: string, process: string, online = true) {
  sessions.set(sessionId, {
    sessionId, pid: 1, uid: 1, package: 'com.x.app', process,
    abi: 'arm64-v8a', android: '15', sdk: 35, entry: 'start', agentVer: '0.8.0',
    connectedAt: 1, lastSeen: 1, online, mapsCount: 0, regionsSample: [],
  } as never);
}

test('the main process wins over a child inserted later', () => {
  sessions.clear();
  put('s_main', 'com.x.app');
  put('s_child', 'com.x.app:render');
  assert.equal(pickSid(), 's_main');
  assert.equal(sessionForPackage('com.x.app'), 's_main');
  // an explicit session is always honored
  assert.equal(pickSid('s_child'), 's_child');
});

test('a child is used only when the main process is not online, and nothing when empty', () => {
  sessions.clear();
  put('s_main', 'com.x.app', false);
  put('s_child', 'com.x.app:render', true);
  assert.equal(pickSid(), 's_child');
  sessions.clear();
  assert.equal(pickSid(), undefined);
  assert.equal(sessionForPackage('com.x.app'), undefined);
});

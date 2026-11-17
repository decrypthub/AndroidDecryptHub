import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyError, errorPayload } from '../src/error_codes.ts';

// These messages are copied from real sessions (field reports from the mtgsig/dewu analysis), because
// the value of this module is exactly that it classifies the failures the tools actually produce.
test('the failure classes a client must branch on are distinguishable', () => {
  assert.equal(classifyError(new Error('mode must be got, inline, sites or vtable')), 'BAD_ARG');
  assert.equal(classifyError(new Error('no session')), 'NO_SESSION');
  assert.equal(classifyError(new Error('no online agent')), 'NO_SESSION');
  assert.equal(classifyError(new Error('agent timed out after 15000 ms')), 'AGENT_TIMEOUT');
  assert.equal(classifyError(new Error('socket hang up')), 'SESSION_OFFLINE');
  assert.equal(classifyError(new Error('target crashed: killed by signal SIGSEGV')), 'TARGET_CRASHED');
  assert.equal(classifyError(new Error('adb: no devices/emulators found')), 'DEVICE_UNAVAILABLE');
});

test('reported capabilities that are absent are UNSUPPORTED_OP, not bad arguments', () => {
  assert.equal(classifyError(new Error('libQBDI.so not available (dlopen)')), 'UNSUPPORTED_OP');
  assert.equal(classifyError(new Error('old agent does not support this op')), 'UNSUPPORTED_OP');
  assert.equal(classifyError(new Error('helper not built: run tools/build_root_watch.sh')), 'HELPER_MISSING');
});

test('capture loss wins over the words it is usually wrapped in', () => {
  // A lossy ring report also says "timeout/incomplete"; misrouting it to AGENT_TIMEOUT would hide the
  // one fact that matters (do not conclude from this window).
  assert.equal(classifyError(new Error('dropped=30249 emitted=712 complete:false')), 'CAPTURE_LOSS');
  assert.equal(classifyError(new Error('906 record(s) were evicted (retain 1000)')), 'CAPTURE_LOSS');
});

test('the payload keeps ok:false and the original prose', () => {
  const p = errorPayload(new Error('invalid addr: expected 0x-prefixed hex'));
  assert.equal(p.ok, false);
  assert.equal(p.code, 'BAD_ARG');
  assert.match(p.error, /expected 0x/);
  assert.equal(errorPayload(undefined).code, 'UNKNOWN');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { NATIVE_THROTTLE_MAX_MS, normalizeThrottleMs, nativeHookInstallPayload } from '../src/native_hook_args.ts';

test('no throttle is the default: missing, null, empty and zero all mean every hit emits', () => {
  assert.equal(normalizeThrottleMs(undefined), 0);
  assert.equal(normalizeThrottleMs(null), 0);
  assert.equal(normalizeThrottleMs(''), 0);
  assert.equal(normalizeThrottleMs(0), 0);
  assert.equal(normalizeThrottleMs(-5), 0);
});

test('a positive window passes through unchanged', () => {
  assert.equal(normalizeThrottleMs(200), 200);
  assert.equal(normalizeThrottleMs(1), 1);
  assert.equal(normalizeThrottleMs('250'), 250);   // numbers arriving as JSON strings still work
});

test('out-of-range windows clamp to the agent ceiling so the effective value is predictable', () => {
  assert.equal(normalizeThrottleMs(NATIVE_THROTTLE_MAX_MS), NATIVE_THROTTLE_MAX_MS);
  assert.equal(normalizeThrottleMs(NATIVE_THROTTLE_MAX_MS + 1), NATIVE_THROTTLE_MAX_MS);
  assert.equal(normalizeThrottleMs(1e9), NATIVE_THROTTLE_MAX_MS);
  assert.equal(normalizeThrottleMs(200.9), 200);
});

test('a non-numeric window is refused instead of silently meaning off', () => {
  assert.throws(() => normalizeThrottleMs('abc'), /throttleMs must be a number of milliseconds, got "abc"/);
  assert.throws(() => normalizeThrottleMs({}), /throttleMs must be a number/);
});

test('the install payload carries throttleMs to the agent', () => {
  const p = nativeHookInstallPayload({ addr: '0x7f001234', throttleMs: 500 });
  assert.equal(p.throttleMs, 500);
  assert.equal(p.action, 'hook');
  assert.equal(p.mode, 'inline');
  assert.equal(p.addr, '0x7f001234');
});

test('the install payload never throttles by surprise', () => {
  assert.equal(nativeHookInstallPayload({ addr: '0x1000' }).throttleMs, 0);
  assert.equal(nativeHookInstallPayload({ addr: '0x1000', throttleMs: 0 }).throttleMs, 0);
});

test('the install payload keeps the rest of the hook shape intact', () => {
  const p = nativeHookInstallPayload({ addr: '0x2000', backtrace: true, skipOriginal: true, returnValue: '0x1', argIndex: 2, argValue: '0x2' });
  assert.equal(p.backtrace, 'true');
  assert.equal(p.skipOriginal, 'true');
  assert.equal(p.returnValue, '0x1');
  assert.equal(p.argIndex, 2);
  assert.equal(p.argValue, '0x2');
  const off = nativeHookInstallPayload({ addr: '0x2000' });
  assert.equal(off.backtrace, 'false');
  assert.equal(off.skipOriginal, 'false');
  assert.equal(off.argIndex, -1);          // -1 = no argument rewrite, the agent default
  assert.equal(off.returnValue, '');
});

test('the payload refuses a garbage window rather than installing an unthrottled hook', () => {
  assert.throws(() => nativeHookInstallPayload({ addr: '0x3000', throttleMs: Number('nope') }), /throttleMs must be a number/);
});

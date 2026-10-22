import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeHookIdentity } from '../src/state.ts';

// The identity of a native-hook record lives INSIDE its payload (the agent emits one JSON object per
// record), so the store could not answer "which hook produced this" without the caller parsing the
// payload itself. Lifting it at ingest is what makes live_captures {hookId} possible - and the reason
// it matters is that `seq` is numbered per hook: two hooks both emit seq=1.

const hexOf = (s: string) => Buffer.from(s, 'utf8').toString('hex');

test('a register event yields its hookId and seq', () => {
  const hex = hexOf('{"hookId":7,"kind":"inline","tid":1234,"x0":"0x1","seq":42,"memWindows":1}');
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK', hex), { hookId: 7, seq: 42 });
});

test('a pre-call memory record and its after twin are told apart by phase', () => {
  const pre = hexOf('{"hookId":3,"seq":9,"mem":[{"reg":"x0","offset":0,"requested":32,"got":32,"short":false,"hex":"aa"}]}');
  const post = hexOf('{"hookId":3,"phase":"after","ret":"0x0","reg":"x2","offset":0,"requested":32,"got":32,"hex":"bb"}');
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK_MEM', pre), { hookId: 3, seq: 9 });
  // The after record has no seq at all - the agent emits it from a different callback. Saying so is
  // the point: a consumer must not invent a seq to pair it.
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK_MEM', post), { hookId: 3, phase: 'after' });
});

test('other capture kinds are left alone instead of being mis-parsed', () => {
  assert.deepEqual(nativeHookIdentity('SSL_write', hexOf('{"hookId":1,"seq":1}')), {});
  assert.deepEqual(nativeHookIdentity('EVP_CipherUpdate', 'aabbcc'), {});
});

test('a truncated or non-JSON payload yields nothing rather than a wrong hook id', () => {
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK', hexOf('{"hookId"')), {});
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK', ''), {});
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK', 'zzzz'), {});
});

test('seq is found even when it sits at the end of a full-size register event', () => {
  // The real event puts the registers first and `seq` last (~900 bytes). A 256-byte window found the
  // hookId but not the seq, so the pair could not be joined - exactly the failure this feature exists
  // to prevent. This fixture is deliberately longer than that window.
  const padding = Array.from({ length: 40 }, (_, i) => `"x${i}":"0x${'ab'.repeat(8)}"`).join(',');
  const event = `{"hookId":12,"kind":"inline","tid":1,${padding},"argIndex":-1,"seq":77,"memWindows":1}`;
  assert.ok(event.length > 600, 'fixture must be longer than the old head window');
  assert.deepEqual(nativeHookIdentity('NATIVE_HOOK', hexOf(event)), { hookId: 12, seq: 77 });
});

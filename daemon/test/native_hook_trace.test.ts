import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NATIVE_TRACE_MAX_INSNS,
  nativeHookInstallPayload,
  nativeTracePayload,
  normalizeTraceFrom,
  normalizeTraceInsns,
} from '../src/native_hook_args.ts';

// In-hook trace (v117) changes what a hook RECORD carries, and it runs on the target thread, so the
// host has to get three things right before the agent sees anything: the ceiling, the register name,
// and - the one that matters most - the DEFAULT must not mention the feature at all. A default
// payload that says traceInsns:0 would still tell the agent "this hook was asked to trace", and the
// acceptance for "off costs nothing" would be untestable.

test('the default install payload carries no trace keys at all', () => {
  const payload = nativeHookInstallPayload({ addr: '0x1234' });
  assert.equal('traceInsns' in payload, false);
  assert.equal('traceFrom' in payload, false);
  assert.deepEqual(nativeTracePayload(0, ''), {});
  assert.deepEqual(nativeTracePayload(undefined, undefined), {});
});

test('a trace install sends exactly the two fields the agent parses', () => {
  const explicit = nativeHookInstallPayload({ addr: '0x10', traceInsns: 32, traceFrom: 'x2' });
  assert.equal(explicit.traceInsns, 32);
  assert.equal(explicit.traceFrom, 'x2');
  // No traceFrom: the run starts at the hooked entry, and the field must be absent rather than "".
  const entry = nativeHookInstallPayload({ addr: '0x10', traceInsns: 200 });
  assert.equal(entry.traceInsns, 200);
  assert.equal('traceFrom' in entry, false);
});

test('the instruction budget is clamped to the ceiling the agent enforces', () => {
  assert.equal(NATIVE_TRACE_MAX_INSNS, 4096);
  assert.equal(normalizeTraceInsns(200), 200);
  assert.equal(normalizeTraceInsns(999999), NATIVE_TRACE_MAX_INSNS);
});

test('a non-numeric or negative budget is refused instead of meaning off', () => {
  assert.throws(() => normalizeTraceInsns('many'), /traceInsns must be a whole number/);
  assert.throws(() => normalizeTraceInsns(1.5), /traceInsns must be a whole number/);
  assert.throws(() => normalizeTraceInsns(-1), /traceInsns must be 0 \(off\) or positive/);
});

test('only registers the hook stub saves are accepted, and the name is canonical', () => {
  assert.equal(normalizeTraceFrom('x0'), 'x0');
  assert.equal(normalizeTraceFrom(' X29 '), 'x29');
  assert.equal(normalizeTraceFrom('x30'), 'x30');
  assert.equal(normalizeTraceFrom(''), '');
  // x10 is not saved by the stub at 256-byte frame: accepting it would read a slot nothing wrote.
  assert.throws(() => normalizeTraceFrom('x10'), /traceFrom must be x0\.\.x9, x29 or x30/);
  assert.throws(() => normalizeTraceFrom('pc'), /traceFrom must be/);
});

test('traceFrom without a budget is refused rather than silently ignored', () => {
  assert.throws(() => nativeTracePayload(0, 'x0'), /traceFrom needs traceInsns/);
  assert.throws(() => nativeHookInstallPayload({ addr: '0x10', traceFrom: 'x0' }), /traceFrom needs traceInsns/);
});

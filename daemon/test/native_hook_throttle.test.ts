import test from 'node:test';
import assert from 'node:assert/strict';
import { NATIVE_THROTTLE_MAX_MS, normalizeThrottleMs, nativeHookInstallPayload } from '../src/native_hook_args.ts';
// The install loops themselves, so "the payload is built but never sent" or "a field is dropped on
// the way to the agent" cannot pass. Both take an injectable sender for exactly this reason.
import { installSymbolHooks } from '../src/native_hook_all.ts';
import { installSvcSiteHooks } from '../src/syscall_watch.ts';

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

test('native_hook_all sends the shared payload - throttleMs and the hook shape - for every symbol', async () => {
  const sent: any[] = [];
  const fake = async (session: string, op: string, args: Record<string, unknown>) => {
    sent.push({ session, op, args });
    return { ok: true, hookId: 100 + sent.length };
  };
  const { hooks, failures } = await installSymbolHooks('s1', 0x7000000000n, [
    { name: 'adh_a', address: '0x10', offset: '0x10', size: 16 },
    { name: 'adh_b', address: '0x30', offset: '0x30', size: 16 },
  ], { throttleMs: 200, backtrace: true }, fake);
  assert.equal(failures.length, 0);
  assert.deepEqual(hooks.map((h) => h.hookId), [101, 102]);
  assert.deepEqual(hooks.map((h) => h.symbol), ['adh_a', 'adh_b']);
  assert.deepEqual(hooks.map((h) => h.address), ['0x7000000010', '0x7000000030']);
  assert.equal(sent.length, 2);
  for (const call of sent) {
    assert.equal(call.session, 's1');
    assert.equal(call.op, 'native_hook');
    assert.equal(call.args.throttleMs, 200);
    assert.equal(call.args.backtrace, 'true');
    assert.equal(call.args.mode, 'inline');
    assert.equal(call.args.argIndex, -1);   // no rewrite unless asked for
  }
});

test('one failed symbol is reported and the rest of the batch still installs', async () => {
  const fake = async (_session: string, _op: string, args: Record<string, unknown>) =>
    (String(args.addr) === '0x1020' ? { ok: false, error: 'already hooked' } : { ok: true, hookId: 7 });
  const { hooks, failures } = await installSymbolHooks('s1', 0x1000n, [
    { name: 'ok', address: '0x10', offset: '0x10', size: 8 },
    { name: 'bad', address: '0x20', offset: '0x20', size: 8 },
  ], {}, fake);
  assert.deepEqual(hooks.map((h) => h.symbol), ['ok']);
  assert.deepEqual(failures, [{ symbol: 'bad', error: 'already hooked' }]);
});

test('syscall_watch installs every site with backtrace and throttleMs', async () => {
  const sent: any[] = [];
  const fake = async (_session: string, _op: string, args: Record<string, unknown>) => {
    sent.push(args);
    return { ok: true, hookId: 40 + sent.length };
  };
  const { installed, error } = await installSvcSiteHooks('s1', [
    { addr: 0x100n, vaddr: '0x100', fileOff: '0x100', nr: 160, name: 'uname', attribution: 'movz-imm' },
    { addr: 0x200n, vaddr: '0x200', fileOff: '0x200', nr: null, name: null, attribution: 'unknown' },
  ], 500, fake);
  assert.equal(error, null);
  assert.deepEqual(installed.map((h) => h.hookId), [41, 42]);
  assert.deepEqual(installed.map((h) => h.syscall), [{ nr: 160, name: 'uname' }, null]);
  assert.equal(sent.length, 2);
  assert.ok(sent.every((a) => a.throttleMs === 500));
  assert.ok(sent.every((a) => a.backtrace === 'true'));   // the digest needs the caller chain
});

test('a mid-batch syscall hook failure hands back the partial installs so the caller can unhook them', async () => {
  let calls = 0;
  const fake = async () => { calls += 1; return calls === 2 ? { ok: false, error: 'prologue mismatch' } : { ok: true, hookId: 50 + calls }; };
  const site = (addr: bigint) => ({ addr, vaddr: `0x${addr.toString(16)}`, fileOff: `0x${addr.toString(16)}`, nr: 160, name: 'uname', attribution: 'movz-imm' });
  const { installed, error } = await installSvcSiteHooks('s1', [site(0x100n), site(0x200n), site(0x300n)], 0, fake);
  assert.ok(error instanceof Error);
  assert.match(error!.message, /svc hook failed at 0x200: prologue mismatch/);
  assert.deepEqual(installed.map((h) => h.hookId), [51]);   // nothing after the failure is attempted
  assert.equal(calls, 2);
});

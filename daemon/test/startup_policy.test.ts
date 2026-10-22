import test from 'node:test';
import assert from 'node:assert/strict';
import { antiDebugTargets, autoAntiDebugEnabled, shouldPreArm, startupWidenPlan } from '../src/service.ts';
import { mergeSettings, settings } from '../src/state.ts';

// The startup policy is the host-side pre-arm: applied at hello, before the capture loop. Two
// things must be true and are easy to break: it is OFF unless settings (or the env override) say
// on, and the plan neutralizes BOTH halves of each check (return value and errno).

const off = { antiDebug: false, module: 'libc.so', extraTargets: [] } as const;
const on = { antiDebug: true, module: 'libc.so', extraTargets: [] } as const;
test('startup anti-debug is off unless settings or the env override says on', () => {
  assert.equal(autoAntiDebugEnabled({} as any, off as any), false);
  assert.equal(autoAntiDebugEnabled({} as any, on as any), true);
  // The env override wins in both directions, so a CI/operator script does not have to rewrite
  // the persisted settings to run a session with (or without) the pre-arm.
  assert.equal(autoAntiDebugEnabled({ ADH_AUTO_ANTIDEBUG: '1' } as any, off as any), true);
  assert.equal(autoAntiDebugEnabled({ ADH_AUTO_ANTIDEBUG: '0' } as any, on as any), false);
  assert.equal(autoAntiDebugEnabled({ ADH_AUTO_ANTIDEBUG: 'on' } as any, off as any), true);
});

test('the startup plan is deliberately minimal: ptrace only', () => {
  const plan = antiDebugTargets(on as any);
  // Measured: hooking access()/faccessat() at hello makes the app's OWN path checks fail during
  // initialization and can kill it. ptrace is the one gate that is safe to fake that early.
  assert.deepEqual(plan, [{ symbol: 'ptrace', returnValue: '0', errno: 0 }]);
});

test('extra targets get the denied pair and are appended once', () => {
  const plan = antiDebugTargets({ antiDebug: true, module: 'libc.so', extraTargets: ['access', 'faccessat', 'access'] } as any);
  assert.deepEqual(plan.map((t) => t.symbol), ['ptrace', 'access', 'faccessat']);
  for (const name of ['access', 'faccessat']) {
    const t = plan.find((x) => x.symbol === name)!;
    assert.equal(t.returnValue, '-1');
    assert.equal(t.errno, 13, `${name}: EACCES is the answer a detector expects for "exists but denied"`);
  }
  assert.equal(plan.filter((t) => t.symbol === 'access').length, 1, 'an extra target must not duplicate');
});

test('an empty package list means every app, a non-empty one is a whitelist', () => {
  const all = { antiDebug: true, module: 'libc.so', extraTargets: [], packages: [] } as any;
  assert.equal(shouldPreArm('com.any.app', {} as any, all), true);
  const one = { antiDebug: true, module: 'libc.so', extraTargets: [], packages: ['com.example.target'] } as any;
  assert.equal(shouldPreArm('com.example.target', {} as any, one), true);
  assert.equal(shouldPreArm('com.other.app', {} as any, one), false, 'pre-arming changes how an app behaves: never silently for others');
  // The master switch still wins over the whitelist.
  assert.equal(shouldPreArm('com.example.target', { ADH_AUTO_ANTIDEBUG: '0' } as any, one), false);
});

test('delayed widening is opt-in, clamped, and deduped', () => {
  const off = startupWidenPlan({ widenAfterMs: 0, widenTargets: ['access'] } as any);
  assert.equal(off.afterMs, 0, '0 = no timer is scheduled even though targets are configured');
  const plan = startupWidenPlan({ widenAfterMs: 99_999_999, widenTargets: ['access', 'access', 'faccessat'] } as any);
  assert.equal(plan.afterMs, 600_000, 'the delay is clamped to ten minutes');
  assert.deepEqual(plan.targets.map((t) => t.symbol), ['access', 'faccessat']);
  assert.deepEqual(plan.targets[0], { symbol: 'access', returnValue: '-1', errno: 13 });
});

test('a settings patch clamps the widen delay and rejects junk targets', () => {
  mergeSettings({ startup: { widenAfterMs: -5, widenTargets: ['access', 'bad symbol', 42] } });
  assert.equal(settings.startup.widenAfterMs, 0);
  assert.deepEqual(settings.startup.widenTargets, ['access']);
});

// The JNI pre-arm is deliberately NOT part of the startup policy: installing the
// RegisterNatives inline hook at hello was measured to corrupt the target's ART (SIGILL, then a
// ConcurrentCopying GC fault) on the SDK 35 reference device, and the wrapper itself is not the
// cause. The capability is documented in docs/CASE_STUDIES.md; it must stay a manual command
// until an install that does not patch libart's text exists.

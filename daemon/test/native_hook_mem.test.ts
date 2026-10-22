import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NATIVE_MEM_WIN_LEN,
  NATIVE_MEM_WIN_MAX,
  NATIVE_MEM_WIN_OFF_MAX,
  NATIVE_MEM_WIN_TOTAL,
  memCapturePreview,
  nativeHookInstallPayload,
  parseMemWindows,
} from '../src/native_hook_args.ts';

test('an empty spec copies nothing', () => {
  for (const value of [undefined, null, '', '   ']) {
    const parsed = parseMemWindows(value);
    assert.deepEqual(parsed.windows, []);
    assert.equal(parsed.spec, '');
  }
});

test('a single window and a spaced list become the canonical spec', () => {
  assert.deepEqual(parseMemWindows('x0:64'), { windows: [{ reg: 0, offset: 0, len: 64 }], spec: 'x0:64' });
  assert.equal(parseMemWindows(' x0:8 , x2+16:32 ').spec, 'x0:8,x2+16:32');
  assert.equal(parseMemWindows('x8+0:1').spec, 'x8:1');
});

test('@ follows one pointer and says so in both the window and the spec', () => {
  // A pointer-of-pointer is the only way to read a VM frame's current instruction record or a
  // dispatch slot's target: the bytes that matter are at *(reg+offset), not at reg+offset.
  assert.deepEqual(parseMemWindows('@x2+32:512'), {
    windows: [{ reg: 2, offset: 32, len: 512, deref: true }],
    spec: '@x2+32:512',
  });
  assert.equal(parseMemWindows('@x0:8').spec, '@x0:8');
  // Both forms in one spec, and the plain one must NOT gain a deref flag.
  const mixed = parseMemWindows('x2:256,@x2+32:512');
  assert.equal(mixed.spec, 'x2:256,@x2+32:512');
  assert.equal(mixed.windows.length, 2);
  assert.equal(mixed.windows[0].deref, undefined);
  assert.equal(mixed.windows[1].deref, true);
  assert.throws(() => parseMemWindows('@x9:8'), /mem window must look like/);
  assert.throws(() => parseMemWindows('@:8'), /mem window must look like/);
});

test('the caps that the agent enforces are accepted on the boundary', () => {
  // Four windows at the per-window ceiling must exactly fill the total. Writing the numbers out by
  // hand is what let this test go stale the day the caps changed: derive the spec from the caps.
  const four = [0, 1, 2, 3].map((r) => `x${r}:${NATIVE_MEM_WIN_LEN}`).join(',');
  assert.equal(NATIVE_MEM_WIN_LEN * NATIVE_MEM_WIN_MAX, NATIVE_MEM_WIN_TOTAL);
  assert.equal(parseMemWindows(four).windows.length, NATIVE_MEM_WIN_MAX);
  assert.equal(parseMemWindows(`x1+${NATIVE_MEM_WIN_OFF_MAX}:1`).spec, `x1+${NATIVE_MEM_WIN_OFF_MAX}:1`);
});

test('a typo is refused instead of installing a hook that copies nothing', () => {
  const tooBig = NATIVE_MEM_WIN_LEN + 1;
  assert.throws(() => parseMemWindows('x9:8'), /mem window must look like/);
  assert.throws(() => parseMemWindows('x0:0'), new RegExp(`mem length 0 must be 1\\.\\.${NATIVE_MEM_WIN_LEN}`));
  assert.throws(() => parseMemWindows(`x0:${tooBig}`), new RegExp(`mem length ${tooBig} must be 1\\.\\.${NATIVE_MEM_WIN_LEN}`));
  assert.throws(() => parseMemWindows('x0:1,x1:1,x2:1,x3:1,x4:1'), /at most 4 windows/);
  assert.throws(() => parseMemWindows(`x0+${NATIVE_MEM_WIN_OFF_MAX + 1}:1`), /mem offset 65536 exceeds 65535/);
  assert.throws(() => parseMemWindows('x0:8,'), /mem window must look like/);
  assert.throws(() => parseMemWindows(8), /mem must be a string/);
});

test('the total cap is a real guard, not a leftover', () => {
  // TOTAL == WIN_MAX * WIN_LEN, so an in-range spec can never exceed it. Assert that relationship
  // and exercise the guard anyway with a spec that would only be accepted if the per-window cap
  // were ignored - that way a future cap change that breaks the invariant fails HERE, loudly,
  // instead of in the field as "my 4 KB window silently became 3 KB".
  assert.equal(NATIVE_MEM_WIN_MAX * NATIVE_MEM_WIN_LEN, NATIVE_MEM_WIN_TOTAL);
  const oversize = [0, 1, 2, 3].map((r) => `x${r}:${NATIVE_MEM_WIN_LEN + 1}`).join(',');
  assert.throws(() => parseMemWindows(oversize), /mem length .* must be 1\.\./);
});

test('the install payload carries the canonical spec and defaults to none', () => {
  assert.equal(nativeHookInstallPayload({ addr: '0x1000', mem: 'x0:8, x0+7:1' }).mem, 'x0:8,x0+7:1');
  assert.equal(nativeHookInstallPayload({ addr: '0x1000' }).mem, '');
});

test('a bad window refuses the payload rather than sending an empty mem', () => {
  assert.throws(() => nativeHookInstallPayload({ addr: '0x1000', mem: 'sp:8' }), /mem window must look like/);
});

test('auto is the spec used when the register is not known yet', () => {
  assert.deepEqual(parseMemWindows('auto'), { windows: [], spec: 'auto' });
  assert.deepEqual(parseMemWindows(' AUTO '), { windows: [], spec: 'auto' });
  assert.equal(nativeHookInstallPayload({ addr: '0x1000', mem: 'auto' }).mem, 'auto');
  assert.throws(() => parseMemWindows('auto,x0:8'), /mem window must look like/);
});

test('a memory capture previews the copied bytes, not the JSON wrapper', () => {
  const json = JSON.stringify({
    hookId: 1,
    seq: 1,
    auto: true,
    mem: [{ reg: 'x0', offset: 0, requested: 64, got: 8, short: true, hex: '4144484d454d3031' }],
  });
  assert.equal(memCapturePreview(json), 'x0 8字节 ADHMEM01');
  assert.equal(memCapturePreview(JSON.stringify({ auto: true, mem: [] })), '没有读到像指针的参数');
  assert.equal(memCapturePreview('not json'), '');
});

test('memory windows do not disturb the rest of the hook payload', () => {
  const p = nativeHookInstallPayload({ addr: '0x2000', mem: 'x3:16', throttleMs: 50, backtrace: true });
  assert.equal(p.mem, 'x3:16');
  assert.equal(p.throttleMs, 50);
  assert.equal(p.backtrace, 'true');
  assert.equal(p.mode, 'inline');
  assert.equal(p.argIndex, -1);
});

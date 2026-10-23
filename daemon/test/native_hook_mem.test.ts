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

test('@#n follows a pointer that an earlier window already copied', () => {
  // The second hop of a pointer chain: a formatter descriptor points at an argument VECTOR, and the
  // vector's slots point at the values. One deref reaches the vector; this reaches the value.
  const parsed = parseMemWindows('@x2+24:32,@#1+8:128,@#1+16:128');
  assert.equal(parsed.spec, '@x2+24:32,@#1+8:128,@#1+16:128');
  assert.equal(parsed.windows.length, 3);
  assert.deepEqual(parsed.windows[1], { reg: -1, offset: 8, len: 128, deref: true, fromWindow: 1 });
  assert.equal(parsed.windows[2].fromWindow, 1);
  // A reference must name an EARLIER window, and the 8-byte pointer must fit inside it.
  assert.throws(() => parseMemWindows('@#1+0:16'), /must reference an earlier window \(1\.\.0\)/);
  assert.throws(() => parseMemWindows('@x0:8,@#2+0:16'), /must reference an earlier window \(1\.\.1\)/);
  assert.throws(() => parseMemWindows('@x0:8,@#1+4:16'), /needs 8 bytes inside window 1 \(length 8\)/);
  assert.throws(() => parseMemWindows('@x0:8,@#1+0:0'), /mem length 0 must be 1\.\./);
});

test('the caps that the agent enforces are accepted on the boundary', () => {
  // Derive the spec from the caps instead of writing the numbers out: that is what let this test go
  // stale the day the caps changed. With six windows at the per-window ceiling the TOTAL is now the
  // binding constraint, so the boundary probe has to respect it.
  const n = Math.min(NATIVE_MEM_WIN_MAX, Math.floor(NATIVE_MEM_WIN_TOTAL / NATIVE_MEM_WIN_LEN));
  const full = [...Array(n)].map((_, r) => `x${r}:${NATIVE_MEM_WIN_LEN}`).join(',');
  assert.ok(n >= 1);
  assert.equal(parseMemWindows(full).windows.length, n);
  assert.ok(NATIVE_MEM_WIN_MAX * NATIVE_MEM_WIN_LEN >= NATIVE_MEM_WIN_TOTAL);
  assert.equal(parseMemWindows(`x1+${NATIVE_MEM_WIN_OFF_MAX}:1`).spec, `x1+${NATIVE_MEM_WIN_OFF_MAX}:1`);
});

test('a typo is refused instead of installing a hook that copies nothing', () => {
  const tooBig = NATIVE_MEM_WIN_LEN + 1;
  assert.throws(() => parseMemWindows('x9:8'), /mem window must look like/);
  assert.throws(() => parseMemWindows('x0:0'), new RegExp(`mem length 0 must be 1\\.\\.${NATIVE_MEM_WIN_LEN}`));
  assert.throws(() => parseMemWindows(`x0:${tooBig}`), new RegExp(`mem length ${tooBig} must be 1\\.\\.${NATIVE_MEM_WIN_LEN}`));
  const tooMany = [...Array(NATIVE_MEM_WIN_MAX + 1)].map((_, r) => `x${r % 9}:1`).join(',');
  assert.throws(() => parseMemWindows(tooMany), new RegExp(`at most ${NATIVE_MEM_WIN_MAX} windows`));
  assert.throws(() => parseMemWindows(`x0+${NATIVE_MEM_WIN_OFF_MAX + 1}:1`), /mem offset 65536 exceeds ±65535/);
  assert.throws(() => parseMemWindows('x0:8,'), /mem window must look like/);
  assert.throws(() => parseMemWindows(8), /mem must be a string/);
});

test('the total cap is a real guard, not a leftover', () => {
  // The window count alone no longer bounds the copy: six windows at the per-window ceiling would be
  // 6 KB while the total stays 4 KB, so TOTAL is now the binding guard. Assert the relationship and
  // exercise the guard, so a future cap change fails HERE rather than in the field as "my window was
  // silently clipped".
  assert.ok(NATIVE_MEM_WIN_MAX * NATIVE_MEM_WIN_LEN >= NATIVE_MEM_WIN_TOTAL);
  const over = [...Array(NATIVE_MEM_WIN_MAX)].map((_, r) => `x${r % 9}:${Math.ceil(NATIVE_MEM_WIN_TOTAL / 2) + 1}`).join(',');
  assert.throws(() => parseMemWindows(over), /mem total .* exceeds|mem length .* must be 1\.\./);
  const fits = [...Array(NATIVE_MEM_WIN_MAX)].map((_, r) => `x${r % 9}:${Math.floor(NATIVE_MEM_WIN_TOTAL / NATIVE_MEM_WIN_MAX)}`).join(',');
  assert.equal(parseMemWindows(fits).windows.length, NATIVE_MEM_WIN_MAX);
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

test('a negative offset reads BEFORE the register and keeps its sign', () => {
  // A template interpreter keeps its instruction records in one contiguous array, so the record that
  // produced the value a handler renders sits at pc-10. Without a negative offset the grammar can only
  // look forward, which is why this exists at all.
  assert.equal(parseMemWindows('x3-40:40').spec, 'x3-40:40');
  assert.deepEqual(parseMemWindows('x3-40:40').windows, [{ reg: 3, offset: -40, len: 40 }]);
  assert.equal(parseMemWindows('x0:8,x0-8:8').spec, 'x0:8,x0-8:8');
  assert.equal(parseMemWindows('@x1-8:16').spec, '@x1-8:16');
  assert.equal(parseMemWindows('x0-0:8').spec, 'x0:8');            // -0 is 0: no sign in the canonical spec
  assert.equal(nativeHookInstallPayload({ addr: '0x1000', mem: 'x3-40:40' }).mem, 'x3-40:40');
  // The total still bounds the list, and the offset ceiling applies to the magnitude, not the sign.
  assert.throws(() => parseMemWindows('x3-70000:8'), /mem offset -70000 exceeds/);
  // A reference into an earlier window indexes BYTES, so a negative index there is a different question.
  assert.throws(() => parseMemWindows('x0:8,@#1-8:8'), /must look like/);
});

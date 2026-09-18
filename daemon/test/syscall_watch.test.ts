import test from 'node:test';
import assert from 'node:assert/strict';
import { attributeSite, parseSyscallToken, resolveSyscallFilter, syscallName } from '../src/syscall_watch.ts';

// Encode the prologue shapes bionic uses for a syscall stub.
const movz = (nr, w = false) => ((w ? 0x52800000 : 0xd2800000) | ((nr & 0xffff) << 5) | 8) >>> 0;
const movzLsl16 = (nr, w = false) => ((w ? 0x52a00000 : 0xd2a00000) | ((nr & 0xffff) << 5) | 8) >>> 0;
const movk = (nr, w = false) => ((w ? 0x72800000 : 0xf2800000) | ((nr & 0xffff) << 5) | 8) >>> 0;
const movReg = (dst, src) => (0xaa0003e0 | (src << 16) | dst) >>> 0;      // mov Xd, Xm (ORR xd, xzr, xm)
const ldrX8Sp = 0xf94003e8;                                                // ldr x8, [sp, #0]
const SVC = 0xd4000001;
const RET = 0xd65f03c0;
const B = 0x14000001;
const CBZ_X0 = 0xb4000040;                                                 // cbz x0, #8
const BR_X8 = 0xd61f0100;                                                  // br x8

function layout(words) {
  const buf = Buffer.alloc(words.length * 4);
  words.forEach((w, i) => buf.writeUInt32LE(w >>> 0, i * 4));
  const idx = words.findIndex((w) => (w >>> 0) === SVC);
  return { buf, svcOff: idx * 4 };
}

test('attributes movz x8, #160 before svc to uname', () => {
  const { buf, svcOff } = layout([movz(160), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, 160);
  assert.equal(r.how, 'movz-imm');
  assert.equal(syscallName(r.nr), 'uname');
});

test('attributes the 32-bit mov w8 form (gettid 178)', () => {
  const { buf, svcOff } = layout([movz(178, true), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, 178);
  assert.equal(syscallName(r.nr), 'gettid');
});

test('attributes movz x8, #imm, lsl #16', () => {
  const { buf, svcOff } = layout([movzLsl16(1), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, 0x10000);
  assert.equal(r.how, 'movz-imm-lsl16');
});

test('refuses when an instruction CLOSER to the svc overwrites x8 (register move)', () => {
  // movz x8, #63 ; mov x8, x1 ; svc  -> the number is not 63, and we must not say it is.
  const { buf, svcOff } = layout([movz(63), movReg(8, 1), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, null);
  assert.equal(r.how, 'ambiguous-write');
});

test('refuses when a load closer to the svc writes x8', () => {
  const { buf, svcOff } = layout([movz(63), ldrX8Sp, SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, null);
  assert.equal(r.how, 'ambiguous-write');
});

test('refuses an unmodelled movz+movk constant instead of half-reporting it', () => {
  // movz w8, #1 ; movk w8, #0x2345, lsl #16 ; svc -> the real number is 0x23450001, which we do not
  // reconstruct, so the site stays unknown rather than confidently wrong.
  const { buf, svcOff } = layout([movz(1, true), movk(0x2345, true), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, null);
  assert.equal(r.how, 'ambiguous-write');
});

test('the closer movz wins over an overwritten farther one', () => {
  // movz x8, #63 ; movz w8, #1, lsl #16 ; svc -> w8 clears the low half, so the answer is 0x10000.
  const { buf, svcOff } = layout([movz(63), movzLsl16(1, true), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, 0x10000);
  assert.equal(r.how, 'movz-imm-lsl16');
});

test('stops at an unconditional branch instead of borrowing the neighbour stub number', () => {
  // movz x8,#63 ; svc ; b ; svc ; ret  -> for the SECOND svc the closest thing is a branch.
  const words = [movz(63), SVC, B, SVC, RET];
  const buf = Buffer.alloc(words.length * 4);
  words.forEach((w, i) => buf.writeUInt32LE(w >>> 0, i * 4));
  const secondSvc = 3 * 4;
  const r = attributeSite(buf, secondSvc);
  assert.equal(r.nr, null);
  assert.equal(r.how, 'unknown');
  assert.ok(r.insns.some((s) => s.startsWith('stop@')), `expected the scan to stop at the branch, saw ${JSON.stringify(r.insns)}`);
});

test('stops at cbz and at br as well', () => {
  for (const [label, branch] of [['cbz', CBZ_X0], ['br', BR_X8]]) {
    const words = [movz(63), SVC, branch, SVC, RET];
    const buf = Buffer.alloc(words.length * 4);
    words.forEach((w, i) => buf.writeUInt32LE(w >>> 0, i * 4));
    const r = attributeSite(buf, 3 * 4);
    assert.equal(r.nr, null, `${label}: expected no attribution across a branch`);
    assert.ok(r.insns.some((s) => s.startsWith('stop@')), `${label}: expected a stop marker`);
  }
});

test('reports unknown when the number comes from a register, never guesses', () => {
  const { buf, svcOff } = layout([movReg(8, 1), SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, null);
});

test('an empty filter means "no filter", not "match nothing"', () => {
  assert.equal(resolveSyscallFilter(''), null);
  assert.equal(resolveSyscallFilter([]), null);
  assert.equal(resolveSyscallFilter(','), null);
  assert.equal(resolveSyscallFilter(undefined), null);
});

test('the filter accepts names, decimal, hex and numbers, and reports junk', () => {
  const a = resolveSyscallFilter('uname,0xa0,117');
  assert.deepEqual([...a.wanted].sort((x, y) => x - y), [117, 160]);
  assert.equal(a.bad.length, 0);
  const b = resolveSyscallFilter(['gettid', 278, 'nope']);
  assert.deepEqual([...b.wanted].sort((x, y) => x - y), [178, 278]);
  assert.deepEqual(b.bad, ['nope']);
});

test('parses filter tokens by name, decimal and hex; rejects junk', () => {
  assert.equal(parseSyscallToken('uname'), 160);
  assert.equal(parseSyscallToken(' 160 '), 160);
  assert.equal(parseSyscallToken('0xa0'), 160);
  assert.equal(parseSyscallToken(117), 117);
  assert.equal(parseSyscallToken('nope'), null);
});

test('names unknown numbers instead of inventing one', () => {
  assert.equal(syscallName(9999), 'syscall_9999');
});
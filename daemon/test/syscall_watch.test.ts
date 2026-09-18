import test from 'node:test';
import assert from 'node:assert/strict';
import { attributeSite, parseSyscallToken, syscallName } from '../src/syscall_watch.ts';

// Encode the exact prologue shape bionic uses for a syscall stub: movz x8/w8, #nr ; svc #0.
const movz = (nr, w = false) => ((w ? 0x52800000 : 0xd2800000) | ((nr & 0xffff) << 5) | 8) >>> 0;
const movzLsl16 = (nr) => (0xd2a00000 | ((nr & 0xffff) << 5) | 8) >>> 0;
const SVC = 0xd4000001;
const RET = 0xd65f03c0;
const B = 0x14000000;

// Lay the words out and hand back the buffer plus the file offset of the FIRST svc word.
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

test('stops at a control-flow instruction instead of borrowing a neighbour stub number', () => {
  // The previous stub ends in `b` between us and its movz: the scan must stop, not attribute 63.
  const { buf, svcOff } = layout([movz(63), SVC, B, SVC, RET]);
  const r = attributeSite(buf, svcOff + 12);   // the second svc
  assert.equal(r.nr, null);
  assert.equal(r.how, 'unknown');
});

test('reports unknown when the number comes from a register, never guesses', () => {
  const { buf, svcOff } = layout([0xaa0103e8 /* mov x8, x1 */, SVC, RET]);
  const r = attributeSite(buf, svcOff);
  assert.equal(r.nr, null);
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
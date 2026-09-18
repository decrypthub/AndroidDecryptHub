import test from 'node:test';
import assert from 'node:assert/strict';
import {digestTrace, traceCompleteness } from '../src/trace_digest.ts';

const insn = (addr, text) => ({ addr, text });

test('reports a loop with its body and iteration count, and does not call a repeated call site a loop', () => {
  const trace = [
    insn('0x1000', 'mov x0, #0'),
    insn('0x1004', 'ldr w1, [x2, #0x10]'),   // loop body
    insn('0x1008', 'bl #0x2000'),            // call executed twice, NOT a loop header
    insn('0x100c', 'b #0x1004'),             // back edge
    insn('0x1004', 'ldr w1, [x2, #0x10]'),
    insn('0x1008', 'bl #0x2000'),
    insn('0x1010', 'ret'),
  ];
  const d = digestTrace(trace);
  assert.equal(d.loops.length, 1, `expected exactly one loop, saw ${JSON.stringify(d.loops)}`);
  assert.equal(d.loops[0].target, '0x1004');
  assert.equal(d.loops[0].iterations, 2);
  assert.ok(d.loops[0].bodyInstructions >= 2);
  assert.equal(d.instructions, 7);
  assert.equal(d.uniqueAddresses, 5);   // 1000/1004/1008/100c/1010
});

test('aggregates call targets and flags register-indirect calls honestly', () => {
  const d = digestTrace([
    insn('0x1', 'bl #0x9000'),
    insn('0x2', 'bl #0x9000'),
    insn('0x3', 'blr x8'),
  ]);
  const direct = d.calls.find((c) => c.target === '0x9000');
  assert.equal(direct?.count, 2);
  assert.equal(direct?.via, 'bl');
  assert.ok(d.calls.some((c) => c.target.startsWith('(')), 'indirect call should be listed, not silently dropped');
  assert.ok(d.notes.some((n) => n.includes('register-indirect')));
});

test('extracts memory access shapes from bracketed operands', () => {
  const d = digestTrace([
    insn('0x1', 'ldr x0, [x1, #0x18]'),
    insn('0x2', 'str w2, [x1, #0x18]'),
    insn('0x3', 'ldr w3, [x4]'),
    insn('0x4', 'ldr w5, [x6, x7, lsl #3]'),
  ]);
  const loaded = d.memory.find((m) => m.mnemonic === 'ldr' && m.base === 'x1' && m.offset === '0x18');
  assert.equal(loaded?.count, 1);
  const stored = d.memory.find((m) => m.mnemonic === 'str');
  assert.equal(stored?.base, 'x1');
  const noOffset = d.memory.find((m) => m.base === 'x4');
  assert.equal(noOffset?.offset, '0');
  const indexed = d.memory.find((m) => m.base === 'x6');
  assert.equal(indexed?.offset, '0', 'register-indexed access has no constant offset');
});

test('flags known crypto constants and keeps the raw value', () => {
  const d = digestTrace([
    insn('0x1', 'mov w8, #0x9e3779b9'),
    insn('0x2', 'mov w9, #0x9e3779b9'),
    insn('0x3', 'movz x10, #0x1234'),
  ]);
  const tea = d.constants.find((c) => c.value === '0x9e3779b9');
  assert.equal(tea?.count, 2);
  assert.match(String(tea?.note ?? ''), /golden ratio/);
  const plain = d.constants.find((c) => c.value === '0x1234');
  assert.equal(plain?.note, undefined);
});

test('counts branch shape and keeps the hottest instructions with their text', () => {
  const d = digestTrace([
    insn('0x1', 'cmp w0, #4'),
    insn('0x2', 'b.gt #0x20'),
    insn('0x3', 'b #0x10'),
    insn('0x4', 'br x9'),
    insn('0x2', 'b.gt #0x20'),
  ]);
  assert.equal(d.branches.conditional, 2);
  assert.equal(d.branches.unconditional, 1);
  assert.equal(d.branches.indirect, 1);
  assert.equal(d.branches.targets.find((t) => t.target === '0x20')?.count, 2);
  assert.equal(d.hotInstructions[0].addr, '0x2');
  assert.match(d.hotInstructions[0].text, /b\.gt/);
});

test('an empty trace says so instead of pretending to have analysed something', () => {
  const d = digestTrace([]);
  assert.equal(d.instructions, 0);
  assert.equal(d.calls.length, 0);
  assert.ok(d.notes.some((n) => n.includes('empty trace')));
});

test('a straight-line trace reports no loops and says why', () => {
  const d = digestTrace([insn('0x1', 'mov x0, #1'), insn('0x2', 'ret')]);
  assert.equal(d.loops.length, 0);
  assert.ok(d.notes.some((n) => n.includes('no repeated address')));
});
test('a clipped trace is reported as clipped, not as a short one', () => {
  assert.deepEqual(traceCompleteness({ count: 120, seen: 900, truncated: true, cap: 8192 }, 120),
    { seen: 900, truncated: true, cap: 8192 });
  // Older agent: no seen/truncated - the list length is all we know, and nothing is claimed.
  assert.deepEqual(traceCompleteness({ count: 120 }, 120), { seen: 120, truncated: false, cap: null });
  // A counter smaller than the list is inconsistent; the list wins and nothing is claimed about
  // clipping (the agent's count is what it SAW, so it can only be >= the list length).
  assert.deepEqual(traceCompleteness({ count: 100 }, 120), { seen: 120, truncated: false, cap: null });
});

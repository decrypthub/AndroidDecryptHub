import test from 'node:test';
import assert from 'node:assert/strict';
import { joinNativeLook } from '../src/native_look.ts';

function hexOf(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('hex');
}

const hook = (seq: number, x0 = '0x1000') => hexOf({
  hookId: 7, seq, memWindows: 1, x0, x1: '0x14',
});
const mem = (seq: number, auto = false) => hexOf({
  hookId: 7, seq, auto,
  mem: [{ reg: 'x0', offset: 0, requested: 8, got: 8, short: false, hex: '4144484d454d3031' }],
});

test('no hit yet is a sentence, not an empty object', () => {
  const look = joinNativeLook([], 7);
  assert.equal(look.hit, false);
  assert.match(look.text, /还没有命中/);
  assert.equal(look.windows.length, 0);
});

test('a hook event and its memory record become one line', () => {
  const look = joinNativeLook([
    { func: 'NATIVE_HOOK', hex: hook(1), id: 1 },
    { func: 'NATIVE_HOOK_MEM', hex: mem(1), id: 2 },
    { func: 'NATIVE_HOOK', hex: hexOf({ hookId: 9, seq: 1, x0: '0x1' }), id: 3 },
  ], 7);
  assert.equal(look.hit, true);
  assert.equal(look.seq, 1);
  assert.equal(look.text, 'x0 8字节 ADHMEM01');
  assert.equal(look.windows[0].hex, '4144484d454d3031');
  assert.equal(look.regs.x0, '0x1000');
  assert.equal(look.note, '');
});

test('the later seq is the one that is shown', () => {
  const look = joinNativeLook([
    { func: 'NATIVE_HOOK_MEM', hex: mem(1), id: 1 },
    { func: 'NATIVE_HOOK', hex: hook(2, '0x2000'), id: 2 },
    { func: 'NATIVE_HOOK_MEM', hex: mem(2), id: 3 },
  ], 7);
  assert.equal(look.seq, 2);
  assert.equal(look.regs.x0, '0x2000');
});

test('a hit with no memory copy says so', () => {
  const look = joinNativeLook([
    { func: 'NATIVE_HOOK', hex: hexOf({ hookId: 7, x0: '0x20' }), id: 1 },
  ], 7);
  assert.equal(look.hit, true);
  assert.match(look.text, /没有抄到内存/);
  assert.equal(look.regs.x0, '0x20');
});

test('auto that copied two pointers says the extra window is another argument', () => {
  const look = joinNativeLook([{
    func: 'NATIVE_HOOK_MEM',
    hex: hexOf({
      hookId: 7, seq: 1, auto: true,
      mem: [
        { reg: 'x0', offset: 0, got: 4, hex: '4144484d' },
        { reg: 'x1', offset: 0, got: 1, hex: '00' },
      ],
    }),
    id: 1,
  }], 7);
  assert.match(look.note, /别的参数寄存器/);
  assert.equal(look.windows.length, 2);
});

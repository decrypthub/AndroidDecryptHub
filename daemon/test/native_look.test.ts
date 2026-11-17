import test from 'node:test';
import assert from 'node:assert/strict';
import { joinNativeLook, selectNativeLook, nativeLookRead } from '../src/native_look.ts';

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

test('an in-hook trace comes back with the hit, on the same line', () => {
  const look = joinNativeLook([{
    func: 'NATIVE_HOOK',
    hex: hexOf({
      hookId: 7, seq: 3, x0: '0x1000', memWindows: 1,
      trace: {
        insns: 32, seen: 32, stopReason: 'instruction-budget',
        start: '0x70001000', stopPc: '0x70001040', capped: false,
        mnemonics: [{ mnemonic: 'ldr', count: 12 }, { mnemonic: 'add', count: 7 }],
        first: ['0x70001000: ldr x0, [x1, #8]'],
      },
    }),
    id: 1,
  }], 7);
  assert.equal(look.hit, true);
  assert.ok(look.trace);
  assert.equal(look.trace?.seen, 32);
  assert.equal(look.trace?.stopReason, 'instruction-budget');
  assert.match(look.text, /重放 trace 32\/32 条/);
  assert.equal(look.trace?.execution, 'replay');
  assert.equal(look.trace?.coverage, 'instrumented-module');
  assert.equal(look.trace?.contextComplete, false);
  assert.match(look.text, /ldr×12/);
});

test('a hook without a trace reports no trace rather than an empty one', () => {
  const look = joinNativeLook([{ func: 'NATIVE_HOOK', hex: hook(1), id: 1 }], 7);
  assert.equal(look.trace, null);
  assert.doesNotMatch(look.text, /就地 trace/);
});

test('seq selects an earlier hit and does not borrow the newest registers', () => {
  const records = [
    { func: 'NATIVE_HOOK', hex: hook(1, '0x1111'), id: 1 },
    { func: 'NATIVE_HOOK_MEM', hex: mem(1), id: 2 },
    { func: 'NATIVE_HOOK', hex: hook(14, '0xeeee'), id: 3 },
    { func: 'NATIVE_HOOK_MEM', hex: mem(14), id: 4 },
  ];
  const latest = selectNativeLook(records, 7);
  assert.equal(latest.look.seq, 14);
  assert.equal(latest.look.regs.x0, '0xeeee');
  assert.equal(latest.retained.total, 2);
  assert.equal(latest.retained.nextBeforeSeq, 14);
  assert.equal(latest.hits, undefined);

  const earlier = selectNativeLook(records, 7, { seq: 1 });
  assert.equal(earlier.look.seq, 1);
  assert.equal(earlier.look.regs.x0, '0x1111');
  assert.equal(earlier.hits?.length, 1);
  assert.equal(earlier.retained.nextBeforeSeq, null);

  const page = selectNativeLook(records, 7, { beforeSeq: 14, limit: 50 });
  assert.deepEqual(page.hits?.map((h) => h.seq), [1]);
  assert.equal(page.look.regs.x0, '0x1111');
});

test('a missing seq names the hits that are still stored', () => {
  const selected = selectNativeLook([
    { func: 'NATIVE_HOOK', hex: hook(2), id: 1 },
  ], 7, { seq: 9 });
  assert.equal(selected.look.hit, false);
  assert.match(selected.look.text, /没有 seq=9/);
  assert.match(selected.look.text, /2/);
  assert.equal(selected.retained.total, 1);
  assert.deepEqual(selected.hits, []);
});

test('beforeSeq and limit reject a bad page and a mixed cursor', () => {
  assert.throws(() => selectNativeLook([], 7, { limit: 51 }), /limit must be an integer 1\.\.50/);
  assert.throws(() => selectNativeLook([], 7, { seq: 1, beforeSeq: 2 }), /not both/);
});

test('read keeps a stored earlier hit when the agent status query fails', async () => {
  const look = await nativeLookRead('s1', 7, {
    captures: [
      { sessionId: 's1', func: 'NATIVE_HOOK', hex: hook(1, '0x1111'), id: 1 },
      { sessionId: 's1', func: 'NATIVE_HOOK', hex: hook(2, '0x2222'), id: 2 },
    ],
    drainSession: async () => {},
    sendCmd: async () => { throw new Error('agent disconnected'); },
  }, { seq: 1 });
  assert.equal(look.seq, 1);
  assert.equal(look.regs.x0, '0x1111');
  assert.equal(look.retained.total, 2);
  assert.equal(look.hits?.length, 1);
  assert.equal(look.drainError, undefined);
  assert.equal(look.observationError, 'agent disconnected');
});

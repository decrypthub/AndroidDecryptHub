import test from 'node:test';
import assert from 'node:assert/strict';

import { firstDifference, oracleRecord, oracleStability } from '../src/oracle.ts';

// The field report that motivated this: "dhw 的非纯函数性质是手写两次重放逐字节比对才发现的，
// 而这恰恰是最先该知道的事". stability answers it in one call with fake-agent deps here.

const reply = (b5: string) => JSON.stringify([{ b5 }]);

function fakeAgent(values: string[]) {
  let i = 0;
  return {
    sendCmd: async (_session: string, op: string) => {
      if (op === 'java_call') return { ok: true, callId: 1 };
      const v = values[Math.min(i, values.length - 1)];
      i++;
      return { ok: true, call: { state: 'done', result: { result: v } } };
    },
  };
}

test('a pure facade answers the same value on every replay', async () => {
  const rec = await oracleRecord('s1', { className: 'X', method: 'entry', extract: 'result[0].b5' }, fakeAgent([reply('v1')]));
  assert.equal(rec.ok, true, rec.error);
  const st = await oracleStability('s1', { id: Number(rec.id), repeat: 3 }, fakeAgent([reply('v1')]));
  assert.equal(st.ok, true, st.error);
  assert.equal(st.stable, true);
  assert.equal(st.distinct, 1);
  assert.equal(st.runs, 3);
  assert.equal(st.firstDiff, null);
});

test('hidden state is reported as unstable, with the first differing path', async () => {
  const rec = await oracleRecord('s1', { className: 'X', method: 'entry', extract: 'result[0].b5' }, fakeAgent([reply('v1'), reply('v2')]));
  assert.equal(rec.ok, true, rec.error);
  const st = await oracleStability('s1', { id: Number(rec.id), repeat: 3 }, fakeAgent([reply('v2'), reply('v1'), reply('v2')]));
  assert.equal(st.ok, true, st.error);
  assert.equal(st.stable, false);
  assert.equal(st.distinct, 2);
  assert.equal(st.firstDiff, '<root>');   // the extracted value itself moved\n  assert.equal(st.extract, 'result[0].b5');
});

test('repeat is clamped so one call cannot spin the target forever', async () => {
  const rec = await oracleRecord('s1', { className: 'X', method: 'entry', extract: 'result[0].b5' }, fakeAgent([reply('v1')]));
  const st = await oracleStability('s1', { id: Number(rec.id), repeat: 100 }, fakeAgent([reply('v1')]));
  assert.equal(st.runs, 8);
  const one = await oracleStability('s1', { id: Number(rec.id), repeat: 0 }, fakeAgent([reply('v1')]));
  assert.equal(one.runs, 3); // default
});

test('firstDifference walks objects and arrays and names the deepest path', () => {
  assert.equal(firstDifference({ a: 1 }, { a: 1 }), null);
  assert.equal(firstDifference({ a: [1, 2] }, { a: [1, 3] }), 'a[1]');
  assert.equal(firstDifference({ a: { b: 'x' } }, { a: { b: 'y' } }), 'a.b');
  assert.equal(firstDifference({ a: 1 }, { b: 1 }), 'a');
  assert.equal(firstDifference(null, { a: 1 }), '<root>');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { getPath, setPath, summarizeDiff, oracleRecord, oracleReplay, oracleDiff, listOracles, dropOracle } from '../src/oracle.ts';

// The oracle is the primitive every real protocol analysis reimplements by hand: call the target's own
// entry point with controlled arguments, then change ONE input field and see which output moved. The
// path language and the dependency matrix are pure and tested here; the wiring is exercised with a fake
// agent so a failure names the wrong thing.

const JDGS = JSON.stringify([JSON.stringify({ b1: 'app-key', b4: 'AAA=', b5: 'deadbeef', b7: '123' })]);
const REPLY = { ok: true, className: 'X', method: 'entry', returnType: 'java.lang.Object[]', result: JDGS };

test('a path walks strings, arrays and object keys', () => {
  assert.equal(getPath(REPLY, 'result[0].b5'), 'deadbeef');
  assert.equal(getPath({ a: { b: [10, 20] } }, 'a.b[1]'), 20);
  assert.equal(getPath({ a: '[1,2]' }, 'a[0]'), 1);       // a JSON string is parsed on the way
  assert.equal(getPath(REPLY, 'result[0].nope'), undefined);
  assert.equal(getPath(null, 'a'), undefined);
});

test('setPath is immutable and creates the containers a path needs', () => {
  const args = [101, [{ $bytesHex: '4142' }, 'x', 'eid']];
  const next: any = setPath(args, '[1][0].$bytesHex', '4344');
  assert.equal(next[1][0].$bytesHex, '4344');
  assert.equal((args[1][0] as any).$bytesHex, '4142');    // the template is untouched
  const grown: any = setPath({}, 'a.b[0].c', 7);
  assert.equal(grown.a.b[0].c, 7);
  assert.deepEqual(setPath([1, 2], '[0]', 9), [9, 2]);
});

test('the diff names the fields that move the output and the ones that never did', () => {
  const baseline = 'deadbeef';
  const res = summarizeDiff(baseline, [
    { label: 'same', patches: [{ path: '[2]', value: 'other-eid' }], value: 'deadbeef' },
    { label: 'moved', patches: [{ path: '[1][0].$bytesHex', value: 'ff' }], value: '0badc0de' },
    { label: 'two fields', patches: [{ path: '[3]', value: '1.1' }, { path: '[4]', value: 'zzz' }], value: 'deadbeef' },
  ]);
  assert.deepEqual(res.sensitive, ['[1][0].$bytesHex']);
  assert.deepEqual(res.insensitive, ['[2]']);
  assert.deepEqual(res.rows.map((r) => r.same), [true, false, true]);
  // A variant with several patches is never used to attribute sensitivity: it cannot tell which one did it.
  assert.equal(res.rows[2].changedPaths.length, 2);
});

test('record keeps the exact arguments and the observed value; replay patches them; diff compares', async () => {
  const seen: any[] = [];
  const fake = {
    sendCmd: async (session: string, op: string, args: Record<string, unknown>) => {
      seen.push({ op, args });
      if (op === 'java_call') return { ok: true, callId: 7 };
      return { ok: true, call: { state: 'done', elapsedMs: 1, result: { result: JSON.stringify([{ b5: 'v1' }]) } } };
    },
  };
  const calls = () => seen.filter((s) => s.op === 'java_call');
  const rec = await oracleRecord('s1', {
    className: 'com.x.Bridge', method: 'entry', params: 'int,java.lang.Object[]',
    args: [101, [{ $bytesHex: '41' }], 'eid'], extract: 'result[0].b5',
  }, fake);
  assert.equal(rec.ok, true, rec.error);
  assert.equal(rec.baseline, 'v1');
  assert.equal(calls()[0].args.detach, 'true');
  assert.equal(JSON.parse(String(calls()[0].args.args))[0], 101);

  const rep = await oracleReplay('s1', { id: Number(rec.id), patches: [{ path: '[1][0].$bytesHex', value: '42' }] }, fake);
  assert.equal(rep.ok, true, rep.error);
  assert.deepEqual(JSON.parse(String(calls()[1].args.args))[1][0].$bytesHex, '42');
  assert.equal(JSON.parse(String(calls()[0].args.args))[1][0].$bytesHex, '41');   // the template is untouched

  const diff = await oracleDiff('s1', {
    id: Number(rec.id),
    variants: [
      { label: 'same', patches: [{ path: '[2]', value: 'eid2' }] },
      { label: 'bumped', patches: [{ path: '[1][0].$bytesHex', value: '43' }] },
    ],
  }, fake);
  assert.equal(diff.ok, true, diff.error);
  assert.equal(diff.diff?.rows.length, 2);

  assert.equal(listOracles().length, 1);
  assert.equal(dropOracle(Number(rec.id)), true);
  assert.equal(listOracles().length, 0);
});

test('an unknown template id is an error, not an empty answer', async () => {
  const fake = { sendCmd: async () => ({ ok: true }) };
  const r = await oracleReplay('s1', { id: 999, patches: [] }, fake);
  assert.equal(r.ok, false);
  assert.match(String(r.error), /unknown oracle id 999/);
});

test('a failed call is reported with the target\'s own error', async () => {
  const fake = {
    sendCmd: async (_s: string, op: string) => (op === 'java_call'
      ? { ok: true, callId: 3 }
      : { ok: true, call: { state: 'failed', error: 'java.lang.IllegalStateException: nope' } }),
  };
  const rec = await oracleRecord('s1', { className: 'a', method: 'b' }, fake);
  assert.equal(rec.ok, false);
  assert.match(String(rec.error), /nope/);
});

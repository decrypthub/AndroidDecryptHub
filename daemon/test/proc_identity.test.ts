import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalizeStarttimeTicks, parseProcStat, assertProcessGeneration } from '../src/proc_identity.ts';

const archive = JSON.parse(readFileSync(new URL('./fixtures/runtime_diagnostics.json', import.meta.url), 'utf8'));
test('process generation keeps large ticks as strings and rejects malformed hello values', () => {
  assert.equal(normalizeStarttimeTicks('18446744073709551615'), '18446744073709551615');
  for (const value of [123456, null, '', '-1', '1.2', '123;id', '123\n', '1'.repeat(21)])
    assert.equal(normalizeStarttimeTicks(value), undefined);
  const weird = archive.thread.stat.replace('(probe (worker))', '(probe\n(worker)))');
  assert.equal(parseProcStat(weird).starttime, '123460');
});
test('independent root identity check refuses reused PIDs while legacy generations stay explicitly unverified', () => {
  const stat = archive.process.stat;
  assert.deepEqual(assertProcessGeneration(stat, 101, '123456'), { starttimeTicks: '123456', sessionGenerationVerified: true });
  assert.deepEqual(assertProcessGeneration(stat, 101), { starttimeTicks: '123456', sessionGenerationVerified: false });
  assert.throws(() => assertProcessGeneration(stat, 101, '123455'), /generation/);
  assert.throws(() => assertProcessGeneration(stat, 102, '123456'), /exact device PID/);
  assert.throws(() => assertProcessGeneration('permission denied', 101, '123456'), /exact device PID/);
  assert.throws(() => assertProcessGeneration(stat, 101, '123456;id'), /generation/);
});

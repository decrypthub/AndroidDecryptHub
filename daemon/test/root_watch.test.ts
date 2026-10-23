import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRootWatch, projectRootSample } from '../src/root_watch.ts';

test('root watch validates exact addresses without rounding and preserves single-thread scope', () => {
  assert.deepEqual(normalizeRootWatch({ tid: 42, addr: '0XABCDEF10' }), {
    tid: 42, addr: '0xabcdef10', width: 8, mode: 'w', durationMs: 5000, maxEvents: 128, stackBytes: 8192,
  });
  assert.equal(normalizeRootWatch({ tid: 1, addr: '0x1004', mode: 'x' }).width, 4);
  for (const args of [
    { tid: 0 }, { tid: '42' }, { addr: '0x1001' }, { addr: '0x1000;id' },
    { addr: '0x10000000000000000' }, { mode: 'x', width: 8 }, { mode: 'anything' },
    { durationMs: 30001 }, { maxEvents: 2049 }, { stackBytes: 16385 }, { stackBytes: 7 },
  ]) assert.throws(() => normalizeRootWatch({ tid: 42, addr: '0x1000', ...args }));
});

test('kernel stack windows are bounded and cannot silently read another address', () => {
  const record = { seq: 1, ip: '0x2000', regs: ['0xdead'], stack: { addr: '0x1000', requested: 8, got: 4, hex: '41424344' } };
  const normal = projectRootSample(record, {});
  assert.equal(normal.regs, undefined);
  assert.deepEqual(normal.stack, { addr: '0x1000', requested: 8, got: 4, short: true });
  assert.equal(normal.stack.hex, undefined);
  const selected = projectRootSample(record, { registers: true, stackAddress: '0x1002', stackSize: 4 });
  assert.deepEqual(selected.regs, ['0xdead']);
  assert.deepEqual(selected.stackWindow, { addr: '0x1002', requested: 4, got: 2, short: true, hex: '4344' });
  assert.throws(() => projectRootSample(record, { stackAddress: '0x999', stackSize: 1 }), /outside/);
  assert.throws(() => projectRootSample(record, { stackAddress: '0x1005', stackSize: 1 }), /outside/);
  assert.throws(() => projectRootSample(record, { stackSize: 2049 }));
  assert.equal(record.stack.hex, '41424344');
});

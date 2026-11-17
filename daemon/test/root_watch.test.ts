import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRootWatch, projectRootSample } from '../src/root_watch.ts';

test('root watch validates exact addresses without rounding and preserves single-thread scope', () => {
  assert.deepEqual(normalizeRootWatch({ tid: 42, addr: '0XABCDEF10' }), {
    tid: 42, addr: '0xabcdef10', width: 8, mode: 'w', durationMs: 5000, maxEvents: 128, stackBytes: 8192,
    breakpoints: [], mem: [],
  });
  assert.equal(normalizeRootWatch({ tid: 1, addr: '0x1004', mode: 'x' }).width, 4);
  for (const args of [
    { tid: 0 }, { tid: '42' }, { addr: '0x1001' }, { addr: '0x1000;id' },
    { addr: '0x10000000000000000' }, { mode: 'x', width: 8 }, { mode: 'anything' },
    { durationMs: 30001 }, { maxEvents: 2049 }, { stackBytes: 16385 }, { stackBytes: 7 },
  ]) assert.throws(() => normalizeRootWatch({ tid: 42, addr: '0x1000', ...args }));
});

test('extra hardware slots and memory windows are validated, not passed through', () => {
  const spec = normalizeRootWatch({
    tid: 7, addr: '0x1000', mode: 'x', width: 4,
    breakpoints: [{ addr: '0x2000', mode: 'x' }, { addr: '0x3000', width: 8, mode: 'rw' }],
    mem: ['x13:16', '@x12+0x40:8', '@@x29-0x30:8', '@@x12@8:0x40'],
  });
  assert.deepEqual(spec.breakpoints, ['bp=0x2000:4:x', 'bp=0x3000:8:rw']);
  assert.deepEqual(spec.mem, ['x13:16', '@x12+0x40:8', '@@x29-0x30:8', '@@x12@8:0x40']);
  for (const bad of [
    { breakpoints: [{ addr: '0x2001', mode: 'x' }] },
    { breakpoints: [{ addr: '0x2000', mode: 'x', width: 8 }] },
    { breakpoints: [{ addr: '0x2000', width: 3 }] },
    { breakpoints: [1] },
    { breakpoints: [{ addr: '0x1000' }, { addr: '0x2000' }, { addr: '0x3000' }, { addr: '0x4000' }] },
    { mem: ['r13:16'] }, { mem: ['x99:8'] }, { mem: ['x1:0'] }, { mem: ['x1:257'] },
    { mem: ['x1+zz:8'] }, { mem: ['x1;id'] }, { mem: [1] },
    { mem: ['x0', 'x1', 'x2', 'x3', 'x4'] },
  ]) assert.throws(() => normalizeRootWatch({ tid: 42, addr: '0x1000', ...bad }));
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

test('event-time stack bytes replace stale process reads without mutating the raw evidence', () => {
  const record = { regs: ['0x1001'], stack: { addr: '0x1000', got: 4, requested: 4, hex: '00656600' },
    mem: [{ spec: 'x0:2', addr: '0x1001', hex: '2020' }] };
  const projected = projectRootSample(record, {});
  assert.deepEqual(projected.mem, [{ spec: 'x0:2', addr: '0x1001', hex: '6566',
    source: 'kernel-stack-sample', snapshotConsistent: true }]);
  assert.equal(record.mem[0].hex, '2020');
  assert.equal(projected.regs, undefined);
});

test('heap reads and partially captured windows remain explicitly asynchronous', () => {
  const record = { regs: ['0x2000', '0x1003'],
    stack: { addr: '0x1000', got: 4, requested: 16, hex: '00656600' },
    mem: [{ spec: 'x0:1', addr: '0x2000', hex: 'aa' }, { spec: 'x1:2', addr: '0x1003', hex: 'bbcc' }] };
  const { mem } = projectRootSample(record, {});
  assert.deepEqual(mem.map((window: any) => [window.hex, window.source, window.snapshotConsistent]),
    [['aa', 'process-memory-after-sample', false], ['bbcc', 'process-memory-after-sample', false]]);
});

test('pointer chains use only captured stack pointers and honor hop offsets', () => {
  const bytes = Buffer.alloc(48);
  bytes.writeBigUInt64LE(0x1008n, 0);
  bytes.writeBigUInt64LE(0x1020n, 16);
  bytes[32] = 0x61;
  const record = { regs: ['0x1000'],
    stack: { addr: '0x1000', got: bytes.length, requested: bytes.length, hex: bytes.toString('hex') },
    mem: [{ spec: '@@x0@8:1', addr: '0x9000', error: 'unreadable' }] };
  const projected = projectRootSample(record, {});
  assert.deepEqual(projected.mem[0], { spec: '@@x0@8:1', addr: '0x1020', hex: '61',
    source: 'kernel-stack-sample', snapshotConsistent: true });
  bytes.writeBigUInt64LE(0x2000n, 0);
  record.stack.hex = bytes.toString('hex');
  assert.equal(projectRootSample(record, {}).mem[0].snapshotConsistent, false);
});

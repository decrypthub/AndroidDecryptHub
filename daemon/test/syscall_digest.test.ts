import test from 'node:test';
import assert from 'node:assert/strict';
import { digestSyscallSamples, pickCaller, callerLabel, ringNote, syscallCounters } from '../src/syscall_digest.ts';

const caller = (module, symbol = null, offset = '0x10') => ({ module, symbol, offset });
const sample = (hookId, observedNr, ts, tid, callers) => ({ hookId, observedNr, ts, tid, callers });

test('skips libc frames and reports the first app frame as the caller', () => {
  const c = pickCaller([caller('libc.so', 'uname'), caller('libadhdetect.so', 'adh_libc_uname_probe')]);
  assert.equal(c.module, 'libadhdetect.so');
  assert.equal(callerLabel(c), 'libadhdetect.so:adh_libc_uname_probe');
  // all-libc chain: fall back to the first frame rather than inventing one
  const only = pickCaller([caller('libc.so', 'openat')]);
  assert.equal(only.module, 'libc.so');
  assert.equal(callerLabel(null), '(unknown)');
});

test('a lossy capture ring produces a note instead of a clean-looking digest', () => {
  assert.equal(ringNote(null), null);
  assert.equal(ringNote({ seq: 10, emitted: 10, dropped: 0, backlog: 0, complete: true }), null);
  const note = ringNote({ seq: 100, emitted: 20, dropped: 80, backlog: 0, complete: false });
  assert.match(String(note), /capture ring is incomplete \(dropped=80/);
  assert.match(String(note), /lower bound/);
});

test('an unmapped (JIT) caller frame is used with its raw address instead of being skipped', () => {
  const jit = { module: null, symbol: null, offset: null, address: '0x7f0012340000' };
  const d = digestSyscallSamples([{ hookId: 1, observedNr: 278, ts: 1, tid: 1, callers: [jit] }]);
  assert.equal(d.groups[0].caller, '0x7f0012340000 (no module)');
});

test('a nearest-preceding symbol is labelled as such instead of pretending to be exact', () => {
  const near = { module: 'libapp.so', symbol: 'cryptoInit', offset: '0x120', address: '0x1', exact: false };
  const exact = { module: 'libapp.so', symbol: 'cryptoInit', offset: '0x10', address: '0x1', exact: true };
  assert.equal(callerLabel(near), 'libapp.so:cryptoInit (near)');
  assert.equal(callerLabel(exact), 'libapp.so:cryptoInit');
});

test('the digest reports the timestamp window it actually observed', () => {
  const d = digestSyscallSamples([
    sample(1, 160, 500, 1, [caller('libapp.so', 'probe')]),
    sample(1, 160, 100, 1, [caller('libapp.so', 'probe')]),
    sample(1, 160, 900, 1, [caller('libapp.so', 'probe')]),
  ]);
  assert.equal(d.observedFrom, 100);
  assert.equal(d.observedTo, 900);
});


test('groups by (syscall number, caller) with counts, window and tids', () => {
  const d = digestSyscallSamples([
    sample(1, 160, 100, 11, [caller('libc.so', 'uname'), caller('libapp.so', 'collectFingerprint')]),
    sample(1, 160, 300, 11, [caller('libc.so', 'uname'), caller('libapp.so', 'collectFingerprint')]),
    sample(1, 160, 500, 12, [caller('libc.so', 'uname'), caller('libapp.so', 'collectFingerprint')]),
    sample(2, 160, 700, 12, [caller('libc.so', 'uname'), caller('libapp.so', 'otherProbe')]),
  ]);
  assert.equal(d.samples, 4);
  assert.equal(d.groups.length, 2);
  const top = d.groups[0];
  assert.equal(top.nr, 160);
  assert.equal(top.name, 'syscall_160');
  assert.equal(top.caller, 'libapp.so:collectFingerprint');
  assert.equal(top.count, 3);
  assert.equal(top.firstTs, 100);
  assert.equal(top.lastTs, 500);
  assert.deepEqual(top.tids, [11, 12]);
  assert.deepEqual(d.observed, [{ nr: 160, count: 4 }]);
});

test('names come from the caller table when provided', () => {
  const d = digestSyscallSamples([sample(1, 160, 1, 1, [caller('libapp.so', 'probe')])], { names: { 160: 'uname' } });
  assert.equal(d.groups[0].name, 'uname');
});

test('a hook whose runtime x8 disagrees with the attributed number is reported as a mismatch', () => {
  const d = digestSyscallSamples([
    sample(7, 63, 10, 1, [caller('libapp.so', 'readFile')]),   // attributed 160 (uname) but issued 63 (read)
    sample(7, 63, 20, 1, [caller('libapp.so', 'readFile')]),
    sample(8, 160, 30, 1, [caller('libapp.so', 'probe')]),     // correct
  ], { expected: { 7: 160, 8: 160 } });
  assert.equal(d.mismatches.length, 1);
  assert.deepEqual(d.mismatches[0], { hookId: 7, attributed: 160, observed: 63, count: 2 });
  assert.ok(d.notes.some((n) => n.includes('attribution mismatch')));
  // hook 8 is not reported
  assert.ok(!d.mismatches.some((m) => m.hookId === 8));
});

test('an unknown syscall number is grouped as unknown rather than dropped', () => {
  const d = digestSyscallSamples([sample(1, null, 5, 1, [caller('libapp.so', 'x')])]);
  assert.equal(d.groups.length, 1);
  assert.equal(d.groups[0].nr, null);
  assert.equal(d.groups[0].name, 'unknown');
  assert.deepEqual(d.observed, [{ nr: null, count: 1 }]);
});

test('empty input says what to do instead of pretending to have data', () => {
  const d = digestSyscallSamples([]);
  assert.equal(d.samples, 0);
  assert.equal(d.groups.length, 0);
  assert.ok(d.notes.some((n) => n.includes('no syscall events')));
});

test('the tids list stays bounded and unique', () => {
  const samples = [];
  for (let i = 0; i < 12; i++) samples.push(sample(1, 178, i, 1000 + i, [caller('libapp.so', 'gettidProbe')]));
  samples.push(sample(1, 178, 99, 1003, [caller('libapp.so', 'gettidProbe')]));
  const d = digestSyscallSamples(samples, { maxTids: 4 });
  assert.equal(d.groups[0].count, 13);
  assert.equal(d.groups[0].tids.length, 4);
  assert.equal(new Set(d.groups[0].tids).size, 4);
});

test('decoded arguments become a group example and feed the path histogram', () => {
  const openat = (path) => [{ name: 'path', kind: 'string', value: path }, { name: 'flags', kind: 'flags', value: 'O_RDONLY' }];
  const d = digestSyscallSamples([
    { hookId: 1, observedNr: 56, ts: 1, tid: 1, callers: [caller('libapp.so', 'probe')], args: openat('/proc/cpuinfo') },
    { hookId: 1, observedNr: 56, ts: 2, tid: 1, callers: [caller('libapp.so', 'probe')], args: openat('/proc/cpuinfo') },
    { hookId: 1, observedNr: 56, ts: 3, tid: 1, callers: [caller('libapp.so', 'probe')], args: openat('/sys/devices/system/cpu/possible') },
  ]);
  assert.equal(d.decodedSamples, 3);
  assert.match(String(d.groups[0].example), /path=\/proc\/cpuinfo/);
  assert.deepEqual(d.paths, [
    { path: '/proc/cpuinfo', count: 2 },
    { path: '/sys/devices/system/cpu/possible', count: 1 },
  ]);
});

test('a group without decoded arguments has no example, and no paths are invented', () => {
  const d = digestSyscallSamples([sample(1, 178, 1, 1, [caller('libapp.so', 'gettidProbe')])]);
  assert.equal(d.groups[0].example, undefined);
  assert.deepEqual(d.paths, []);
  assert.equal(d.decodedSamples, 0);
});

test('a module without a symbol is labelled by offset, not by an empty name', () => {
  const d = digestSyscallSamples([sample(1, 178, 1, 1, [caller('libapp.so', null, '0x4bb10')])]);
  assert.equal(d.groups[0].caller, 'libapp.so+0x4bb10');
});
test('a thinned watch is counted, not mistaken for a quiet target', () => {
  // The agent's status is authoritative: hits counts every hit, throttled the suppressed ones.
  const withStatus = syscallCounters([{ id: 3, hits: 120, throttled: 100 }, { id: 4, hits: 5, throttled: 0 }], 25, 3);
  assert.deepEqual(withStatus, { hits: 125, throttled: 100, emitted: 25, source: 'hook-status', basis: 'since-install' });
  // Without status the event deltas are the lower bound - and the source field says so.
  const events = syscallCounters(null, 25, 3);
  assert.deepEqual(events, { hits: 28, throttled: 3, emitted: 25, source: 'events', basis: 'window-lower-bound' });
  // A hook set that exists but was never hit must not invent numbers.
  assert.deepEqual(syscallCounters([{ id: 9, hits: 0, throttled: 0 }], 0, 0), { hits: 0, throttled: 0, emitted: 0, source: 'hook-status', basis: 'since-install' });
});

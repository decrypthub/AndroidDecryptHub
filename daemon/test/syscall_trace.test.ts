import test from 'node:test';
import assert from 'node:assert/strict';
import { syscallTraceStart, syscallTraceDigest, syscallTraceStop } from '../src/syscall_trace.ts';

function fakeDeps({ watch, digest, unhook } = {}) {
  const calls = { watch: [], digest: [], unhook: [] };
  return {
    calls,
    deps: {
      watch: async (session, opts) => { calls.watch.push(opts); return watch ?? { module: 'libc.so', installedCount: 1, matchedCount: 1, svcCount: 10, hooks: [{ hookId: 7, addr: '0x1', syscall: { nr: 160, name: 'uname' } }] }; },
      digest: async (session, opts) => { calls.digest.push(opts); return digest ?? { samples: 2, groups: [], observed: [], mismatches: [], hooksSeen: [7], paths: [], decodedSamples: 0, observedFrom: 1, observedTo: 2, notes: [], window: { sinceMs: null, limit: 1000 }, symbolSource: 'dynsym' }; },
      unhook: async (session, ids) => { calls.unhook.push(ids); return unhook ?? { unhooked: ids, failures: [] }; },
    },
  };
}

test('start threads the attributed syscall number of every hook into expected', async () => {
  const { deps, calls } = fakeDeps({
    watch: {
      module: 'libc.so', installedCount: 2, matchedCount: 2, svcCount: 224,
      hooks: [
        { hookId: 3, addr: '0xa', syscall: { nr: 160, name: 'uname' } },
        { hookId: 4, addr: '0xb', syscall: { nr: 56, name: 'openat' } },
      ],
    },
  });
  const r = await syscallTraceStart('s1', { module: 'libc.so', syscalls: ['uname', 'openat'], limit: 2 }, deps);
  assert.deepEqual(r.hookIds, [3, 4]);
  assert.deepEqual(r.expected, { 3: 160, 4: 56 });
  assert.equal(r.svcCount, 224);
  assert.deepEqual(calls.watch[0], { module: 'libc.so', syscalls: ['uname', 'openat'], limit: 2 });
});

test('start reports sites whose number could not be attributed instead of inventing one', async () => {
  const { deps } = fakeDeps({
    watch: {
      module: 'libapp.so', installedCount: 2, matchedCount: 2, svcCount: 3,
      hooks: [
        { hookId: 1, addr: '0x1', syscall: { nr: 178, name: 'gettid' } },
        { hookId: 2, addr: '0x2', syscall: null },
      ],
    },
  });
  const r = await syscallTraceStart('s1', { module: 'libapp.so' }, deps);
  assert.deepEqual(r.expected, { 1: 178 });
  assert.deepEqual(r.unattributed, ['0x2']);
  assert.match(r.note, /no statically attributed number/);
});

test('start fails loud when the watch installed nothing', async () => {
  const { deps } = fakeDeps({ watch: { module: 'libc.so', installedCount: 0, matchedCount: 0, svcCount: 0, hooks: [] } });
  await assert.rejects(() => syscallTraceStart('s1', { module: 'libc.so' }, deps), /no hook was installed/);
});

test('digest forwards hookIds and the expected map and returns the digest', async () => {
  const { deps, calls } = fakeDeps({});
  const r = await syscallTraceDigest('s1', { hookIds: [7, 7], expected: { 7: 160 }, decode: false }, deps);
  assert.deepEqual(calls.digest[0].hookIds, [7]);
  assert.deepEqual(calls.digest[0].expected, { 7: 160 });
  assert.equal(calls.digest[0].decode, false);
  assert.equal(r.digest.samples, 2);
});

test('digest refuses an empty id list instead of silently doing nothing', async () => {
  const { deps } = fakeDeps({});
  await assert.rejects(() => syscallTraceDigest('s1', { hookIds: [0, -1] }, deps), /need hookIds/);
});

test('stop unhooks exactly the ids it was given, deduped', async () => {
  const { deps, calls } = fakeDeps({});
  const r = await syscallTraceStop('s1', { hookIds: [3, 3, 4] }, deps);
  assert.deepEqual(calls.unhook[0], [3, 4]);
  assert.equal(r.ok, true);
  assert.deepEqual(r.unhooked, [3, 4]);
});

test('stop surfaces per-id failures', async () => {
  const { deps } = fakeDeps({ unhook: { unhooked: [3], failures: [{ hookId: 4, error: 'gone' }] } });
  const r = await syscallTraceStop('s1', { hookIds: [3, 4] }, deps);
  assert.equal(r.ok, false);
  assert.equal(r.failures.length, 1);
});

test('stop refuses to run without ids (no implicit unhook-all)', async () => {
  const { deps, calls } = fakeDeps({});
  await assert.rejects(() => syscallTraceStop('s1', { hookIds: [] }, deps), /need hookIds/);
  assert.equal(calls.unhook.length, 0);
});
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { nativeHookInstallPayload, nativeObservationPayload, ensureNativeObservationSupport, NATIVE_EVENT_LIMIT_MAX } from '../src/native_hook_args.ts';
import { installSymbolHooks } from '../src/native_hook_all.ts';
import { nativeLookArm, nativeLookRead, joinNativeLook } from '../src/native_look.ts';

test('observation controls have explicit defaults and reject misleading or overflowing values', () => {
  assert.deepEqual(nativeObservationPayload({}), { maxEvents: 0, sampleEvery: 1, tid: 0, returnAddress: '' });
  assert.deepEqual(nativeObservationPayload({ maxEvents: 3, sampleEvery: 7, tid: 123, returnAddress: '00ABCD' }),
    { maxEvents: 3, sampleEvery: 7, tid: 123, returnAddress: '0xabcd' });
  for (const maxEvents of [-1, 0.1, NaN, Infinity, NATIVE_EVENT_LIMIT_MAX + 1, true as any])
    assert.throws(() => nativeObservationPayload({ maxEvents }), /maxEvents/);
  for (const sampleEvery of [0, -1, 2.5, NATIVE_EVENT_LIMIT_MAX + 1])
    assert.throws(() => nativeObservationPayload({ sampleEvery }), /sampleEvery/);
  for (const tid of [-1, 0.1, 2 ** 32]) assert.throws(() => nativeObservationPayload({ tid }), /tid/);
  for (const returnAddress of ['0', '-1', '0x10000000000000000', '0x12junk', 'x30'])
    assert.throws(() => nativeObservationPayload({ returnAddress }), /returnAddress/);
});

test('single, batch and native_look installs carry the same controls to the agent', async () => {
  const options = { maxEvents: 2, sampleEvery: 3, tid: 117, returnAddress: '0x1234' };
  const sent: any[] = [];
  const send = async (_session: string, op: string, args: any) => {
    sent.push({ op, args });
    return args.action === 'status' ? { ok: true, status: { observationControlsVersion: 1 } } : { ok: true, hookId: 7 };
  };
  const payload = nativeHookInstallPayload({ addr: '0x1000', ...options, skipOriginal: true, returnValue: '0x54' });
  assert.equal(payload.skipOriginal, 'true');
  assert.equal(payload.returnValue, '0x54');
  await installSymbolHooks('s1', 0x1000n, [{ name: 'target', address: '0x10', offset: '0x10', size: 16 }], options, send);
  await nativeLookArm('s1', { addr: '0x1010', ...options }, { sendCmd: send, captures: [], drainSession: async () => {} });
  assert.equal(sent.filter(s => s.args.action === 'status').length, 2);
  for (const wire of [payload, ...sent.filter(s => s.args.action === 'hook').map((s) => s.args)]) {
    for (const [key, value] of Object.entries(options)) assert.equal(wire[key], value, key);
  }
  await assert.rejects(() => installSymbolHooks('s1', 0x1000n, [], { sampleEvery: 0 }, send), /sampleEvery/);
});

test('new observation controls require an advertised version; defaults do not query legacy agents', async () => {
  let calls = 0;
  const legacy = async () => { calls++; return { ok: true, status: {} }; };
  await ensureNativeObservationSupport('s1', {}, legacy);
  await ensureNativeObservationSupport('s1', { maxEvents: 0, sampleEvery: 1, tid: 0, returnAddress: '' }, legacy);
  assert.equal(calls, 0);
  await assert.rejects(() => ensureNativeObservationSupport('s1', { sampleEvery: 0 }, legacy), /sampleEvery/);
  assert.equal(calls, 0, 'invalid controls must fail before any RPC');
  for (const version of [undefined, 0, '1', NaN, 0.5]) {
    await assert.rejects(() => ensureNativeObservationSupport('s1', { maxEvents: 1 },
      async () => ({ ok: true, status: { observationControlsVersion: version } })), /does not support/);
  }
  await assert.rejects(() => ensureNativeObservationSupport('s1', { tid: 7 }, async () => { throw new Error('offline'); }), /cannot verify.*offline/);
  assert.deepEqual(await ensureNativeObservationSupport('s1', { maxEvents: 1 },
    async () => ({ ok: true, status: { observationControlsVersion: 1 } })),
    { maxEvents: 1, sampleEvery: 1, tid: 0, returnAddress: '' });
});

test('legacy native_look and batch calls with controls fail before any hook is installed', async () => {
  let installed = 0, queried = 0;
  const send = async (_session: string, _op: string, args: any) => {
    if (args.action === 'status') { queried++; return { ok: true, status: {} }; }
    installed++; return { ok: true, hookId: 7 };
  };
  await assert.rejects(() => nativeLookArm('s1', { addr: '0x1010', maxEvents: 1 },
    { sendCmd: send, captures: [], drainSession: async () => {} }), /does not support/);
  await assert.rejects(() => installSymbolHooks('s1', 0x1000n,
    [{ name: 'target', address: '0x10', offset: '0x10', size: 16 }], { sampleEvery: 2 }, send), /does not support/);
  assert.equal(queried, 2); assert.equal(installed, 0);
});

test('native_look never combines registers from a different seq and retains before/after phases', () => {
  const record = (func: string, event: any, id: number) => ({ func, hex: Buffer.from(JSON.stringify({ hookId: 7, ...event })).toString('hex'), id });
  const prior = record('NATIVE_HOOK', { seq: 1, x0: '0x1111' }, 1);
  const missing = joinNativeLook([prior, record('NATIVE_HOOK_MEM', { seq: 2, mem: [{ reg: 'x0', hex: '4144', got: 2 }] }, 2)], 7);
  assert.deepEqual(missing.regs, {});
  assert.equal(missing.pairing, 'memory-only');
  assert.match(missing.note, /缺失/);
  const paired = joinNativeLook([
    record('NATIVE_HOOK', { seq: 3, x0: '0x3333' }, 3),
    record('NATIVE_HOOK_MEM', { seq: 3, mem: [{ reg: 'x0', hex: '41' }] }, 4),
    record('NATIVE_HOOK_MEM', { seq: 3, phase: 'after', mem: [{ reg: 'x0', hex: '42' }] }, 5),
  ], 7);
  assert.equal(paired.pairing, 'paired');
  assert.deepEqual(paired.windows.map((w) => [w.phase, w.hex]), [['before', '41'], ['after', '42']]);
  const newer = joinNativeLook([prior, record('NATIVE_HOOK_MEM', { seq: 1, mem: [{ hex: '41' }] }, 2),
    record('NATIVE_HOOK', { seq: 2, x0: '0x2222' }, 3)], 7);
  assert.equal(newer.seq, 2);
  assert.equal(newer.windows.length, 0);
});

test('actual C++ event gate keeps a strict quota under concurrent callers and resets cleanly', (t) => {
  const compiler = process.env.CXX || 'g++';
  const probe = spawnSync(compiler, ['--version'], { encoding: 'utf8' });
  if (probe.error && (probe.error as NodeJS.ErrnoException).code === 'ENOENT') {
    t.skip(`${compiler} unavailable; native gate runtime test needs a host C++ compiler`);
    return;
  }
  assert.equal(probe.status, 0, probe.stderr);
  const dir = mkdtempSync(path.join(tmpdir(), 'adh-native-budget-'));
  try {
    const exe = path.join(dir, process.platform === 'win32' ? 'budget.exe' : 'budget');
    const source = fileURLToPath(new URL('../../agent/test/native_event_budget.cpp', import.meta.url));
    const built = spawnSync(compiler, ['-std=c++11', '-pthread', '-Wall', '-Wextra', '-Werror', source, '-o', exe], { encoding: 'utf8', timeout: 30000 });
    assert.equal(built.status, 0, `${built.stdout}\n${built.stderr}`);
    const run = spawnSync(exe, [], { encoding: 'utf8', timeout: 10000 });
    assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
    assert.match(run.stdout, /ADH_NATIVE_EVENT_BUDGET_PASS/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('native_look reports filtered traffic even when no capture record was admitted', async () => {
  const look: any = await nativeLookRead('s1', 7, {
    captures: [], drainSession: async () => {},
    sendCmd: async () => ({ ok: true, status: { hooks: [{ id: 7, hits: 12, filtered: 12, selected: 0,
      sampledOut: 0, throttled: 0, limited: 0, emitted: 0, maxEvents: 2, sampleEvery: 3,
      budgetReached: false, emittedMeaning: 'submitted-to-capture-ring' }] } }),
  });
  assert.equal(look.hit, false);
  assert.equal(look.observation.filtered, 12);
  assert.match(look.text, /已触发 12 次/);
  assert.doesNotMatch(look.text, /还没有命中/);
});

test('native_look keeps stored records readable and explicitly reports drain/status failures', async () => {
  const look = await nativeLookRead('s1', 7, {
    captures: [{ sessionId: 's1', func: 'NATIVE_HOOK', hex: Buffer.from(JSON.stringify({ hookId: 7, seq: 1, x0: '0x1234' })).toString('hex') }],
    drainSession: async () => { throw new Error('drain timed out'); },
    sendCmd: async () => { throw new Error('agent disconnected'); },
  });
  assert.equal(look.hit, true);
  assert.equal(look.regs.x0, '0x1234');
  assert.equal(look.drainError, 'drain timed out');
  assert.equal(look.observationError, 'agent disconnected');
});

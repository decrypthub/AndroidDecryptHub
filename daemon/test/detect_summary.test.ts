import test from 'node:test';
import assert from 'node:assert/strict';
import {
  armDetectJava, detectJavaPlan, pathKind, planDetectModules, selectDetectModules,
  summarizeDetection, sysHooksArmed,
} from '../src/detect.ts';
import { policySystemOn } from '../src/service.ts';

const pkg = 'com.example.app';
const appPath = (name: string) => `/data/app/${pkg}-xx/lib/arm64/${name}`;

test('ptrace keeps the request result and a traceme note', () => {
  const s = summarizeDetection([{
    func: 'ptrace',
    text: 'request=0\tpid=0\tret=-1\tlr=0xabc\tnote=PTRACE_TRACEME',
  }], true);
  const debug = s.kinds.find((k) => k.kind === 'debug');
  assert.equal(debug?.count, 1);
  assert.match(debug?.examples[0] ?? '', /PTRACE_TRACEME/);
  assert.match(debug?.examples[0] ?? '', /ret=-1/);
  assert.equal(s.hits[0].lr, '0xabc');
});

test('a legacy ptrace line and a legacy access path still classify', () => {
  const s = summarizeDetection([
    { func: 'ptrace', text: 'ptrace(request=0 PTRACE_TRACEME)' },
    { func: 'access', text: '/system/xbin/su' },
    { func: 'sysprop', text: 'ro.debuggable' },
  ], true);
  assert.equal(s.kinds.find((k) => k.kind === 'debug')?.count, 2);
  assert.equal(s.kinds.find((k) => k.kind === 'root')?.count, 1);
});

test('su is root, a surface library is not, and the return value stays on the path', () => {
  assert.equal(pathKind('/system/lib64/libsurfaceflinger.so'), null);
  assert.equal(pathKind('/system/bin/su'), 'root');
  const s = summarizeDetection([
    { func: 'access', text: 'mode=0\tret=-1\tlr=0x1\tpath=/system/bin/su' },
    { func: 'faccessat', text: 'dirfd=-100\tmode=0\tflags=0\tret=0\tlr=0x2\tpath=/system/lib64/libsurfaceflinger.so' },
  ], true);
  assert.equal(s.kinds.find((k) => k.kind === 'root')?.count, 1);
  assert.match(s.kinds.find((k) => k.kind === 'root')?.examples[0] ?? '', /ret=-1/);
  assert.equal(s.kinds.find((k) => k.kind === 'other')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'root')?.examples.some((e) => e.includes('surface')), false);
});

test('proc status is debug, maps is integrity, and an ordinary open is ignored', () => {
  const s = summarizeDetection([
    { func: 'faccessat', text: 'dirfd=-100\tmode=0\tflags=0\tret=0\tlr=0x3\tpath=/proc/self/status' },
    { func: 'openat', text: '/proc/self/maps' },
    { func: 'openat', text: '/data/data/com.example.app/cache/x' },
    { func: 'read', text: 'PTRACE_TRACEME' },
  ], true);
  assert.equal(s.kinds.find((k) => k.kind === 'debug')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'integrity')?.count, 1);
  assert.equal(s.hits.length, 2);
});

test('property name and value pick the checklist row', () => {
  const s = summarizeDetection([
    { func: 'sysprop', text: 'ret=1\tlr=0x4\tname=ro.debuggable\tvalue=1' },
    { func: 'propread', text: 'lr=0x5\tname=ro.kernel.qemu\tvalue=1' },
    { func: 'sysprop', text: 'ret=2\tlr=0x6\tname=ro.build.tags\tvalue=test-keys' },
    { func: 'sysprop', text: 'ret=4\tlr=0x7\tname=persist.sys.locale\tvalue=zh-CN' },
  ], true);
  assert.equal(s.kinds.find((k) => k.kind === 'debug')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'emulator')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'root')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'prop')?.count, 1);
  assert.match(s.kinds.find((k) => k.kind === 'debug')?.examples[0] ?? '', /ro\.debuggable=1/);
});

test('only the named Java detection methods join the checklist', () => {
  const s = summarizeDetection([
    { func: 'JAVA_HOOK', text: JSON.stringify({ target: 'android.os.Debug.isDebuggerConnected()', arg: '', ret: 'true' }) },
    { func: 'JAVA_HOOK', text: JSON.stringify({ target: 'android.app.ApplicationPackageManager.getPackageInfo(java.lang.String,int)', arg: 'com.example.app,64' }) },
    { func: 'JAVA_HOOK', text: JSON.stringify({ target: 'java.io.File.exists()', arg: '/system/bin/su' }) },
    { func: 'JAVA_HOOK', text: JSON.stringify({ target: 'java.io.File.exists()', arg: '/data/data/com.example.app/cache' }) },
    { func: 'JAVA_HOOK', text: JSON.stringify({ target: 'javax.crypto.Cipher.doFinal()', arg: '' }) },
    { func: 'NATIVE_HOOK', text: 'x0=1' },
  ], true);
  assert.equal(s.kinds.find((k) => k.kind === 'debug')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'signature')?.count, 1);
  assert.equal(s.kinds.find((k) => k.kind === 'root')?.count, 1);
  assert.equal(s.hits.length, 3);
});

test('an empty store says whether the hooks were armed', () => {
  const off = summarizeDetection([], false);
  assert.match(off.reason, /^未开$/);
  assert.ok(off.unchecked.includes('反调试'));
  const on = summarizeDetection([], true);
  assert.match(on.reason, /^已开 · 暂无$/);
  // "no reply yet" must not collapse into the same empty string as "nothing to say": the old
  // fallthrough rendered an unknown state as nothing at all.
  const unknown = summarizeDetection([], null);
  assert.match(unknown.reason, /^状态未知$/);
  assert.match(on.caveat, /直接读手机型号/);
});

test('install reply: a positive system counter is armed, negatives are not', () => {
  assert.equal(sysHooksArmed(undefined), null);
  assert.equal(sysHooksArmed({ op: 'capture_stop', sys: { ptrace: 1 } }), false);
  assert.equal(sysHooksArmed({ op: 'capture_start', sys: { ptrace: -1, access: 0, prop: 0 } }), false);
  assert.equal(sysHooksArmed({ op: 'capture_start', sys: { ptrace: 2, faccessat: -1 } }), true);
});

test('Manager policy y=1 turns system detection on; absent or default stays off', () => {
  assert.equal(policySystemOn(undefined), false);
  assert.equal(policySystemOn(''), false);
  assert.equal(policySystemOn('default'), false);
  assert.equal(policySystemOn('d=1,h=1,s=1,a=1,t=1,e=1'), false);
  assert.equal(policySystemOn('d=1,h=1,s=1,a=1,t=1,e=1,y=0'), false);
  assert.equal(policySystemOn('d=1,h=1,s=1,a=1,t=1,e=1,y=1'), true);
  assert.equal(policySystemOn('y=1'), true);
});

test('module selection keeps this app libraries and drops libc', () => {
  const mods = [
    { name: 'liba.so', path: appPath('liba.so'), symbols: ['ptrace', 'malloc'] },
    { name: 'libc.so', path: '/apex/com.android.runtime/lib64/bionic/libc.so', symbols: ['ptrace', 'access', 'faccessat'] },
    { name: 'libpacked.so', path: appPath('libpacked.so'), symbols: [], packed: true },
    { name: 'libquiet.so', path: appPath('libquiet.so'), symbols: ['malloc'] },
  ];
  const plan = selectDetectModules(mods, pkg);
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.modules.map((m) => m.name), ['liba.so']);
  assert.equal(plan.sysModule, 'liba.so');
  assert.deepEqual(plan.skippedPacked, ['libpacked.so']);
});

test('more than eight app libraries is reported instead of being cut in silence', () => {
  const mods = Array.from({ length: 9 }, (_, i) => ({
    name: `lib${i}.so`, path: appPath(`lib${i}.so`), symbols: ['access'],
  }));
  const plan = selectDetectModules(mods, pkg);
  assert.equal(plan.truncated, true);
  assert.equal(plan.modules.length, 8);
  assert.equal(plan.sysModule.split(',').length, 8);
  assert.equal(selectDetectModules(mods, '').ok, false);
});

test('the java plan refuses an unknown family and leaves File.exists out unless asked', () => {
  const debug = detectJavaPlan(['debug']);
  assert.equal(debug.ok, true);
  assert.equal(debug.hooks.length, 2);
  assert.equal(debug.hooks.some((h) => h.method === 'exists'), false);
  assert.equal(detectJavaPlan(['file']).hooks[0].hot, true);
  assert.equal(detectJavaPlan(['nope']).ok, false);
  assert.equal(detectJavaPlan([]).ok, false);
});

test('detect_java installs only after confirm, and a refused call does not touch the agent', async () => {
  let sent = 0;
  const refused = await armDetectJava('sid', ['signature'], false, async () => { sent++; return {}; });
  assert.equal(refused.ok, false);
  assert.equal(sent, 0);
  const calls: any[] = [];
  const armed = await armDetectJava('sid', ['debug'], true, async (session, op, args) => {
    calls.push({ session, op, args });
    return { ok: true, hookId: calls.length };
  });
  assert.equal(armed.installed, 2);
  assert.equal(armed.ok, true);
  assert.equal(calls[0].op, 'java_hook');
  assert.equal(calls[0].args.stack, 'true');
  assert.equal(calls[0].args.className, 'android.os.Debug');
  assert.equal(calls[1].args.method, 'waitingForDebugger');
});

test('planning reads got entries of this app only', async () => {
  const asked: string[] = [];
  const plan = await planDetectModules('sid', pkg, async (_session, op, args) => {
    if (op === 'maps') return { regions: [
      { start: '1000', end: '2000', perms: 'r--p', offset: '0', dev: '0', inode: 1, path: appPath('liba.so') },
      { start: '3000', end: '4000', perms: 'r-xp', offset: '0', dev: '0', inode: 2, path: '/apex/com.android.runtime/lib64/bionic/libc.so' },
    ] };
    asked.push(String(args?.module ?? ''));
    if (args?.module === 'liba.so') return { ok: true, result: { packed: false, entries: [{ symbol: 'faccessat' }, { symbol: 'malloc' }] } };
    return { ok: true, result: { entries: [{ symbol: 'ptrace' }] } };
  });
  assert.deepEqual(asked, ['liba.so']);
  assert.equal(plan.sysModule, 'liba.so');
  assert.deepEqual(plan.modules[0].symbols, ['faccessat']);
});

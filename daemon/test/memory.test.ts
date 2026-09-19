import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveModule, ModuleAmbiguousError, classifyAddress, normalizeAddressForAgent } from '../src/memory.ts';

const mod = (name: string, path: string) => ({ name, path, base: '7000000000', end: '7000100000', size: 65536, segs: 1 });

test('module names resolve exactly, then uniquely, and ambiguity is an error', () => {
  const mods = [mod('libc.so', '/apex/com.android.runtime/lib64/bionic/libc.so'),
                mod('libc++.so', '/system/lib64/libc++.so'),
                mod('libcutils.so', '/system/lib64/libcutils.so')];
  assert.equal(resolveModule(mods, 'libcutils.so')?.path, '/system/lib64/libcutils.so');   // exact basename wins
  assert.equal(resolveModule(mods, '/system/lib64/libc++.so')?.name, 'libc++.so');          // exact path
  assert.throws(() => resolveModule(mods, 'libc'), (e: any) => e instanceof ModuleAmbiguousError
    && e.candidates.includes('libc.so') && e.candidates.includes('libc++.so') && e.candidates.includes('libcutils.so'));
  assert.equal(resolveModule(mods, 'libadhdetect.so'), undefined);                          // not loaded
  const single = [...mods, mod('libadhdetect.so', '/data/app/libadhdetect.so')];
  assert.equal(resolveModule(single, 'libadhdetect')?.name, 'libadhdetect.so');             // unique suffix
});

test('an address is classified against the live maps before anything is called', () => {
  const regions = [
    { start: '7000000000', end: '7000100000', perms: 'r-xp', offset: '0', dev: '00:00', inode: 0, path: '/system/lib64/libc.so' },
    { start: '7100000000', end: '7100001000', perms: 'rw-p', offset: '0', dev: '00:00', inode: 0, path: '[anon]' },
  ];
  assert.deepEqual(classifyAddress(regions, '0x7000001000'), { mapped: true, executable: true, path: '/system/lib64/libc.so' });
  assert.deepEqual(classifyAddress(regions, '0x7100000000'), { mapped: true, executable: false, path: '[anon]' });
  assert.equal(classifyAddress(regions, '0x6000000000').mapped, false);          // not mapped at all
  assert.equal(classifyAddress(regions, '0x7000100000').mapped, false);          // end is exclusive
  assert.equal(classifyAddress(regions, 'not-an-address').mapped, false);        // garbage never maps
});

test('the address handed to the agent is the one the guard checked', () => {
  // The agent parses with strtoull(...,0): a bare digit string is decimal there and octal with a
  // leading zero - "010000000000" used to be 10_000_000_000 for the guard and 0x40000000 for the
  // agent. The guard now hands over its own normalized form, so both sides mean the same address.
  assert.equal(normalizeAddressForAgent('0x7000001000'), '0x7000001000');
  assert.equal(normalizeAddressForAgent('  0x7000001000  '), '0x7000001000');   // whitespace dropped
  assert.equal(normalizeAddressForAgent('0X7000001000'), '0x7000001000');       // case normalized
  assert.equal(normalizeAddressForAgent('7f0000abc0'), '0x7f0000abc0');         // bare hex keeps a-f
  assert.equal(normalizeAddressForAgent('010000000000'), '0x2540be400');        // decimal, never octal
  assert.equal(normalizeAddressForAgent('7000001000'), '0x1a13b89e8');          // all-digit = decimal
  assert.throws(() => normalizeAddressForAgent('0x7000000000garbage'));
  assert.throws(() => normalizeAddressForAgent('-1'));
});

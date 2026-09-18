import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveModule, ModuleAmbiguousError } from '../src/memory.ts';

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

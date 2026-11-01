import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { pageModuleSymbols, resolveModule, fromArchive, moduleSymbols, SYMBOL_KINDS } from '../src/module_symbols.ts';
import { parseDynSymbols, type DynSymbol } from '../src/backtrace.ts';

// The fixture is the sandbox's own mock native library: a REAL ELF the build produces, so the paging
// test runs over the same bytes `parseDynSymbols` sees on a device instead of a hand-made table.
const here = dirname(fileURLToPath(import.meta.url));
const SANDBOX_SO = join(here, '..', '..', 'sandbox-native', 'build', 'libadhdetect.so');

const sym = (name: string, addr: bigint, size: number | bigint, kind: DynSymbol['kind'] = 'func'): DynSymbol =>
  ({ name, addr, size: BigInt(size), kind });

const TABLE: DynSymbol[] = [
  sym('EVP_EncryptInit_ex', 0x1000n, 40),
  sym('EVP_EncryptUpdate', 0x1100n, 60),
  sym('EVP_DecryptUpdate', 0x1200n, 55),
  sym('SSL_write', 0x2000n, 30),
  sym('crypto_table', 0x3000n, 8, 'object'),
  sym('crypto_lock', 0x3100n, 10),
  sym('no_size_fn', 0x4000n, 0),
];

// ---- filters ------------------------------------------------------------------------------------

test('no filter returns the whole table as one page, addresses module-relative', () => {
  const page = pageModuleSymbols(TABLE, {});
  assert.equal(page.total, 7);
  assert.equal(page.returned, 7);
  assert.equal(page.nextOffset, null);
  assert.equal(page.symbolsInModule, 7);
  assert.deepEqual(page.counts, { func: 6, object: 1 });
  assert.equal(page.kind, 'any');
  assert.equal(page.contains, null);
  assert.equal(page.symbols[0].name, 'EVP_EncryptInit_ex');
  assert.equal(page.symbols[0].offset, '0x1000');
  assert.equal(page.symbols[0].size, '0x28');
  assert.equal(page.symbols[0].sizeBytes, 40);
  assert.equal(page.symbols[0].kind, 'func');
});

test('kind=func drops data symbols and kind=object keeps only them', () => {
  const funcs = pageModuleSymbols(TABLE, { kind: 'func' });
  assert.deepEqual(funcs.symbols.map((s) => s.name), [
    'EVP_EncryptInit_ex', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate', 'SSL_write', 'crypto_lock', 'no_size_fn',
  ]);
  assert.equal(funcs.total, 6);
  // counts describe the MODULE, not the filtered page: the caller still learns what it filtered out.
  assert.deepEqual(funcs.counts, { func: 6, object: 1 });
  const objects = pageModuleSymbols(TABLE, { kind: 'object' });
  assert.deepEqual(objects.symbols.map((s) => s.name), ['crypto_table']);
  assert.equal(objects.total, 1);
});

test('contains is a case-sensitive substring filter, not a prefix or a glob', () => {
  const evp = pageModuleSymbols(TABLE, { contains: 'EVP_' });
  assert.equal(evp.total, 3);
  const low = pageModuleSymbols(TABLE, { contains: 'evp_' });
  assert.equal(low.total, 0);              // case matters; the caller must not assume a fold
  assert.equal(low.contains, 'evp_');
  const both = pageModuleSymbols(TABLE, { kind: 'func', contains: 'crypto' });
  assert.deepEqual(both.symbols.map((s) => s.name), ['crypto_lock']);
});

test('an unknown or missing kind falls back to any instead of silently returning nothing', () => {
  for (const kind of [undefined, '', 'FUNC', 'symbol', null]) {
    const page = pageModuleSymbols(TABLE, { kind: kind as any });
    assert.equal(page.kind, 'any', `kind=${String(kind)} should fall back to any`);
    assert.equal(page.total, 7);
  }
  assert.deepEqual([...SYMBOL_KINDS], ['any', 'func', 'object']);
});

// ---- paging -------------------------------------------------------------------------------------

test('paging walks the filtered set exactly once, with nextOffset null at the end', () => {
  const seen: string[] = [];
  let offset: number | null = 0;
  let pages = 0;
  while (offset != null) {
    const page = pageModuleSymbols(TABLE, { limit: 3, offset });
    assert.ok(page.returned <= 3);
    assert.equal(page.total, 7);           // total is stable across pages
    seen.push(...page.symbols.map((s) => s.name));
    offset = page.nextOffset;
    pages++;
    assert.ok(pages < 10, 'paging did not terminate');
  }
  assert.equal(pages, 3);                  // 3 + 3 + 1
  assert.deepEqual(seen, TABLE.map((s) => s.name));
});

test('an offset past the end is an empty page, not a wrap and not an error', () => {
  const page = pageModuleSymbols(TABLE, { limit: 5, offset: 99 });
  assert.equal(page.returned, 0);
  assert.equal(page.symbols.length, 0);
  assert.equal(page.nextOffset, null);
  assert.equal(page.total, 7);
  assert.equal(page.offset, 99);
});

test('limit and offset are clamped so no call can dump the whole table unpaged', () => {
  const huge = pageModuleSymbols(TABLE, { limit: 1e9, offset: -5 });
  assert.equal(huge.limit, 5000);
  assert.equal(huge.offset, 0);
  const zero = pageModuleSymbols(TABLE, { limit: 0 });
  assert.equal(zero.limit, 1);
  assert.equal(zero.returned, 1);
  // NaN/strings must not become a NaN cursor that slices from 0 forever.
  const nan = pageModuleSymbols(TABLE, { limit: Number.NaN, offset: Number.NaN });
  assert.equal(nan.limit, 200);
  assert.equal(nan.offset, 0);
  assert.equal(pageModuleSymbols(TABLE, { limit: '3' as any }).limit, 3);
});

test('an empty table reports zeros and a null cursor instead of throwing', () => {
  const page = pageModuleSymbols([], {});
  assert.deepEqual(
    { total: page.total, returned: page.returned, nextOffset: page.nextOffset, inModule: page.symbolsInModule },
    { total: 0, returned: 0, nextOffset: null, inModule: 0 },
  );
  const undefinedTable = pageModuleSymbols(undefined as any, {});
  assert.equal(undefinedTable.total, 0);
});

// ---- module resolution --------------------------------------------------------------------------

test('resolveModule prefers exact name, then exact path, then path tail', () => {
  const mods = [
    { name: 'libfoo.so', path: '/data/app/~~x/com.a/lib/arm64/libfoo.so' },
    { name: 'libbar.so', path: '/system/lib64/libbar.so' },
    { name: 'libfoolong.so', path: '/system/lib64/libfoolong.so' },
  ];
  assert.equal(resolveModule(mods, 'libfoo.so')?.path, '/data/app/~~x/com.a/lib/arm64/libfoo.so');
  assert.equal(resolveModule(mods, '/system/lib64/libbar.so')?.name, 'libbar.so');
  assert.equal(resolveModule(mods, 'libbarextra.so'), null);
  // A tail match is how an operator names a library it only half-remembers.
  const tailOnly = [{ name: 'renamed', path: '/data/local/tmp/libzzz.so' }];
  assert.equal(resolveModule(tailOnly, 'libzzz.so')?.path, '/data/local/tmp/libzzz.so');
});

test('an ambiguous selector is refused with the candidates, never silently narrowed', () => {
  const mods = [
    { name: 'libcrypto_a.so', path: '/data/app/x/lib/arm64/libcrypto_a.so' },
    { name: 'libcrypto_b.so', path: '/data/app/x/lib/arm64/libcrypto_b.so' },
  ];
  assert.throws(() => resolveModule(mods, 'libcrypto'), /ambiguous \(2 matches: libcrypto_a\.so, libcrypto_b\.so\)/);
  // ...but the full path still resolves, so the operator has a way out of the ambiguity.
  assert.equal(resolveModule(mods, '/data/app/x/lib/arm64/libcrypto_b.so')?.name, 'libcrypto_b.so');
  assert.equal(resolveModule(mods, ''), null);
  assert.equal(resolveModule(mods, 'libnope.so'), null);
});

test('fromArchive is what tells a mapped-from-APK library apart from a real .so', () => {
  assert.equal(fromArchive('/data/app/~~x/com.a/base.apk'), true);
  assert.equal(fromArchive('/system/framework/framework.jar'), true);
  assert.equal(fromArchive('/apex/com.android.art/javalib/core-oj.jar'), true);
  assert.equal(fromArchive('/data/app/~~x/com.a/lib/arm64/libfoo.so'), false);
  assert.equal(fromArchive('/data/local/tmp/a.APK'), true);      // case-insensitive on purpose
});

// ---- against a real ELF -------------------------------------------------------------------------

test('a real .so pages through the same filters PT_DYNAMIC reports', (t) => {
  if (!existsSync(SANDBOX_SO)) { t.skip(`fixture not built: ${SANDBOX_SO} (run tools/build_detect.sh)`); return; }
  const syms = parseDynSymbols(readFileSync(SANDBOX_SO));
  assert.ok(syms.length > 20, `expected the sandbox exports, saw ${syms.length}`);
  const all = pageModuleSymbols(syms, { limit: 10 });
  assert.equal(all.total, syms.length);
  assert.equal(all.returned, 10);
  assert.equal(all.nextOffset, 10);
  assert.ok(all.counts.func > 0 && all.counts.func + all.counts.object === all.symbolsInModule);

  // A known export must appear on ITS page with the offset a hook would add to the module base.
  const idx = syms.findIndex((s) => s.name === 'adh_bt_target');
  assert.ok(idx >= 0, 'adh_bt_target missing from the parsed dynamic symbols');
  const target = syms[idx];
  const pageNo = Math.floor(idx / 10);
  const page = pageModuleSymbols(syms, { limit: 10, offset: pageNo * 10 });
  const row = page.symbols.find((s) => s.name === 'adh_bt_target');
  assert.ok(row, 'adh_bt_target was not on the page its index implies');
  assert.equal(row.offset, `0x${target.addr.toString(16)}`);
  assert.equal(row.kind, 'func');

  // funcs-only must be a strict subset, and paging it must still terminate.
  const funcsOnly = pageModuleSymbols(syms, { kind: 'func', limit: 7 });
  assert.ok(funcsOnly.total <= syms.length);
  assert.ok(funcsOnly.symbols.every((s) => s.kind === 'func'));
  let cursor: number | null = 0, walked = 0, guard = 0;
  while (cursor != null && guard++ < 500) {
    const p = pageModuleSymbols(syms, { kind: 'func', limit: 7, offset: cursor });
    walked += p.returned;
    cursor = p.nextOffset;
  }
  assert.equal(walked, funcsOnly.total, 'paging lost or duplicated rows');
});

// ---- moduleSymbols: the live shell, with the dump chain injected --------------------------------
//
// The archive short-circuit and the "stripped library" branch cannot be produced on a live target on
// demand, so they are driven here through injected deps. What is asserted is the behaviour that
// matters: an archive-mapped module must NOT be dumped at all, and it must not report symbols.

const tableOf = (modules: any[]) => async () => ({ regions: [], modules, inRegion: () => undefined, moduleOf: () => null }) as any;
const spy = () => { const calls: string[] = []; return { calls, fn: async (session: string, base: string) => { calls.push(base); return Buffer.alloc(0); } }; };

test('an archive-mapped module is reported symbol-less WITHOUT being dumped', async () => {
  const dump = spy();
  const result = await moduleSymbols('s_test', { module: 'base.apk' }, {
    loadModuleTable: tableOf([
      { name: 'base.apk', path: '/data/app/~~x/com.a/base.apk', base: '7f00000000', end: '7f00100000', size: 1, segs: 3 },
    ]) as any,
    reconstructSo: dump.fn as any,
    parseDynSymbols: ((buf: Buffer) => { assert.fail('parseDynSymbols must not run for an archive-mapped module'); return []; }) as any,
  });
  assert.deepEqual(dump.calls, []);                 // the whole point: no dump of a zip slice
  assert.equal(result.symbolSource, 'archive-mapped');
  assert.equal(result.module, 'base.apk');
  assert.equal(result.total, 0);
  assert.equal(result.returned, 0);
  assert.equal(result.nextOffset, null);
  assert.equal(result.symbolsInModule, 0);
  assert.equal(result.base, '0x7f00000000');
  assert.match(result.notes.join(' '), /archive/);
});

test('a real .so path IS dumped, and its rows carry base + offset', async () => {
  const dump = spy();
  const result = await moduleSymbols('s_test', { module: 'libfoo.so', limit: 1 }, {
    loadModuleTable: tableOf([
      { name: 'libfoo.so', path: '/data/app/~~x/com.a/lib/arm64/libfoo.so', base: '7f10000000', end: '7f10100000', size: 1, segs: 2 },
    ]) as any,
    reconstructSo: dump.fn as any,
    parseDynSymbols: (() => [sym('alpha', 0x100n, 8), sym('beta', 0x200n, 4, 'object'), sym('gamma', 0x300n, 0)]) as any,
  });
  assert.deepEqual(dump.calls, ['7f10000000']);     // dumped once, at the module base
  assert.equal(result.symbolSource, 'dynsym');
  assert.equal(result.total, 3);
  assert.equal(result.returned, 1);
  assert.equal(result.nextOffset, 1);               // paging is offered, not implied
  assert.deepEqual(result.counts, { func: 2, object: 1 });
  assert.equal(result.symbols[0].offset, '0x100');
  assert.match(result.notes.join(' '), /offset:1/);
});

test('a stripped library and a no-match filter each explain themselves', async () => {
  const empty = await moduleSymbols('s_test', { module: 'libs.so' }, {
    loadModuleTable: tableOf([{ name: 'libs.so', path: '/d/libs.so', base: '1000', end: '2000', size: 1, segs: 1 }]) as any,
    reconstructSo: (async () => Buffer.alloc(0)) as any,
    parseDynSymbols: (() => []) as any,
  });
  assert.equal(empty.symbolSource, 'dynsym');
  assert.equal(empty.total, 0);
  assert.match(empty.notes.join(' '), /stripped|PT_DYNAMIC/);

  const noMatch = await moduleSymbols('s_test', { module: 'libs.so', contains: 'zzz' }, {
    loadModuleTable: tableOf([{ name: 'libs.so', path: '/d/libs.so', base: '1000', end: '2000', size: 1, segs: 1 }]) as any,
    reconstructSo: (async () => Buffer.alloc(0)) as any,
    parseDynSymbols: (() => [sym('alpha', 0x10n, 4)]) as any,
  });
  assert.equal(noMatch.total, 0);
  assert.equal(noMatch.symbolsInModule, 1);         // still says how many the module has
  assert.match(noMatch.notes.join(' '), /matched kind=any contains="zzz"/);
});

test('an unknown or ambiguous module fails with an actionable message and dumps nothing', async () => {
  const dump = spy();
  const deps = {
    loadModuleTable: tableOf([
      { name: 'libcrypto_a.so', path: '/d/libcrypto_a.so', base: '1000', end: '2000', size: 1, segs: 1 },
      { name: 'libcrypto_b.so', path: '/d/libcrypto_b.so', base: '3000', end: '4000', size: 1, segs: 1 },
    ]) as any,
    reconstructSo: dump.fn as any,
    parseDynSymbols: (() => []) as any,
  };
  await assert.rejects(moduleSymbols('s_test', { module: 'libcrypto' }, deps as any), /ambiguous \(2 matches: libcrypto_a\.so, libcrypto_b\.so\)/);
  await assert.rejects(moduleSymbols('s_test', { module: 'libnope.so' }, deps as any), /module not found in this process: libnope\.so/);
  await assert.rejects(moduleSymbols('s_test', { module: '   ' }, deps as any), /need module/);
  assert.deepEqual(dump.calls, [], 'a refused selector must not dump anything');
});

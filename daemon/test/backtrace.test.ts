import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseDynSymbols, symbolize } from '../src/backtrace.ts';

const here = dirname(fileURLToPath(import.meta.url));
const SANDBOX_SO = join(here, '..', '..', 'sandbox-native', 'build', 'libadhdetect.so');

test('symbolize prefers an exact (size-covered) hit', () => {
  const syms = [{ addr: 0x1000n, size: 0x20n, name: 'foo', kind: 'func' as const },
                { addr: 0x2000n, size: 0n, name: 'bar', kind: 'func' as const }];
  const a = symbolize(0x1004n, syms);
  assert.equal(a.symbol, 'foo');
  assert.equal(a.exact, true);
  assert.equal(a.symbolOffset, '0x4');
  // outside the sized symbol -> nearest preceding, explicitly not exact
  const b = symbolize(0x1024n, syms);
  assert.equal(b.symbol, 'foo');
  assert.equal(b.exact, false);
  // before the first symbol -> no name at all
  assert.equal(symbolize(0x800n, syms).symbol, null);
});

test('parseDynSymbols reads a real .so through PT_DYNAMIC (no section headers needed)', (t) => {
  if (!existsSync(SANDBOX_SO)) { t.skip(`fixture not built: ${SANDBOX_SO} (run tools/build_detect.sh)`); return; }
  const buf = readFileSync(SANDBOX_SO);
  const syms = parseDynSymbols(buf);
  assert.ok(syms.length > 20, `expected the sandbox exports, saw ${syms.length}`);
  const target = syms.find((s) => s.name === 'adh_bt_target');
  assert.ok(target, 'adh_bt_target missing from the parsed dynamic symbols');
  assert.equal(target.kind, 'func');
  assert.equal(target.size, 20n);
  const inside = symbolize(target.addr + 4n, syms);
  assert.equal(inside.symbol, 'adh_bt_target');
  assert.equal(inside.exact, true);
});

test('parseDynSymbols returns nothing for a non-ELF buffer instead of throwing', () => {
  assert.deepEqual(parseDynSymbols(Buffer.from('not an elf at all, definitely not')), []);
});

test('parseDynSymbols tolerates a truncated header', () => {
  const buf = Buffer.alloc(64);
  buf.writeUInt32LE(0x464c457f, 0);
  buf[4] = 2;
  buf.writeBigUInt64LE(0x100000n, 32);      // phoff far past the end
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(4, 56);
  assert.deepEqual(parseDynSymbols(buf), []);
});
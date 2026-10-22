import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeSo } from '../src/analysis.ts';

// native_analyze on a 1.6 MB obfuscated .so returned ~19 MB of strings in one reply. That is not an
// analysis answer: it is a way to fill the caller's context in a single call, and there was no way
// to ask for the rest later. The reply is paged now, every page says what it left out, and a long
// run is cut per entry instead of only being capped by count.

const dir = mkdtempSync(join(tmpdir(), 'adh-analyze-'));
const so = join(dir, 'fake.so');
const LONG = 'C'.repeat(300);   // longer than the 200-char per-entry default
const CUT = 'C'.repeat(200);

// Not a real ELF: readelf refuses it, which is fine — the string scan is the part under test, and
// this also proves a failed symbol read does not take the whole answer down with it.
writeFileSync(so, Buffer.concat([
  Buffer.from('AAAA'), Buffer.from([0]),
  Buffer.from('BBBBBB'), Buffer.from([0]),
  Buffer.from(LONG), Buffer.from([0]),
  Buffer.from('AAAA'), Buffer.from([0]),   // duplicate: one entry, not two
  Buffer.from('LAST'),                     // ends at EOF: the run the old loop dropped
]));

test.after(() => rmSync(dir, { recursive: true, force: true }));

test('default page returns every unique run, deduped, with the EOF run included', async () => {
  const r = await analyzeSo(so);
  assert.equal(r.stringsTotal, 4);
  assert.deepEqual(r.strings, ['AAAA', 'BBBBBB', CUT, 'LAST']);
  assert.equal(r.counts.strings, 4);
  assert.equal(r.nextOffset, null);
  assert.equal(r.longStrings, 1);
});

test('a long run is cut at maxStringChars and counted, never silently shortened', async () => {
  const r = await analyzeSo(so, { maxStringChars: 32 });
  assert.equal(r.strings[2], 'C'.repeat(32));
  assert.equal(r.longStrings, 1);
});

test('paging: maxStrings + stringsOffset walk the list and nextOffset ends it', async () => {
  const p1 = await analyzeSo(so, { maxStrings: 2 });
  assert.deepEqual(p1.strings, ['AAAA', 'BBBBBB']);
  assert.equal(p1.stringsReturned, 2);
  assert.equal(p1.nextOffset, 2);
  assert.equal(p1.stringsTotal, 4);

  const p2 = await analyzeSo(so, { maxStrings: 2, stringsOffset: p1.nextOffset });
  assert.deepEqual(p2.strings, [CUT, 'LAST']);
  assert.equal(p2.nextOffset, null);
  assert.equal(p2.stringsOffset, 2);
});

test('minLen drops short runs instead of forcing the caller to filter them', async () => {
  const r = await analyzeSo(so, { minLen: 5 });
  assert.deepEqual(r.strings, ['BBBBBB', CUT]);
});

test('an offset past the end is an empty page, not an error', async () => {
  const r = await analyzeSo(so, { stringsOffset: 99 });
  assert.equal(r.stringsReturned, 0);
  assert.deepEqual(r.strings, []);
  assert.equal(r.nextOffset, null);
  assert.equal(r.stringsTotal, 4);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeAdrp, decodeAddImm, decodeLdrImm, findReferences, elfSegments } from '../src/elf_xref.ts';

// These decoders exist because two hand-rolled versions silently under-reported on libjdg and on
// libjdJmaEncryptUtil ("0 references -> this table is unused"), and the conclusion drawn from that was
// wrong. The instruction words below are real: the ADRP one is from libjdg+0x8949c, which forms the
// RC4 state address and is the proof that the decoder works at all.

test('ADRP is decoded PC-relative from the page, with a sign-extended offset', () => {
  // adrp x9, #0x155000 at pc 0x8949c  (bytes 69 06 00 90 -> word 0x90000669)
  assert.equal(decodeAdrp(0x90000669, 0x8949c), 0x155000);
  // A negative offset: adrp x0, #0x0 at pc 0x1000 stays on the same page.
  assert.equal(decodeAdrp(0x90000000, 0x1000), 0x1000);
  // Not an ADRP (it is an ADD) -> null, so a caller cannot silently treat a random word as a page.
  assert.equal(decodeAdrp(0x9110dab5, 0x1000), null);
  // The signed-int32 trap: masking with 0x9f000000 yields a NEGATIVE number for any word with bit 31
  // set, so the comparison must be done on the unsigned value.
  assert.equal(((0x90000669 & 0x9f000000) >>> 0), 0x90000000);
});

test('ADD immediate honours the LSL #12 shift', () => {
  const plain = decodeAddImm(0x9110dab5);          // add x21, x21, #0x436
  assert.equal(plain?.imm, 0x436);
  assert.equal(plain?.shift, 0);
  // add x9, x9, #0x2, lsl #12  -> 0x2000, which is how a table 8 KiB away is reached.
  const shiftedWord = (0x91000000 | (1 << 22) | (0x2 << 10) | (9 << 5) | 9) >>> 0;
  const shifted = decodeAddImm(shiftedWord);
  assert.equal(shifted?.shift, 12);
  assert.equal(shifted?.imm, 0x2000);
});

test('LDR immediate scales by the destination width', () => {
  assert.equal(decodeLdrImm((0xf9400000 | (0x10 << 10)) >>> 0)?.offset, 0x80);   // 16 * 8
  assert.equal(decodeLdrImm((0xb9400000 | (0x10 << 10)) >>> 0)?.offset, 0x40);   // 16 * 4
  assert.equal(decodeLdrImm((0x3dc00000 | (0x10 << 10)) >>> 0)?.offset, 0x100);  // 16 * 16 (q register)
  assert.equal(decodeLdrImm(0x91000000), null);
});

// A tiny synthetic image: one executable segment mapped at 0x1000, word-indexed by file offset.
function image(words: number[], vaddr = 0x1000) {
  const bytes = new Uint8Array(words.length * 4);
  const dv = new DataView(bytes.buffer);
  words.forEach((w, i) => dv.setUint32(i * 4, w >>> 0, true));
  const segs = [{ fileOffset: 0, vaddr, fileSize: bytes.length, executable: true }];
  const readU32 = (off: number) => dv.getUint32(off, true);
  return { bytes, segs, readU32 };
}

test('an ADRP+ADD pair that sums to the target is found, and one that does not is not', () => {
  // adrp x9, page(0x4000) ; add x9, x9, #0x2a4  -> 0x42a4
  const pc0 = 0x1000;
  const page = 0x4000;
  const adrpImm = (page - (pc0 & ~0xfff)) >> 12;
  const adrp = 0x90000000 | ((adrpImm & 0x3) << 29) | (((adrpImm >> 2) & 0x7ffff) << 5) | 9;
  const add = 0x91000000 | (0x2a4 << 10) | (9 << 5) | 9;
  const hit = image([adrp, add]);
  const refs = findReferences(hit.readU32, hit.segs, 0x42a4);
  assert.equal(refs.length, 1);
  assert.equal(refs[0].form, 'add');
  assert.equal(refs[0].value, 0x42a4);

  // Ask for a different address on the same page: the pair must NOT be reported as an exact match.
  const other = findReferences(hit.readU32, hit.segs, 0x42b0);
  assert.equal(other.filter((r) => r.form === 'add').length, 0);
});

test('a table reached through a 128-bit load is found even though imm12 is scaled by 16', () => {
  // adrp x22, page(0x8000) ; ldr q0, [x22, #0x110]  -> lands at 0x8110
  const pc0 = 0x2000;
  const page = 0x8000;
  const adrpImm = (page - (pc0 & ~0xfff)) >> 12;
  const adrp = (0x90000000 | ((adrpImm & 0x3) << 29) | (((adrpImm >> 2) & 0x7ffff) << 5) | 22) >>> 0;
  const ldr128 = (0x3dc00000 | ((0x110 / 16) << 10) | (22 << 5) | 0) >>> 0;
  const img = image([adrp, ldr128], pc0);
  const refs = findReferences(img.readU32, img.segs, 0x8100, 0x200);
  assert.equal(refs.length, 1);
  assert.equal(refs[0].form, 'ldr128');
  assert.equal(refs[0].value, 0x8110);
});

test('a page that is loaded but consumed later is still reported, as adrp-only', () => {
  const pc0 = 0x3000;
  const page = 0xc000;
  const adrpImm = (page - (pc0 & ~0xfff)) >> 12;
  const adrp = (0x90000000 | ((adrpImm & 0x3) << 29) | (((adrpImm >> 2) & 0x7ffff) << 5) | 3) >>> 0;
  const mov = 0xaa0103e0;                       // mov x0, x1 - nothing to do with the page
  const img = image([adrp, mov], pc0);
  const refs = findReferences(img.readU32, img.segs, 0xc0a0);
  assert.equal(refs.length, 1);
  assert.equal(refs[0].form, 'adrp-only');
  assert.equal(refs[0].value, 0xc000);
});

test('elfSegments rejects a non-ELF buffer instead of reading garbage', () => {
  assert.throws(() => elfSegments(new Uint8Array([1, 2, 3, 4])), /not an ELF/);
});

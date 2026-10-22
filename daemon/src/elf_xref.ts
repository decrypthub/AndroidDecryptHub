// "Who references this address?" for an ELF shared object, with the encodings a hand-rolled matcher
// misses. Written because the ad-hoc versions used during the jdgs work silently under-reported:
//
//   - ADD (immediate) with shift = LSL #12: the byte offset lives in imm12 * 0x1000, not imm12.
//   - LDR with a 32-bit / 128-bit destination scales the imm12 by 4 / 16, not 8.
//   - A table is often reached as `adrp page; add base, page, #off` where off is NOT the table start
//     (e.g. add #0xf00 then `ldr [x, #0x110]`), so an exact "lo12 == table offset" matcher finds
//     nothing and the caller concludes "no code references this table" - which is a wrong conclusion,
//     not a missing feature.
//
// The decoders are exported so they can be tested against real instruction words instead of against
// the same assumption that produced them.

export interface ElfSegment {
  /** File offset of the segment. */
  fileOffset: number;
  /** Virtual address the segment is mapped at. */
  vaddr: number;
  /** Bytes present in the file. */
  fileSize: number;
  executable: boolean;
}

export interface ElfReference {
  /** Virtual address of the referencing instruction. */
  site: number;
  /** How the address was formed: exact add, shifted add, or a load from the page. */
  form: 'add' | 'add-lsl12' | 'ldr' | 'ldr32' | 'ldr128' | 'adrp-only';
  /** The address the instruction pair actually materializes. */
  value: number;
}

/** ADRP: `1 op immlo[2] 10000 immhi[19] Rd[5]`. Returns the target page or null. */
export function decodeAdrp(word: number, pc: number): number | null {
  if (((word & 0x9f000000) >>> 0) !== 0x90000000) return null;
  const immlo = (word >>> 29) & 0x3;
  const immhi = (word >>> 5) & 0x7ffff;
  const imm = ((immhi << 2) | immlo) << 12;
  // Sign-extend the 33-bit byte offset (21 bits << 12).
  const signed = imm & 0x100000000 ? imm - 0x200000000 : imm;
  return ((pc & ~0xfff) + signed) >>> 0;
}

/** ADD (immediate), 32/64-bit. Returns { rd, rn, value, shift } or null. */
export function decodeAddImm(word: number): { rd: number; rn: number; imm: number; shift: number; is64: boolean } | null {
  const is64 = ((word & 0xff800000) >>> 0) === 0x91000000;
  const is32 = ((word & 0xff800000) >>> 0) === 0x11000000;
  if (!is64 && !is32) return null;
  const rd = word & 0x1f;
  const rn = (word >>> 5) & 0x1f;
  const imm12 = (word >>> 10) & 0xfff;
  const shift = (word >>> 22) & 0x1 ? 12 : 0;   // sh bit
  return { rd, rn, imm: imm12 << shift, shift, is64 };
}

/** LDR (immediate, unsigned offset). Returns { rt, rn, offset, bytes } or null. */
export function decodeLdrImm(word: number): { rt: number; rn: number; offset: number; bytes: number } | null {
  // 64-bit integer 1111 1001 01, 32-bit integer 1011 1001 01, 128-bit SIMD 0011 1101 01.
  const is64 = ((word & 0xffc00000) >>> 0) === 0xf9400000;
  const is32 = ((word & 0xffc00000) >>> 0) === 0xb9400000;
  const is128 = ((word & 0xffc00000) >>> 0) === 0x3dc00000;
  if (!is64 && !is32 && !is128) return null;
  const rt = word & 0x1f;
  const rn = (word >>> 5) & 0x1f;
  const imm12 = (word >>> 10) & 0xfff;
  const bytes = is64 ? 8 : is32 ? 4 : 16;
  return { rt, rn, offset: imm12 * bytes, bytes };
}

/**
 * Find instructions that materialize `targetVa`.
 *
 * Two passes over each executable segment: an ADRP+ADD pair that sums exactly to the target (the
 * textbook form), and an ADRP whose page matches followed by a load that lands in the same 4 KiB page
 * (the "base + offset" form). The second pass reports the page-relative landing address, so a caller
 * can tell "this is the table" from "this is near the table" instead of getting no answer at all.
 */
export function findReferences(
  readU32: (offset: number) => number,
  segments: readonly ElfSegment[],
  targetVa: number,
  windowBytes = 512,
  scanAhead = 4,
): ElfReference[] {
  const out: ElfReference[] = [];
  const page = targetVa & ~0xfff;
  for (const seg of segments) {
    if (!seg.executable) continue;
    const end = seg.fileOffset + seg.fileSize;
    for (let off = seg.fileOffset; off + 8 <= end; off += 4) {
      const word = readU32(off);
      const pc = (seg.vaddr + (off - seg.fileOffset)) >>> 0;
      const adrpPage = decodeAdrp(word, pc);
      if (adrpPage === null || adrpPage !== page) continue;
      const adrpRd = word & 0x1f;
      // Look ahead a few instructions, not just one: obfuscated code often interleaves unrelated work
      // between `adrp page` and the `add`/`ldr` that consumes it (measured on a VMP-flattened module,
      // where an immediate-next-insn matcher reported every reference as bare ADRP).
      let consumed: ElfReference | null = null;
      for (let step = 1; step <= scanAhead; step++) {
        const off2 = off + step * 4;
        if (off2 + 4 > end) break;
        const w2 = readU32(off2);
        const add = decodeAddImm(w2);
        if (add && add.rn === adrpRd) {
          const value = (adrpPage + add.imm) >>> 0;
          if (value === targetVa) {
            consumed = { site: pc, form: add.shift ? 'add-lsl12' : 'add', value };
            break;
          }
          // A different offset from the same page: not the target, but the page IS in use here.
          continue;
        }
        const ldr = decodeLdrImm(w2);
        if (ldr && ldr.rn === adrpRd) {
          const value = (adrpPage + ldr.offset) >>> 0;
          if (value >= targetVa && value < targetVa + windowBytes) {
            const form = ldr.bytes === 8 ? 'ldr' : ldr.bytes === 4 ? 'ldr32' : 'ldr128';
            consumed = { site: pc, form, value };
          }
          break;
        }
      }
      // The page is loaded but nothing in the lookahead consumes it for this target: still worth
      // reporting, because "the page is referenced from here" is what a caller needs to look at.
      out.push(consumed ?? { site: pc, form: 'adrp-only', value: adrpPage });
    }
  }
  return out;
}

/** Parse ELF64 little-endian program headers into the segment list the scanners need. */
export function elfSegments(buf: Uint8Array): ElfSegment[] {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint32(0, false) !== 0x7f454c46) throw new Error('not an ELF file');
  if (buf[4] !== 2 || buf[5] !== 1) throw new Error('only ELF64 little-endian is supported');
  const phoff = Number(dv.getBigUint64(0x20, true));
  const phentsize = dv.getUint16(0x36, true);
  const phnum = dv.getUint16(0x38, true);
  const segs: ElfSegment[] = [];
  for (let i = 0; i < phnum; i++) {
    const off = phoff + i * phentsize;
    if (dv.getUint32(off, true) !== 1) continue;          // PT_LOAD
    const flags = dv.getUint32(off + 4, true);
    segs.push({
      fileOffset: Number(dv.getBigUint64(off + 8, true)),
      vaddr: Number(dv.getBigUint64(off + 16, true)),
      fileSize: Number(dv.getBigUint64(off + 32, true)),
      executable: (flags & 1) !== 0,
    });
  }
  return segs;
}

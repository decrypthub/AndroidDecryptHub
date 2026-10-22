// List every ADRP in a .so that materializes one page, and disassemble the four instructions after
// each with Capstone. The strict ADRP+ADD matcher in elf_xref.mjs finds the textbook idiom only;
// a table reached as `adrp x9, page` + `ldr q0, [x9, #off]` (or through a pointer table) needs the
// raw window to read.
import { readFileSync } from 'node:fs';
import { disasmBytes } from './src/capstone.ts';

const file = process.argv[2];
const pageArg = Number.parseInt(process.argv[3], 16);
const buf = readFileSync(file);

const ePhOff = Number(buf.readBigUInt64LE(0x20));
const ePhentSize = buf.readUInt16LE(0x36);
const ePhNum = buf.readUInt16LE(0x38);
const segs = [];
for (let i = 0; i < ePhNum; i++) {
  const off = ePhOff + i * ePhentSize;
  if (buf.readUInt32LE(off) !== 1) continue;
  segs.push({
    pOffset: Number(buf.readBigUInt64LE(off + 8)),
    pVaddr: Number(buf.readBigUInt64LE(off + 16)),
    pFilesz: Number(buf.readBigUInt64LE(off + 32)),
    exec: (buf.readUInt32LE(off + 4) & 1) !== 0,
  });
}
const sext = (v, bits) => ((v & (1 << (bits - 1))) ? v - (1 << bits) : v);

const found = [];
for (const seg of segs.filter((s) => s.exec)) {
  const end = Math.min(buf.length, seg.pOffset + seg.pFilesz);
  for (let off = seg.pOffset; off + 4 <= end; off += 4) {
    const w = buf.readUInt32LE(off);
    if (((w & 0x9f000000) >>> 0) !== 0x90000000) continue;
    const immlo = (w >>> 29) & 0x3;
    const immhi = (w >>> 5) & 0x7ffff;
    const pc = seg.pVaddr + (off - seg.pOffset);
    const target = (pc & ~0xfff) + (sext((immhi << 2) | immlo, 21) << 12);
    if (target === pageArg) found.push({ off, pc, fileOff: off });
  }
}
console.log(`ADRP -> 0x${pageArg.toString(16)}: ${found.length} site(s)`);
for (const site of found.slice(0, 12)) {
  const win = buf.subarray(site.fileOff, Math.min(buf.length, site.fileOff + 4 * 6));
  const insns = await disasmBytes(new Uint8Array(win), BigInt(site.pc), 6);
  console.log(`  +0x${site.pc.toString(16)} (file 0x${site.fileOff.toString(16)}):`);
  for (const i of insns) console.log(`      ${i.addr}  ${i.text}`);
}

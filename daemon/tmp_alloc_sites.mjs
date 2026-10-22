// Find `mov w0, #<n>` immediately followed by a call, to locate the *hex formatter* siblings of a
// digest: a 16-byte digest needs a 33-byte buffer (32 hex + NUL) and a 32-byte digest needs 65. The
// allocation size is the cheapest fingerprint of which digest a formatter formats.
import { readFileSync } from 'node:fs';
import { disasmBytes } from './src/capstone.ts';

const file = process.argv[2];
// Number('0x41') is 65; Number.parseInt('0x41', 16) is ALSO 65 - but Number.parseInt on a string
// like '65' with radix 16 gives 101, and that silent mismatch is exactly how the first run of this
// searched for the wrong immediates and reported "0 sites" with a straight face.
const want = (process.argv[3] ?? '0x41,0x21').split(',').map((x) => Number(x));
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
// MOVZ Wd, #imm16, LSL #0 : sf=0 opc=10 100101 hw=00 imm16 Rd  -> 0x52800000 | (imm16 << 5) | Rd
for (const n of want) {
  const word = (0x52800000 | ((n & 0xffff) << 5) | 0) >>> 0;
  const hits = [];
  for (const seg of segs.filter((s) => s.exec)) {
    const end = Math.min(buf.length, seg.pOffset + seg.pFilesz);
    for (let off = seg.pOffset; off + 8 <= end; off += 4) {
      if (buf.readUInt32LE(off) !== word) continue;
      const pc = seg.pVaddr + (off - seg.pOffset);
      hits.push({ off, pc });
    }
  }
  console.log(`mov w0, #0x${n.toString(16)} (word 0x${word.toString(16)}): ${hits.length} site(s)`);
  for (const h of hits.slice(0, 8)) {
    const win = buf.subarray(h.off, Math.min(buf.length, h.off + 4 * 4));
    const insns = await disasmBytes(new Uint8Array(win), BigInt(h.pc), 4);
    console.log(`  +0x${h.pc.toString(16)}: ${insns.map((i) => i.text).join(' | ')}`);
  }
}

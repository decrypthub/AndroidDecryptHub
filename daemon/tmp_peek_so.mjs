// Disassemble a window of a .so by module offset, using the same Capstone build the daemon uses.
// Usage: node peek_so.mjs <file.so> <offset-hex> [count]
import { readFileSync } from 'node:fs';
import { disasmBytes } from './src/capstone.ts';

const file = process.argv[2];
const start = Number.parseInt(process.argv[3], 16);
const count = Number.parseInt(process.argv[4] ?? '16', 10);
const buf = readFileSync(file);
const ePhOff = Number(buf.readBigUInt64LE(0x20));
const ePhentSize = buf.readUInt16LE(0x36);
const ePhNum = buf.readUInt16LE(0x38);
function vaToFile(va) {
  for (let i = 0; i < ePhNum; i++) {
    const off = ePhOff + i * ePhentSize;
    if (buf.readUInt32LE(off) !== 1) continue;
    const pOffset = Number(buf.readBigUInt64LE(off + 8));
    const pVaddr = Number(buf.readBigUInt64LE(off + 16));
    const pFilesz = Number(buf.readBigUInt64LE(off + 32));
    if (va >= pVaddr && va < pVaddr + pFilesz) return pOffset + (va - pVaddr);
  }
  return null;
}
const fileOff = vaToFile(start);
if (fileOff == null) {
  console.error('offset not mapped');
  process.exit(2);
}
const win = buf.subarray(fileOff, Math.min(buf.length, fileOff + 4 * count));
console.log(`file 0x${fileOff.toString(16)} -> va 0x${start.toString(16)} raw ${win.subarray(0, 16).toString('hex')}`);
const insns = await disasmBytes(new Uint8Array(win), BigInt(start), count);
if (insns.length === 0) {
  console.log('  capstone decoded NOTHING - the bytes are not valid AArch64');
} else {
  for (const i of insns) console.log(`  ${i.addr}  ${i.bytes.padEnd(8)} ${i.text}`);
}

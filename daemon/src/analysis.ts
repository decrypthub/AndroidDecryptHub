// Static binary analysis of ELF .so files — host-side, shells out to the NDK's llvm tools.
// Extracted from index.ts so the daemon's wiring stays lean. Pure functions over a file
// path/Buffer; no daemon state, no agent protocol.
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { homedir } from 'node:os';
import { join } from 'node:path';

const execFileP = promisify(execFile);

// The NDK ships llvm-objdump/llvm-readelf per HOST OS, under a triple-named prebuilt dir, with a
// .exe suffix on Windows. Hardcoding the Windows triple meant that on any other host the spawn
// failed with ENOENT and `analyzeSo` reported that as an ANALYSIS error — `defined-exports=none`,
// `ERR spawn …llvm-objdump.exe` — so two acceptance scripts failed and the failure looked like the
// binary was unparseable rather than the tool being absent.
const HOST_TRIPLE = process.platform === 'win32' ? 'windows-x86_64' : 'linux-x86_64';
const EXE = process.platform === 'win32' ? '.exe' : '';
function defaultNdkBin(): string {
  const ndkRoot = process.env.ANDROID_NDK_HOME
    ?? (process.env.ANDROID_SDK_ROOT ? join(process.env.ANDROID_SDK_ROOT, 'ndk', '28.2.13676358') : undefined)
    ?? join(homedir(), 'AppData/Local/Android/Sdk/ndk/28.2.13676358');
  return join(ndkRoot, 'toolchains/llvm/prebuilt', HOST_TRIPLE, 'bin');
}
const LLVM_BIN = process.env.ADH_LLVM_BIN ?? defaultNdkBin();

// Resolve a tool: the NDK's copy when it is actually there, otherwise the same-named tool on PATH
// (a bare name makes execFile search PATH). llvm-objdump/llvm-readelf are the same programs in both
// places, so this is a lookup, not a substitution — and it is what lets a host without the Android
// SDK still analyse a .so instead of reporting ENOENT as a parse failure.
function llvmTool(name: string, override?: string): string {
  if (override) return override;
  const fromNdk = join(LLVM_BIN, name + EXE);
  return existsSync(fromNdk) ? fromNdk : name;
}
export const OBJDUMP = llvmTool('llvm-objdump', process.env.ADH_OBJDUMP);
const READELF = llvmTool('llvm-readelf', process.env.ADH_READELF);

// Dynamic symbols (exports/imports), NEEDED libs, and printable strings of an ELF .so.
export async function analyzeSo(path: string): Promise<any> {
  const exports: string[] = [], imports: string[] = [];
  let readelfError = '';   // fail-loud: an absent/failing readelf must not masquerade as "no symbols"
  try {
    const { stdout } = await execFileP(READELF, ['--dyn-syms', path], { maxBuffer: 32 * 1024 * 1024 });
    for (const line of stdout.split('\n')) {
      // Num: Value Size Type Bind Vis Ndx Name
      const m = line.match(/^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(FUNC|OBJECT|NOTYPE)\s+\S+\s+\S+\s+(\S+)\s+(\S+)/i);
      if (!m) continue;
      const [, , , ndx, name] = m;
      if (!name || name === '') continue;
      if (ndx === 'UND') imports.push(name); else exports.push(name);
    }
  } catch (e) { readelfError = `readelf --dyn-syms failed: ${(e as Error).message}`; }
  const needed: string[] = [];
  try {
    const { stdout } = await execFileP(READELF, ['-d', path], { maxBuffer: 8 * 1024 * 1024 });
    for (const line of stdout.split('\n')) { const m = line.match(/\(NEEDED\).*\[(.+?)\]/); if (m) needed.push(m[1]); }
  } catch (e) { if (!readelfError) readelfError = `readelf -d failed: ${(e as Error).message}`; }
  // printable string runs (>=4)
  const buf = await readFile(path);
  const strings: string[] = []; let cur = '';
  for (let i = 0; i < buf.length && strings.length < 5000; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) cur += String.fromCharCode(b);
    else { if (cur.length >= 4) strings.push(cur); cur = ''; }
  }
  return { exports: [...new Set(exports)], imports: [...new Set(imports)], needed, strings: [...new Set(strings)],
    ...(readelfError ? { readelfError } : {}),
    counts: { exports: exports.length, imports: imports.length, needed: needed.length, strings: strings.length } };
}

// Known crypto constant signatures (byte patterns) — locate algorithms in stripped
// native libs where symbols are gone (H.4). Little-endian where applicable.
// Exported so crypto_variants.ts can reuse these standard patterns instead of keeping a second copy
// of the same table (one fact, one source of truth).
export const CRYPTO_CONSTS: { name: string; hex: string }[] = [
  { name: 'AES-Sbox', hex: '637c777bf26b6fc53001672bfed7ab76' },
  { name: 'AES-InvSbox', hex: '52096ad53036a538bf40a39e81f3d7fb' },
  { name: 'Base64-std', hex: Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/').toString('hex') },
  { name: 'Base64-url', hex: Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_').toString('hex') },
  { name: 'SHA256-init', hex: '67e6096a85ae67bb' },   // H0,H1 LE
  { name: 'SHA256-K', hex: '982f8a4291443771' },       // K0,K1 LE
  { name: 'MD5-init', hex: '0123456789abcdef' },        // A,B LE (0x67452301,0xefcdab89)
  { name: 'SHA1-init', hex: '01234567' + '89abcdef' },  // A,B LE
  { name: 'TEA-delta', hex: 'b979379e' },               // 0x9e3779b9 LE
];
export function cryptoConstScan(buf: Buffer): { name: string; offset: string; hexLen: number }[] {
  const hits: { name: string; offset: string; hexLen: number }[] = [];
  for (const c of CRYPTO_CONSTS) {
    const pat = Buffer.from(c.hex, 'hex');
    let idx = buf.indexOf(pat);
    let n = 0;
    while (idx >= 0 && n < 8) { hits.push({ name: c.name, offset: '0x' + idx.toString(16), hexLen: pat.length }); n++; idx = buf.indexOf(pat, idx + 1); }
  }
  return hits;
}

// Scan an ELF .so's executable segments for arm64 `svc #0` (0xd4000001) — direct
// syscalls that bypass libc/PLT (and thus GOT hooks). E.9 L1: locate hotspots.
export function svcScan(buf: Buffer): { hits: { fileOff: string; vaddr: string }[]; execSegs: number; scanned: number; truncated?: boolean } {
  const hits: { fileOff: string; vaddr: string }[] = [];
  let execSegs = 0, scanned = 0;
  let truncated = false;
  if (buf.length < 64 || buf.readUInt32LE(0) !== 0x464c457f || buf[4] !== 2) return { hits, execSegs, scanned };
  const phoff = Number(buf.readBigUInt64LE(32));
  const phentsize = buf.readUInt16LE(54), phnum = buf.readUInt16LE(56);
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * phentsize;
    if (o + 56 > buf.length) break;
    if (buf.readUInt32LE(o) !== 1) continue;                 // PT_LOAD
    if (!(buf.readUInt32LE(o + 4) & 1)) continue;            // PF_X
    execSegs++;
    const off = Number(buf.readBigUInt64LE(o + 8));
    const vaddr = Number(buf.readBigUInt64LE(o + 16));
    const filesz = Number(buf.readBigUInt64LE(o + 32));
    const end = Math.min(off + filesz, buf.length);
    for (let a = off; a + 4 <= end; a += 4) {
      scanned += 4;
      if (buf.readUInt32LE(a) === 0xd4000001) hits.push({ fileOff: '0x' + a.toString(16), vaddr: '0x' + (vaddr + (a - off)).toString(16) });
      // The cap is reported, not silent: callers must be able to tell "the module has 4096 svc sites"
      // from "we stopped looking".
      if (hits.length >= 4096) { truncated = true; return { hits, execSegs, scanned, truncated }; }
    }
  }
  return truncated ? { hits, execSegs, scanned, truncated } : { hits, execSegs, scanned };
}

export interface Insn { addr: string; bytes: string; mnemonic: string; text: string; }
// Disassemble an ELF .so on disk (llvm-objdump). By symbol, or an address range.
export async function disasmSo(path: string, opts: { symbol?: string; start?: string; stop?: string }): Promise<Insn[]> {
  const args = ['-d'];
  if (opts.symbol) args.push(`--disassemble-symbols=${opts.symbol}`);
  if (opts.start) args.push(`--start-address=0x${opts.start.replace(/^0x/, '')}`);
  if (opts.stop) args.push(`--stop-address=0x${opts.stop.replace(/^0x/, '')}`);
  args.push(path);
  const { stdout } = await execFileP(OBJDUMP, args, { maxBuffer: 32 * 1024 * 1024 });
  const insns: Insn[] = [];
  for (const line of stdout.split('\n')) {
    const m = line.match(/^\s*([0-9a-f]+):\s+([0-9a-f]{2}(?: ?[0-9a-f]{2})*)\s+(.+?)\s*$/i);
    if (m) insns.push({ addr: m[1], bytes: m[2].replace(/\s+/g, ''), mnemonic: m[3].trim().split(/\s+/)[0], text: m[3].trim() });
  }
  return insns;
}

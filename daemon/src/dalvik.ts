// Dalvik (dex code_item) disassembly — host-side, shells out to the SDK's `dexdump -d`.
//
// Why not decode the opcodes here: Dalvik's 256-entry table has ~15 different instruction widths,
// and a wrong width desyncs every instruction after it in a way that still LOOKS like a
// disassembly (plausible mnemonics, wrong operands). `dexdump` is the reference decoder and ships
// with build-tools, so this module only owns (a) finding it, (b) feeding it a dex the caller
// already holds, (c) parsing the text back into per-method records. When the tool is absent the
// reply says so and keeps the raw bytecode — it does not degrade to a guess that a caller cannot
// tell apart from the real thing.
//
// The output is written with `-o` to a temp file and parsed by streaming: a dumped dex can be
// 100 MB+ and its full disassembly is far larger, so buffering it in memory (or in a reply) is
// exactly the failure native_analyze just had.
import { spawn } from 'node:child_process';
import { closeSync, createReadStream, existsSync, openSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EXE = process.platform === 'win32' ? '.exe' : '';

export const DALVIK_MAX_METHODS = 20;   // methods returned per call
export const DALVIK_MAX_INSNS = 400;    // instructions per method

// build-tools/<version>/dexdump.exe — pick the highest version that actually has the tool.
function buildToolsDirs(): string[] {
  const roots: string[] = [];
  for (const envName of ['ANDROID_SDK_ROOT', 'ANDROID_HOME']) {
    const v = process.env[envName];
    if (v) roots.push(v);
  }
  if (process.platform === 'win32') {
    if (process.env.LOCALAPPDATA) roots.push(join(process.env.LOCALAPPDATA, 'Android', 'Sdk'));
  } else if (process.platform === 'darwin') {
    roots.push(join(process.env.HOME ?? '', 'Library', 'Android', 'sdk'));
  } else {
    roots.push(join(process.env.HOME ?? '', 'Android', 'Sdk'));
  }
  return roots.map((r) => join(r, 'build-tools'));
}

function versionLess(a: string, b: string): boolean {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

/** Absolute path to dexdump, or '' when the host has no build-tools. ADH_DEXDUMP overrides. */
export function findDexdump(): string {
  const override = process.env.ADH_DEXDUMP;
  if (override) return existsSync(override) ? override : '';
  for (const bt of buildToolsDirs()) {
    if (!existsSync(bt)) continue;
    let versions: string[] = [];
    try { versions = readdirSync(bt).filter((d) => /^\d+\.\d+\.\d+$/.test(d)); } catch { continue; }
    versions.sort((a, b) => (versionLess(a, b) ? 1 : -1));
    for (const v of versions) {
      const p = join(bt, v, 'dexdump' + EXE);
      if (existsSync(p)) return p;
    }
  }
  return '';
}

export interface DalvikInsn { offset: string; hex: string; text: string }
export interface DalvikMethod {
  class: string; name: string; type: string; access: string;
  /** code = has a code_item; native/abstract carry no instructions. */
  kind: 'code' | 'native' | 'abstract';
  registers?: number; ins?: number; outs?: number; insnsSize?: number;
  insns: DalvikInsn[];
  /** true when the per-method instruction cap cut this body. */
  insnsTruncated?: boolean;
}
export interface DalvikResult {
  available: boolean; tool?: string; classes?: number;
  methodMatches?: number; returned?: number; truncated?: boolean;
  methods: DalvikMethod[];
  error?: string; note?: string;
}
export interface DalvikOptions {
  class?: string; method?: string;
  maxMethods?: number; maxInsns?: number;
  tool?: string;
}

/** `com.foo.Bar`, `Lcom/foo/Bar;` and `Bar` all compare on the same normalised form. */
function normClass(s: string): string {
  return s.trim().replace(/^L/, '').replace(/[;.]/g, '/').toLowerCase();
}

const INSN_RE = /^\s*([0-9a-f]{4,}):\s+(?:([0-9a-f]{4}(?: [0-9a-f]{4})*)\s+)?\|([0-9a-f]{4}):\s?(.*)$/;

/**
 * Line-oriented parser for `dexdump -d`. Exported through `parseDexdump` so the extraction can be
 * tested on a canned dump without the SDK (the format is the contract, not the tool).
 */
export class DexdumpParser {
  private cls = '';
  private section = '';
  private cur: DalvikMethod | null = null;
  private readonly wantClass: string;
  private readonly wantMethod: string;
  private readonly maxMethods: number;
  private readonly maxInsns: number;
  classes = 0;
  matches = 0;
  truncated = false;
  methods: DalvikMethod[] = [];

  constructor(opts: DalvikOptions = {}) {
    this.wantClass = normClass(opts.class ?? '');
    this.wantMethod = (opts.method ?? '').toLowerCase();
    this.maxMethods = Math.max(1, Math.min(200, Math.floor(opts.maxMethods ?? DALVIK_MAX_METHODS)));
    this.maxInsns = Math.max(1, Math.min(100_000, Math.floor(opts.maxInsns ?? DALVIK_MAX_INSNS)));
  }

  private flush() {
    const m = this.cur;
    this.cur = null;
    if (!m) return;
    if (this.wantClass && !normClass(m.class).includes(this.wantClass)) return;
    if (this.wantMethod && !m.name.toLowerCase().includes(this.wantMethod)) return;
    this.matches++;
    if (this.methods.length >= this.maxMethods) { this.truncated = true; return; }
    this.methods.push(m);
  }

  feed(line: string) {
    const mClass = /^\s*Class descriptor\s*:\s*'(.*)'\s*$/.exec(line);
    if (mClass) { this.flush(); this.cls = mClass[1]; this.section = ''; this.classes++; return; }
    const mSect = /^\s{1,4}(Static fields|Instance fields|Direct methods|Virtual methods)\s*-/.exec(line);
    if (mSect) { this.flush(); this.section = mSect[1]; return; }
    if (this.section !== 'Direct methods' && this.section !== 'Virtual methods') return;
    const mName = /^\s{4,}name\s+:\s*'(.*)'\s*$/.exec(line);
    if (mName) {
      this.flush();
      this.cur = { class: this.cls, name: mName[1], type: '', access: '', kind: 'code', insns: [] };
      return;
    }
    const m = this.cur;
    if (!m) return;
    const mType = /^\s{4,}type\s+:\s*'(.*)'\s*$/.exec(line);
    if (mType) { m.type = mType[1]; return; }
    const mAcc = /^\s{4,}access\s+:\s*(0x[0-9a-f]+)\s*\((.*)\)\s*$/.exec(line);
    if (mAcc) {
      m.access = mAcc[2].trim();
      if (/\bNATIVE\b/.test(m.access)) m.kind = 'native';
      else if (/\bABSTRACT\b/.test(m.access)) m.kind = 'abstract';
      return;
    }
    const mReg = /^\s{4,}registers\s*:\s*(\d+)/.exec(line);
    if (mReg) { m.registers = Number(mReg[1]); return; }
    const mIns = /^\s{4,}ins\s*:\s*(\d+)/.exec(line);
    if (mIns) { m.ins = Number(mIns[1]); return; }
    const mOuts = /^\s{4,}outs\s*:\s*(\d+)/.exec(line);
    if (mOuts) { m.outs = Number(mOuts[1]); return; }
    const mSize = /^\s{4,}insns size\s*:\s*(\d+)/.exec(line);
    if (mSize) { m.insnsSize = Number(mSize[1]); return; }
    const mInsn = INSN_RE.exec(line);
    if (mInsn) {
      if (m.insns.length >= this.maxInsns) { m.insnsTruncated = true; return; }
      m.insns.push({ offset: mInsn[3], hex: (mInsn[2] ?? '').trim(), text: mInsn[4].trimEnd() });
    }
  }

  finish(): void { this.flush(); }
}

export function parseDexdump(text: string, opts: DalvikOptions = {}): Omit<DalvikResult, 'available' | 'tool'> {
  const p = new DexdumpParser(opts);
  for (const line of text.split('\n')) p.feed(line);
  p.finish();
  return {
    classes: p.classes, methodMatches: p.matches, returned: p.methods.length,
    ...(p.truncated ? { truncated: true } : {}),
    methods: p.methods,
  };
}

/**
 * Disassemble the methods of a dex buffer. Returns `available:false` + an actionable error when
 * dexdump is missing or refuses the file (a dumped dex with a stale header checksum fails
 * verification: run dex_repair first and pass the repaired bytes).
 */
export async function disassembleDex(buf: Buffer, opts: DalvikOptions = {}): Promise<DalvikResult> {
  const tool = opts.tool ?? findDexdump();
  if (!tool) {
    return { available: false, methods: [], error: 'dexdump not found — install Android SDK build-tools or set ADH_DEXDUMP to its path' };
  }
  const stamp = `${process.pid}_${Date.now()}_${Math.floor(Math.random() * 1e6)}`;
  const dexPath = join(tmpdir(), `adh_dex_${stamp}.dex`);
  const outPath = join(tmpdir(), `adh_dex_${stamp}.txt`);
  const errPath = join(tmpdir(), `adh_dex_${stamp}.err`);
  const cleanup = () => { for (const p of [dexPath, outPath, errPath]) { try { unlinkSync(p); } catch { /* may not exist */ } } };
  writeFileSync(dexPath, buf);
  // `-o` is broken on at least one build-tools Windows build ("Can't open …: Invalid argument"),
  // so stdout goes straight to a file through an inherited fd. No pipe, and no maxBuffer: the
  // disassembly of a large dex is far bigger than anything that should be buffered.
  const outFd = openSync(outPath, 'w');
  const errFd = openSync(errPath, 'w');
  let code: number;
  try {
    code = await new Promise<number>((resolve, reject) => {
      const child = spawn(tool, ['-d', dexPath], { stdio: ['ignore', outFd, errFd] });
      child.on('error', reject);
      child.on('close', (c) => resolve(c ?? -1));
    });
  } catch (e) {
    cleanup();
    return { available: false, tool, methods: [], error: `dexdump could not run: ${(e as Error).message}` };
  } finally {
    closeSync(outFd); closeSync(errFd);
  }
  if (code !== 0) {
    const msg = (readFileSync(errPath, 'utf8') || '').trim().split('\n').slice(-2).join(' ');
    cleanup();
    const hint = /checksum|verif|magic|corrupt/i.test(msg) ? ' — the dex header is stale or the buffer is not a dex: run dex_repair and retry' : '';
    return { available: false, tool, methods: [], error: `dexdump exited ${code}: ${msg || '(no stderr)'}${hint}` };
  }
  try {
    const p = new DexdumpParser(opts);
    const rl = createInterface({ input: createReadStream(outPath, 'utf8'), crlfDelay: Infinity });
    for await (const line of rl) p.feed(line);
    p.finish();
    return {
      available: true, tool, classes: p.classes, methodMatches: p.matches,
      returned: p.methods.length, ...(p.truncated ? { truncated: true } : {}), methods: p.methods,
      ...(p.methods.length === 0 ? { note: 'no method matched — class is compared on its normalised descriptor (L…; → dotted) as a case-insensitive substring, method on its name' } : {}),
    };
  } finally {
    cleanup();
  }
}

// Minimal DEX parser — enough for search/index + crypto static scan (v0.4/v0.5).
// Parses header, string_ids, type_ids, method_ids, class_defs. Not a full verifier.

export interface DexMethod { cls: string; name: string; }
export interface DexClass { name: string; superName: string; access: number; }
export interface ParsedDex {
  magic: string;
  counts: { strings: number; types: number; protos: number; fields: number; methods: number; classes: number };
  strings: string[];
  types: string[];
  methods: DexMethod[];
  classes: DexClass[];
}

function readUleb128(buf: Buffer, pos: number): [number, number] {
  let result = 0, shift = 0, p = pos, b: number;
  do { b = buf[p++]; result |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
  return [result >>> 0, p];
}

// string_data_item: uleb128 utf16 length, then MUTF-8 bytes NUL-terminated.
function readMutf8(buf: Buffer, off: number): string {
  let [, p] = readUleb128(buf, off);   // skip declared utf16 length
  let end = p;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.subarray(p, end).toString('utf8');   // ASCII identifiers decode fine
}

export function parseDex(buf: Buffer): ParsedDex {
  if (buf.length < 112 || !(buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a))
    throw new Error('not a dex (bad magic)');
  const magic = buf.subarray(0, 7).toString('latin1');
  const u32 = (o: number) => buf.readUInt32LE(o);

  const stringIdsSize = u32(56), stringIdsOff = u32(60);
  const typeIdsSize = u32(64), typeIdsOff = u32(68);
  const protoIdsSize = u32(72);
  const fieldIdsSize = u32(80);
  const methodIdsSize = u32(88), methodIdsOff = u32(92);
  const classDefsSize = u32(96), classDefsOff = u32(100);

  const strings: string[] = new Array(stringIdsSize);
  for (let i = 0; i < stringIdsSize; i++) {
    const dataOff = u32(stringIdsOff + i * 4);
    strings[i] = dataOff && dataOff < buf.length ? readMutf8(buf, dataOff) : '';
  }
  const types: string[] = new Array(typeIdsSize);
  for (let i = 0; i < typeIdsSize; i++) {
    const sidx = u32(typeIdsOff + i * 4);
    types[i] = strings[sidx] ?? '';
  }
  const methods: DexMethod[] = new Array(methodIdsSize);
  for (let i = 0; i < methodIdsSize; i++) {
    const o = methodIdsOff + i * 8;
    const classIdx = buf.readUInt16LE(o);
    const nameIdx = u32(o + 4);
    methods[i] = { cls: types[classIdx] ?? '', name: strings[nameIdx] ?? '' };
  }
  const classes: DexClass[] = new Array(classDefsSize);
  for (let i = 0; i < classDefsSize; i++) {
    const o = classDefsOff + i * 32;
    const classIdx = u32(o);
    const access = u32(o + 4);
    const superIdx = u32(o + 8);
    classes[i] = { name: types[classIdx] ?? '', superName: types[superIdx] ?? '', access };
  }
  return {
    magic,
    counts: { strings: stringIdsSize, types: typeIdsSize, protos: protoIdsSize, fields: fieldIdsSize, methods: methodIdsSize, classes: classDefsSize },
    strings, types, methods, classes,
  };
}

// Searchable index over a parsed dex: strings / classes / methods (K.2/K.3).
// Case-insensitive substring; invoke-xref (bytecode) is a later enhancement.
export function searchDex(d: ParsedDex, query: string, kinds: string[] = ['string', 'class', 'method'], limit = 200): {
  query: string; strings: string[]; classes: string[]; methods: DexMethod[]; counts: Record<string, number>;
} {
  const q = query.toLowerCase();
  const wantS = kinds.includes('string'), wantC = kinds.includes('class'), wantM = kinds.includes('method');
  const strings = wantS ? d.strings.filter(s => s.toLowerCase().includes(q)) : [];
  const classes = wantC ? d.classes.map(c => c.name).filter(n => n.toLowerCase().includes(q)) : [];
  const methods = wantM ? d.methods.filter(m => (m.cls + '->' + m.name).toLowerCase().includes(q)) : [];
  return {
    query,
    strings: strings.slice(0, limit),
    classes: classes.slice(0, limit),
    methods: methods.slice(0, limit),
    counts: { strings: strings.length, classes: classes.length, methods: methods.length },
  };
}

// Dalvik instruction width table (code units), indexed by opcode byte.
// Default 1; override the multi-unit formats. Payloads (0x0100/0x0200/0x0300) are
// handled specially before this table is consulted.
const INSN_W = (() => {
  const w = new Uint8Array(256).fill(1);
  const set = (a: number, b: number, v: number) => { for (let i = a; i <= b; i++) w[i] = v; };
  w[0x02] = 2; w[0x03] = 3; w[0x05] = 2; w[0x06] = 3; w[0x08] = 2; w[0x09] = 3;
  w[0x13] = 2; w[0x14] = 3; w[0x15] = 2; w[0x16] = 2; w[0x17] = 3; w[0x18] = 5; w[0x19] = 2;
  w[0x1a] = 2; w[0x1b] = 3; w[0x1c] = 2; w[0x1f] = 2; w[0x20] = 2; w[0x22] = 2; w[0x23] = 2;
  w[0x24] = 3; w[0x25] = 3; w[0x26] = 3; w[0x29] = 2; w[0x2a] = 3; w[0x2b] = 3; w[0x2c] = 3;
  set(0x2d, 0x31, 2); set(0x32, 0x37, 2); set(0x38, 0x3d, 2);
  set(0x44, 0x51, 2); set(0x52, 0x5f, 2); set(0x60, 0x6d, 2);
  set(0x6e, 0x72, 3); set(0x74, 0x78, 3);
  set(0x90, 0xaf, 2); set(0xd0, 0xd7, 2); set(0xd8, 0xe2, 2);
  w[0xfa] = 4; w[0xfb] = 4; w[0xfc] = 3; w[0xfd] = 3; w[0xfe] = 2; w[0xff] = 2;
  return w;
})();

// Walk a code_item's insns, returning the method refs it invokes. Returns null if
// the walk desyncs (width-table gap) so callers can skip it rather than emit garbage.
function walkCode(buf: Buffer, codeOff: number, methods: DexMethod[]): string[] | null {
  if (codeOff + 16 > buf.length) return null;
  const insnsSize = buf.readUInt32LE(codeOff + 12);
  const start = codeOff + 16;
  if (start + insnsSize * 2 > buf.length) return null;
  const callees: string[] = [];
  let pc = 0;
  while (pc < insnsSize) {
    const unit = buf.readUInt16LE(start + pc * 2);
    if (unit === 0x0100) { const n = buf.readUInt16LE(start + (pc + 1) * 2); pc += n * 2 + 4; continue; }
    if (unit === 0x0200) { const n = buf.readUInt16LE(start + (pc + 1) * 2); pc += n * 4 + 2; continue; }
    if (unit === 0x0300) { const ew = buf.readUInt16LE(start + (pc + 1) * 2); const n = buf.readUInt32LE(start + (pc + 2) * 2); pc += Math.ceil((n * ew) / 2) + 4; continue; }
    const op = unit & 0xff;
    const w = INSN_W[op];
    if (w <= 0) return null;
    if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
      const midx = buf.readUInt16LE(start + (pc + 1) * 2);
      if (methods[midx]) callees.push(methods[midx].cls + '->' + methods[midx].name);
    }
    pc += w;
  }
  return pc === insnsSize ? callees : null;   // sanity: must land exactly on the boundary
}

export interface XrefResult { xref: Map<string, string[]>; methodsWithCode: number; skipped: number; }
// Build the invoke cross-reference: callee "cls->name" -> [caller "cls->name"].
export function invokeXref(buf: Buffer, d: ParsedDex): XrefResult {
  const u32 = (o: number) => buf.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  const methods = d.methods;
  const xref = new Map<string, Set<string>>();
  let methodsWithCode = 0, skipped = 0;
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24);
    if (!cdOff) continue;
    let p = cdOff;
    let sf, inf, dm, vm;
    [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
    [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(buf, p); [, p] = readUleb128(buf, p); }  // skip fields
    for (const count of [dm, vm]) {
      let midx = 0;
      for (let k = 0; k < count; k++) {
        let diff, af, co;
        [diff, p] = readUleb128(buf, p); midx += diff;
        [af, p] = readUleb128(buf, p);
        [co, p] = readUleb128(buf, p);
        if (co) {
          methodsWithCode++;
          const caller = methods[midx] ? methods[midx].cls + '->' + methods[midx].name : `?#${midx}`;
          const callees = walkCode(buf, co, methods);
          if (callees === null) { skipped++; continue; }
          for (const ce of callees) { if (!xref.has(ce)) xref.set(ce, new Set()); xref.get(ce)!.add(caller); }
        }
      }
    }
  }
  const out = new Map<string, string[]>();
  for (const [k, v] of xref) out.set(k, [...v]);
  return { xref: out, methodsWithCode, skipped };
}

const CRYPTO_CLASS_RE = /^L(javax\/crypto\/|java\/security\/(MessageDigest|Signature|KeyPairGenerator|KeyFactory)|android\/util\/Base64)/;
const ALGO_STRING_RE = /(AES|DESede|DES|RSA|Blowfish|ChaCha|HmacSHA?\d*|HmacMD5|SHA-?(1|224|256|384|512)|MD5|PBKDF2|PKCS[157]|\/(CBC|GCM|ECB|CTR|CFB)\/|GCM|Base64)/;

// Static crypto channel: crypto API method refs + algorithm-name strings.
export function cryptoScan(d: ParsedDex): {
  cryptoApis: DexMethod[]; algoStrings: string[]; summary: Record<string, number>;
} {
  const cryptoApis = d.methods.filter(m => CRYPTO_CLASS_RE.test(m.cls));
  const algoStrings = [...new Set(d.strings.filter(s => s.length >= 3 && s.length < 64 && ALGO_STRING_RE.test(s)))];
  const summary: Record<string, number> = {};
  for (const m of cryptoApis) {
    const k = m.cls.replace(/^L/, '').replace(/;$/, '').split('/').slice(-1)[0] + '.' + m.name;
    summary[k] = (summary[k] ?? 0) + 1;
  }
  return { cryptoApis, algoStrings, summary };
}

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

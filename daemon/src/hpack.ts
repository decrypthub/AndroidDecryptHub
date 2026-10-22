// HPACK decoder (RFC 7541). One instance per HTTP/2 connection direction:
// header blocks must be fed in the order they appear on that direction, because
// the dynamic table carries over. Static table and Huffman codes are the RFC tables.

export interface HpackField { name: string; value: string }

export interface HpackDecoder {
  // Optional fields instead of a discriminated union: `strictNullChecks` is off, so a
  // boolean-literal discriminant does not narrow (see tsconfig.json).
  decode(block: Buffer): { ok: boolean; fields?: HpackField[]; error?: string };
}

const STATIC: HpackField[] = [
  [':authority', ''], [':method', 'GET'], [':method', 'POST'], [':path', '/'], [':path', '/index.html'],
  [':scheme', 'http'], [':scheme', 'https'], [':status', '200'], [':status', '204'], [':status', '206'],
  [':status', '304'], [':status', '400'], [':status', '404'], [':status', '500'], ['accept-charset', ''],
  ['accept-encoding', 'gzip, deflate'], ['accept-language', ''], ['accept-ranges', ''], ['accept', ''],
  ['access-control-allow-origin', ''], ['age', ''], ['allow', ''], ['authorization', ''], ['cache-control', ''],
  ['content-disposition', ''], ['content-encoding', ''], ['content-language', ''], ['content-length', ''],
  ['content-location', ''], ['content-range', ''], ['content-type', ''], ['cookie', ''], ['date', ''],
  ['etag', ''], ['expect', ''], ['expires', ''], ['from', ''], ['host', ''], ['if-match', ''],
  ['if-modified-since', ''], ['if-none-match', ''], ['if-range', ''], ['if-unmodified-since', ''],
  ['last-modified', ''], ['link', ''], ['location', ''], ['max-forwards', ''], ['proxy-authenticate', ''],
  ['proxy-authorization', ''], ['range', ''], ['referer', ''], ['refresh', ''], ['retry-after', ''],
  ['server', ''], ['set-cookie', ''], ['strict-transport-security', ''], ['transfer-encoding', ''],
  ['user-agent', ''], ['vary', ''], ['via', ''], ['www-authenticate', ''],
].map(([name, value]) => ({ name, value }));

// RFC 7541 Appendix B. Code is the low `len` bits, MSB first on the wire.
const HUFF_CODE = [
  0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
  0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
  0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
  0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
  0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa,
  0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb,
  0x7ffc, 0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
  0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
  0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4,
  0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c,
  0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
  0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6,
  0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed,
  0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8,
  0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb,
  0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf,
  0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1,
  0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6,
  0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
  0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
  0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
  0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
  0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea,
  0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
  0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
  0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];
const HUFF_LEN = [
  13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
  28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
  5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
  15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
  6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
  20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
  24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
  22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
  21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
  26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
  19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
  20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
  26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

interface HuffNode { s?: number; z?: HuffNode; o?: HuffNode }

function buildTrie(): HuffNode {
  const root: HuffNode = {};
  for (let sym = 0; sym < 256; sym++) {
    const code = HUFF_CODE[sym];
    const len = HUFF_LEN[sym];
    let node = root;
    for (let i = len - 1; i >= 0; i--) {
      const bit = (code >>> i) & 1;
      const next = bit ? (node.o ??= {}) : (node.z ??= {});
      node = next;
    }
    node.s = sym;
  }
  return root;
}

const HUFF_ROOT = buildTrie();

/** Huffman-decode one string. Padding must be a 1–7 bit prefix of EOS (all ones). */
export function huffmanDecode(raw: Buffer): Buffer | null {
  if (!raw.length) return Buffer.alloc(0);
  const out: number[] = [];
  let node = HUFF_ROOT;
  let partialBits = 0;
  let partialOnes = 0;
  for (const byte of raw) {
    for (let i = 7; i >= 0; i--) {
      const bit = (byte >>> i) & 1;
      node = bit ? node.o! : node.z!;
      if (!node) return null;
      partialBits++;
      if (bit) { if (partialOnes >= 0) partialOnes++; }
      else partialOnes = -1;
      if (node.s != null) {
        out.push(node.s);
        node = HUFF_ROOT;
        partialBits = 0;
        partialOnes = 0;
      }
    }
  }
  if (node !== HUFF_ROOT && (partialOnes !== partialBits || partialBits > 7)) return null;
  return Buffer.from(out);
}

function bytesToText(buf: Buffer): string {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(buf); }
  catch { return buf.toString('latin1'); }
}

function readInt(buf: Buffer, pos: number, prefix: number): { value: number; next: number } | null {
  if (pos >= buf.length || prefix < 1 || prefix > 8) return null;
  const max = (1 << prefix) - 1;
  let value = buf[pos] & max;
  pos++;
  if (value < max) return { value, next: pos };
  let m = 0;
  for (;;) {
    if (pos >= buf.length || m > 28) return null;
    const b = buf[pos++];
    value += (b & 0x7f) * (2 ** m);
    if (value > 0x1fffffff) return null;
    m += 7;
    if ((b & 0x80) === 0) return { value, next: pos };
  }
}

function readString(buf: Buffer, pos: number): { text: string; bytes: number; next: number } | null {
  if (pos >= buf.length) return null;
  const huff = (buf[pos] & 0x80) !== 0;
  const len = readInt(buf, pos, 7);
  if (!len || len.value > (1 << 20)) return null;
  const end = len.next + len.value;
  if (end > buf.length) return null;
  const raw = buf.subarray(len.next, end);
  const decoded = huff ? huffmanDecode(raw) : raw;
  if (!decoded) return null;
  return { text: bytesToText(decoded), bytes: decoded.length, next: end };
}

interface DynEntry { name: string; value: string; size: number }

const TABLE_HARD_CAP = 65536;
const MAX_FIELDS = 512;

export function createHpackDecoder(): HpackDecoder {
  let maxSize = 4096;
  let size = 0;
  const table: DynEntry[] = []; // index 0 is the newest

  function evict() {
    while (table.length && size > maxSize) {
      const last = table.pop()!;
      size -= last.size;
    }
  }

  function lookup(index: number): HpackField | null {
    if (index <= 0) return null;
    if (index <= STATIC.length) return STATIC[index - 1];
    return table[index - STATIC.length - 1] ?? null;
  }

  function add(name: string, value: string, nameBytes: number, valueBytes: number) {
    const entrySize = nameBytes + valueBytes + 32;
    if (entrySize > maxSize) { table.length = 0; size = 0; return; }
    table.unshift({ name, value, size: entrySize });
    size += entrySize;
    evict();
  }

  return {
    decode(block: Buffer) {
      const fields: HpackField[] = [];
      let pos = 0;
      let sawField = false;
      while (pos < block.length) {
        if (fields.length >= MAX_FIELDS) return { ok: false, error: '头部字段太多' };
        const b = block[pos];
        if ((b & 0xe0) === 0x20) {
          if (sawField) return { ok: false, error: '动态表大小更新不在块首' };
          const n = readInt(block, pos, 5);
          if (!n) return { ok: false, error: '动态表大小读不完' };
          if (n.value > TABLE_HARD_CAP) return { ok: false, error: '动态表上限过大' };
          maxSize = n.value;
          evict();
          pos = n.next;
          continue;
        }
        sawField = true;
        if (b & 0x80) {
          const idx = readInt(block, pos, 7);
          if (!idx || idx.value === 0) return { ok: false, error: '索引非法' };
          const hit = lookup(idx.value);
          if (!hit) return { ok: false, error: `索引 ${idx.value} 不在表里` };
          fields.push({ name: hit.name, value: hit.value });
          pos = idx.next;
          continue;
        }
        const incremental = (b & 0x40) !== 0;
        const idx = readInt(block, pos, incremental ? 6 : 4);
        if (!idx) return { ok: false, error: '名字索引读不完' };
        let name: string;
        let nameBytes: number;
        let next = idx.next;
        if (idx.value === 0) {
          const s = readString(block, next);
          if (!s) return { ok: false, error: '字段名读不完' };
          name = s.text.toLowerCase();
          nameBytes = s.bytes;
          next = s.next;
        } else {
          const hit = lookup(idx.value);
          if (!hit) return { ok: false, error: `名字索引 ${idx.value} 不在表里` };
          name = hit.name;
          nameBytes = Buffer.byteLength(hit.name);
        }
        const value = readString(block, next);
        if (!value) return { ok: false, error: '字段值读不完' };
        fields.push({ name, value: value.text });
        if (incremental) add(name, value.text, nameBytes, value.bytes);
        pos = value.next;
      }
      return { ok: true, fields };
    },
  };
}

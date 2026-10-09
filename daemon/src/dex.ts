// Minimal DEX parser — enough for search/index + crypto static scan (v0.4/v0.5).
// Parses header, string_ids, type_ids, method_ids, class_defs. Not a full verifier.
import { createHash } from 'node:crypto';

export interface DexProto { shorty: string; returnType: string; params: string[]; descriptor: string; }
export interface DexField { cls: string; type: string; name: string; }
export interface DexMethod { cls: string; name: string; proto: string; returnType: string; params: string[]; }
export interface DexClass { name: string; superName: string; access: number; }
export interface ParsedDex {
  magic: string;
  counts: { strings: number; types: number; protos: number; fields: number; methods: number; classes: number };
  strings: string[];
  types: string[];
  protos: DexProto[];
  fields: DexField[];
  methods: DexMethod[];
  classes: DexClass[];
}

function readUleb128(buf: Buffer, pos: number): [number, number] {
  let result = 0, shift = 0, p = pos, b: number;
  do {
    // Bounded: a truncated LEB used to read buf[len] (undefined in Node, but that is not a bounds
    // check). The sentinel p > buf.length is what every caller already tests for.
    if (p >= buf.length) return [0, buf.length + 1];
    b = buf[p++]; result |= (b & 0x7f) << shift; shift += 7;
  } while (b & 0x80);
  return [result >>> 0, p];
}

// Signed LEB128 (encoded_catch_handler.size is signed; <= 0 means a catch-all follows).
function readSleb128(buf: Buffer, pos: number): [number, number] {
  let result = 0, shift = 0, p = pos, b: number;
  do {
    if (p >= buf.length) return [0, buf.length + 1];   // see readUleb128: bounded, sentinel on EOF
    b = buf[p++]; result |= (b & 0x7f) << shift; shift += 7;
  } while (b & 0x80);
  if (shift < 32 && (b & 0x40)) result |= -(1 << shift);
  return [result, p];
}

export interface CodeItemInfo { hex: string; size: number; tries: number; insnsSize: number; }
// The walk without the hex copy: coverage and the layout checker only need to know whether an item
// is walkable (materialising a hex string per method is pure allocation amplification on a
// 46k-method dex, and a hostile handler list can make each of those strings huge).
export function codeItemEnd(buf: Buffer, co: number): number | null {
// Parse one FULL code_item: 16B header + insns + (tries[] + encoded_catch_handler_list when
// tries > 0). Returns null when the item runs past the buffer or the handler list is malformed,
// so callers report it as unresolvable instead of pretending the method has no code (the old
// code path silently returned "" for every method with try/catch and inflated the recovery rate).
  if (co < 0 || co + 16 > buf.length) return null;
  const tries = buf.readUInt16LE(co + 6);
  const insnsSize = buf.readUInt32LE(co + 12);
  let end = co + 16 + insnsSize * 2;
  if (end > buf.length) return null;
  if (tries > 0) {
    end = (end + 3) & ~3;                            // tries[] is 4-byte aligned from file start
    if (end + tries * 8 > buf.length) return null;
    let p = end + tries * 8;                         // skip tries[] (start/count/handler_off)
    let handlers: number;
    if (p >= buf.length) return null;
    [handlers, p] = readUleb128(buf, p);
    for (let i = 0; i < handlers; i++) {
      let n: number;
      if (p >= buf.length) return null;
      [n, p] = readSleb128(buf, p);
      for (let k = 0, pairs = Math.abs(n); k < pairs; k++) {
        if (p >= buf.length) return null;
        [, p] = readUleb128(buf, p);                 // type_idx
        if (p >= buf.length) return null;
        [, p] = readUleb128(buf, p);                 // addr
      }
      if (n <= 0) {                                  // catch-all handler
        if (p >= buf.length) return null;
        [, p] = readUleb128(buf, p);
      }
    }
    end = p;
  }
  if (end > buf.length) return null;
  return end;
}
export function readCodeItem(buf: Buffer, co: number): CodeItemInfo | null {
  const end = codeItemEnd(buf, co);
  if (end == null) return null;
  return { hex: buf.subarray(co, end).toString('hex'), size: end - co,
           tries: buf.readUInt16LE(co + 6), insnsSize: buf.readUInt32LE(co + 12) };
}

// string_data_item: uleb128 utf16 length, then MUTF-8 bytes NUL-terminated.
function readMutf8(buf: Buffer, off: number): string {
  let [, p] = readUleb128(buf, off);   // skip declared utf16 length
  let end = p;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.subarray(p, end).toString('utf8');   // ASCII identifiers decode fine
}

// ---- artifact shape: real code vs carrier ------------------------------------------------
//
// A packed target can hand you a dex whose header is valid but whose contents are not the app's
// code. A large buffer may parse as "classes.dex" while declaring only a handful of classes.
// Counting classes helps distinguish that carrier from dense dexes containing real code.
export interface DexArtifactShape {
  classes: number;
  methods: number;
  bytesPerClass: number;   // 0 when the dex declares no classes at all
  carrier: boolean;
  reason: string;
}

/** Bytes a single class would have to occupy before the file is classified as a carrier. */
export const DEX_CARRIER_BYTES_PER_CLASS = 1 << 20;

export function classifyDexArtifact(size: number, classes: number, methods: number): DexArtifactShape {
  const bytesPerClass = classes > 0 ? Math.round(size / classes) : 0;
  const carrier = classes === 0 || bytesPerClass > DEX_CARRIER_BYTES_PER_CLASS;
  return {
    classes, methods, bytesPerClass, carrier,
    reason: carrier
      ? (classes === 0
          ? 'declares no classes'
          : `${(bytesPerClass / 1048576).toFixed(1)} MiB per class (> ${DEX_CARRIER_BYTES_PER_CLASS / 1048576} MiB): a carrier, not code`)
      : `${bytesPerClass} bytes per class`,
  };
}

export function parseDex(buf: Buffer): ParsedDex {
  if (buf.length < 112 || !(buf[0] === 0x64 && buf[1] === 0x65 && buf[2] === 0x78 && buf[3] === 0x0a))
    throw new Error('not a dex (bad magic)');
  const magic = buf.subarray(0, 7).toString('latin1');
  const u32 = (o: number) => buf.readUInt32LE(o);

  const stringIdsSize = u32(56), stringIdsOff = u32(60);
  const typeIdsSize = u32(64), typeIdsOff = u32(68);
  const protoIdsSize = u32(72), protoIdsOff = u32(76);
  const fieldIdsSize = u32(80), fieldIdsOff = u32(84);
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
  const protos: DexProto[] = new Array(protoIdsSize);
  for (let i = 0; i < protoIdsSize; i++) {
    const o = protoIdsOff + i * 12;
    const shorty = strings[u32(o)] ?? '';
    const returnType = types[u32(o + 4)] ?? '';
    const paramsOff = u32(o + 8);
    const params: string[] = [];
    if (paramsOff && paramsOff + 4 <= buf.length) {
      const n = u32(paramsOff);
      for (let j = 0; j < n && paramsOff + 6 + j * 2 <= buf.length; j++)
        params.push(types[buf.readUInt16LE(paramsOff + 4 + j * 2)] ?? '');
    }
    protos[i] = { shorty, returnType, params, descriptor: `(${params.join('')})${returnType}` };
  }
  const fields: DexField[] = new Array(fieldIdsSize);
  for (let i = 0; i < fieldIdsSize; i++) {
    const o = fieldIdsOff + i * 8;
    fields[i] = {
      cls: types[buf.readUInt16LE(o)] ?? '',
      type: types[buf.readUInt16LE(o + 2)] ?? '',
      name: strings[u32(o + 4)] ?? '',
    };
  }
  const methods: DexMethod[] = new Array(methodIdsSize);
  for (let i = 0; i < methodIdsSize; i++) {
    const o = methodIdsOff + i * 8;
    const classIdx = buf.readUInt16LE(o);
    const protoIdx = buf.readUInt16LE(o + 2);
    const nameIdx = u32(o + 4);
    const proto = protos[protoIdx] ?? { descriptor: '', returnType: '', params: [] };
    methods[i] = { cls: types[classIdx] ?? '', name: strings[nameIdx] ?? '', proto: proto.descriptor, returnType: proto.returnType, params: proto.params };
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
    strings, types, protos, fields, methods, classes,
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

export interface DexCallEdge { callerIdx: number; caller: string; calleeIdx: number; callee: string; }
export interface DexStringUse { callerIdx: number; caller: string; stringIdx: number; value: string; }
export interface DexReflectionEdge { callerIdx: number; caller: string; api: string; targetClass: string; targetDescriptor: string; }
export interface DexFieldAccess { callerIdx: number; caller: string; fieldIdx: number; field: string; access: 'read' | 'write'; }
export interface DexCodeAnalysis {
  calls: DexCallEdge[];
  stringUses: DexStringUse[];
  fieldAccesses: DexFieldAccess[];
  reflections: DexReflectionEdge[];
  methodsWithCode: number;
  skipped: number;
}

function methodLabel(m: DexMethod | undefined, idx: number): string {
  return m ? `${m.cls}->${m.name}${m.proto}` : `?#${idx}`;
}

function invokeRegisters(buf: Buffer, start: number, pc: number, op: number): number[] {
  const unit = buf.readUInt16LE(start + pc * 2);
  if (op >= 0x6e && op <= 0x72) { // format 35c: C,D,E,F in word 3; G in word 1
    const count = (unit >>> 12) & 0x0f;
    const g = (unit >>> 8) & 0x0f;
    const packed = buf.readUInt16LE(start + (pc + 2) * 2);
    const regs = [packed & 0xf, (packed >>> 4) & 0xf, (packed >>> 8) & 0xf, (packed >>> 12) & 0xf, g];
    return regs.slice(0, count);
  }
  if (op >= 0x74 && op <= 0x78) { // format 3rc: contiguous register range
    const count = (unit >>> 8) & 0xff;
    const first = buf.readUInt16LE(start + (pc + 2) * 2);
    return Array.from({ length: Math.min(count, 32) }, (_, i) => first + i);
  }
  return [];
}

function writtenRegister(buf: Buffer, start: number, pc: number, op: number): number | undefined {
  const unit = buf.readUInt16LE(start + pc * 2);
  if (op === 0x01 || op === 0x04 || op === 0x07 || (op >= 0xb0 && op <= 0xcf)) return (unit >>> 8) & 0x0f;
  if (op === 0x02 || op === 0x05 || op === 0x08 || (op >= 0x0a && op <= 0x0d) ||
      (op >= 0x12 && op <= 0x1c) || (op >= 0x1f && op <= 0x23) ||
      (op >= 0x2d && op <= 0x31) || (op >= 0x44 && op <= 0x4a) ||
      (op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66) ||
      (op >= 0x7b && op <= 0xaf) || (op >= 0xd0 && op <= 0xe2)) return unit >>> 8;
  if (op === 0x03 || op === 0x06 || op === 0x09) return buf.readUInt16LE(start + (pc + 1) * 2);
  return undefined;
}

function movedStringRegister(buf: Buffer, start: number, pc: number, op: number): { dst: number; src: number } | null {
  const unit = buf.readUInt16LE(start + pc * 2);
  if (op === 0x01 || op === 0x07)
    return { dst: (unit >>> 8) & 0x0f, src: (unit >>> 12) & 0x0f };
  if (op === 0x02 || op === 0x08)
    return { dst: unit >>> 8, src: buf.readUInt16LE(start + (pc + 1) * 2) };
  if (op === 0x03 || op === 0x09)
    return { dst: buf.readUInt16LE(start + (pc + 1) * 2), src: buf.readUInt16LE(start + (pc + 2) * 2) };
  return null;
}

function analyzeCodeItem(buf: Buffer, codeOff: number, d: ParsedDex, callerIdx: number):
    { calls: DexCallEdge[]; stringUses: DexStringUse[]; fieldAccesses: DexFieldAccess[]; reflections: DexReflectionEdge[] } | null {
  if (codeOff + 16 > buf.length) return null;
  const insnsSize = buf.readUInt32LE(codeOff + 12);
  const start = codeOff + 16;
  if (start + insnsSize * 2 > buf.length) return null;
  const caller = methodLabel(d.methods[callerIdx], callerIdx);
  const calls: DexCallEdge[] = [], stringUses: DexStringUse[] = [], fieldAccesses: DexFieldAccess[] = [], reflections: DexReflectionEdge[] = [];
  const registerStrings = new Map<number, number>();
  let pc = 0;
  while (pc < insnsSize) {
    const unit = buf.readUInt16LE(start + pc * 2);
    if (unit === 0x0100) { const n = buf.readUInt16LE(start + (pc + 1) * 2); pc += n * 2 + 4; continue; }
    if (unit === 0x0200) { const n = buf.readUInt16LE(start + (pc + 1) * 2); pc += n * 4 + 2; continue; }
    if (unit === 0x0300) { const ew = buf.readUInt16LE(start + (pc + 1) * 2); const n = buf.readUInt32LE(start + (pc + 2) * 2); pc += Math.ceil((n * ew) / 2) + 4; continue; }
    const op = unit & 0xff;
    const width = INSN_W[op];
    if (!width || pc + width > insnsSize) return null;
    const move = movedStringRegister(buf, start, pc, op);
    if (move) {
      const source = registerStrings.get(move.src);
      if (source === undefined) registerStrings.delete(move.dst); else registerStrings.set(move.dst, source);
    } else if (op === 0x1a) { // const-string vAA, string@BBBB
      const reg = unit >>> 8;
      const stringIdx = buf.readUInt16LE(start + (pc + 1) * 2);
      registerStrings.set(reg, stringIdx);
      stringUses.push({ callerIdx, caller, stringIdx, value: d.strings[stringIdx] ?? '' });
    } else if (op === 0x1b) { // const-string/jumbo vAA, string@BBBBBBBB
      const reg = unit >>> 8;
      const stringIdx = buf.readUInt32LE(start + (pc + 1) * 2);
      registerStrings.set(reg, stringIdx);
      stringUses.push({ callerIdx, caller, stringIdx, value: d.strings[stringIdx] ?? '' });
    } else if ((op >= 0x52 && op <= 0x5f) || (op >= 0x60 && op <= 0x6d)) {
      const fieldIdx = buf.readUInt16LE(start + (pc + 1) * 2);
      const f = d.fields[fieldIdx];
      if (f) fieldAccesses.push({
        callerIdx, caller, fieldIdx, field: `${f.cls}->${f.name}:${f.type}`,
        access: ((op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66)) ? 'read' : 'write',
      });
      const dst = writtenRegister(buf, start, pc, op);
      if (dst !== undefined) registerStrings.delete(dst);
    } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
      const calleeIdx = buf.readUInt16LE(start + (pc + 1) * 2);
      const calleeMethod = d.methods[calleeIdx];
      const callee = methodLabel(calleeMethod, calleeIdx);
      calls.push({ callerIdx, caller, calleeIdx, callee });
      if (calleeMethod?.cls === 'Ljava/lang/Class;' && calleeMethod.name === 'forName') {
        const argReg = invokeRegisters(buf, start, pc, op)[0];
        const stringIdx = argReg === undefined ? undefined : registerStrings.get(argReg);
        if (stringIdx !== undefined) {
          const targetClass = d.strings[stringIdx] ?? '';
          if (targetClass) reflections.push({
            callerIdx, caller, api: callee,
            targetClass,
            targetDescriptor: targetClass.startsWith('L') ? targetClass : `L${targetClass.replace(/\./g, '/')};`,
          });
        }
      }
    } else {
      const dst = writtenRegister(buf, start, pc, op);
      if (dst !== undefined) registerStrings.delete(dst);
    }
    pc += width;
  }
  return pc === insnsSize ? { calls, stringUses, fieldAccesses, reflections } : null;
}

// One pass over encoded class_data/code_item structures for the persistent WS-F index.
// It records concrete caller ids, const-string use sites, invoke edges and resolvable
// Class.forName targets. Malformed code_items are counted and excluded, never guessed.
export function analyzeDexCode(buf: Buffer, d: ParsedDex): DexCodeAnalysis {
  const u32 = (o: number) => buf.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  const calls: DexCallEdge[] = [], stringUses: DexStringUse[] = [], fieldAccesses: DexFieldAccess[] = [], reflections: DexReflectionEdge[] = [];
  let methodsWithCode = 0, skipped = 0;
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24);
    if (!cdOff) continue;
    let p = cdOff; let sf, inf, dm, vm;
    [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
    [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(buf, p); [, p] = readUleb128(buf, p); }
    for (const count of [dm, vm]) {
      let methodIdx = 0;
      for (let k = 0; k < count; k++) {
        let diff, access, codeOff;
        [diff, p] = readUleb128(buf, p); methodIdx += diff;
        [access, p] = readUleb128(buf, p); void access;
        [codeOff, p] = readUleb128(buf, p);
        if (!codeOff) continue;
        methodsWithCode++;
        const refs = analyzeCodeItem(buf, codeOff, d, methodIdx);
        if (!refs) { skipped++; continue; }
        calls.push(...refs.calls); stringUses.push(...refs.stringUses); fieldAccesses.push(...refs.fieldAccesses); reflections.push(...refs.reflections);
      }
    }
  }
  return { calls, stringUses, fieldAccesses, reflections, methodsWithCode, skipped };
}

export interface MethodCode { method: string; midx: number; access: number; registers: number; ins: number; outs: number; tries: number; insnsSize: number; insnsHex: string; codeItemHex: string; unresolvable?: string; }
// Extract the runtime code_item bytes of methods matching class(substring)+name.
// This is L.7 passive recovery: after a packer decrypts the in-memory dex, dump it
// (art_dexfiles) and pull the target method's bytecode here.
export function extractMethodCode(buf: Buffer, d: ParsedDex, classPat: string, methodName?: string): MethodCode[] {
  const u32 = (o: number) => buf.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  const methods = d.methods;
  const cp = classPat.toLowerCase();
  const out: MethodCode[] = [];
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24);
    if (!cdOff) continue;
    let p = cdOff;
    let sf, inf, dm, vm;
    [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
    [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(buf, p); [, p] = readUleb128(buf, p); }
    for (const count of [dm, vm]) {
      let midx = 0;
      for (let k = 0; k < count; k++) {
        let diff, af, co;
        [diff, p] = readUleb128(buf, p); midx += diff;
        [af, p] = readUleb128(buf, p);
        [co, p] = readUleb128(buf, p);
        // dm/vm are attacker-controlled ulebs: without this bound a lying count walks the loop for
        // up to 2^32 iterations (the review measured ~60s per class) while holding the request thread.
        if (p > buf.length) break;
        const m = methods[midx];
        if (!m) continue;
        if (!m.cls.toLowerCase().includes(cp)) continue;
        if (methodName && m.name !== methodName) continue;
        if (!co) { out.push({ method: m.cls + '->' + m.name, midx, access: af, registers: 0, ins: 0, outs: 0, tries: 0, insnsSize: 0, insnsHex: '', codeItemHex: '' }); continue; }
        // Full code_item — including the tries[]/encoded_catch_handler_list tail that follows the
        // insns (4-byte aligned) whenever the method has try/catch blocks. An item we cannot walk
        // comes back as '' plus an explicit `unresolvable` reason, never as a silent empty method.
        // The header is only read once the item is known to fit: a code_off pointing past the end
        // used to make readUInt32LE throw (RangeError -> an opaque 500 on the route) before the
        // per-method reason could be reported.
        const ci = readCodeItem(buf, co);
        if (!ci) {
          out.push({ method: m.cls + '->' + m.name, midx, access: af, registers: 0, ins: 0, outs: 0, tries: 0,
                     insnsSize: 0, insnsHex: '', codeItemHex: '',
                     unresolvable: `code_item at 0x${co.toString(16)} is truncated or has a malformed handler list` });
          continue;
        }
        const registers = buf.readUInt16LE(co), ins = buf.readUInt16LE(co + 2), outs = buf.readUInt16LE(co + 4);
        const insnsSize = ci.insnsSize;
        const insnsHex = buf.subarray(co + 16, co + 16 + insnsSize * 2).toString('hex');
        out.push({ method: m.cls + '->' + m.name, midx, access: af, registers, ins, outs, tries: ci.tries, insnsSize, insnsHex,
                   codeItemHex: ci.hex });
      }
    }
  }
  return out;
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
        if (p > buf.length) break;                   // bounded: see extractMethodCode
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
const ALGO_STRING_RE = /(AES|DESede|DES|RSA|Blowfish|ChaCha|HmacSHA?\d*|HmacMD5|SHA-?(1|224|256|384|512)|MD5|PKCS[157]|\/(CBC|GCM|ECB|CTR|CFB)\/|GCM|Base64)/;

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

// ---- unpack support: method-gap analysis + structural standard-DEX rebuild ------------

function writeUleb128(v: number): Buffer {
  const b: number[] = [];
  do { let x = v & 0x7f; v >>>= 7; if (v) x |= 0x80; b.push(x); } while (v);
  return Buffer.from(b);
}
function adler32(buf: Buffer): number {
  let a = 1, b = 0; const MOD = 65521;
  for (let i = 0; i < buf.length; i++) { a = (a + buf[i]) % MOD; b = (b + a) % MOD; }
  return ((b << 16) | a) >>> 0;
}

export interface Coverage {
  total: number; concreteJava: number; native: number; abstract: number;
  basePresent: number; baseEmpty: number; unresolvable: number; recoveryRate: number;
  missing: { midx: number; method: string }[]; missingTotal: number;
  unresolvableMethods: { midx: number; method: string; reason: string }[];
}
// Honest per-method state over the BASE (dumped) dex. Recovery rate is computed over
// concrete Java methods only (native/abstract have no code_item by definition).
export function analyzeCoverage(buf: Buffer, d: ParsedDex): Coverage {
  const u32 = (o: number) => buf.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  const methods = d.methods;
  let total = 0, nat = 0, abs = 0, present = 0, empty = 0, unresolvable = 0, missingTotal = 0;
  const missing: { midx: number; method: string }[] = [];
  const unresolvableMethods: { midx: number; method: string; reason: string }[] = [];
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24); if (!cdOff) continue;
    let p = cdOff; let sf, inf, dm, vm;
    [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
    [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(buf, p); [, p] = readUleb128(buf, p); }
    for (const count of [dm, vm]) {
      let midx = 0;
      for (let k = 0; k < count; k++) {
        let diff, af, co; [diff, p] = readUleb128(buf, p); midx += diff; [af, p] = readUleb128(buf, p); [co, p] = readUleb128(buf, p);
        if (p > buf.length) break;                   // bounded: see extractMethodCode
        total++;
        if (af & 0x0100) { nat++; continue; }       // native
        if (af & 0x0400) { abs++; continue; }        // abstract
        const label = () => { const m = methods[midx]; return m ? m.cls + '->' + m.name : '#' + midx; };
        // "present" means the code_item was actually walked end to end — a code_off that points
        // at a truncated/malformed item is reported as unresolvable (and listed in `missing`, so
        // the recovery path picks it up) instead of counting toward the recovery rate.
        if (co && codeItemEnd(buf, co) != null) { present++; continue; }
        if (co) {
          unresolvable++;
          if (unresolvableMethods.length < 200) unresolvableMethods.push({ midx, method: label(), reason: `code_item at 0x${co.toString(16)} truncated or malformed` });
        } else empty++;
        missingTotal++;                              // the list below is capped; this count is not
        if (missing.length < 5000) missing.push({ midx, method: label() });
      }
    }
  }
  const concreteJava = total - nat - abs;
  return { total, concreteJava, native: nat, abstract: abs, basePresent: present, baseEmpty: empty,
           unresolvable, recoveryRate: concreteJava ? present / concreteJava : 1, missing, missingTotal, unresolvableMethods };
}

// Parse one class_data_item: four uleb counts followed by the encoded field/method lists. Returns
// null when the item runs past the buffer. class_data items are packed back to back with no
// alignment padding, so `end` is exactly where the next one starts.
export interface ClassDataItem {
  sf: number; inf: number; dm: number; vm: number;
  staticFields: [number, number][]; instanceFields: [number, number][];
  direct: { diff: number; af: number; co: number; midx: number }[];
  virt: { diff: number; af: number; co: number; midx: number }[];
  end: number;
}
export function readClassDataItem(buf: Buffer, off: number): ClassDataItem | null {
  if (off < 0 || off >= buf.length) return null;
  let p = off, sf, inf, dm, vm;
  [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
  [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
  if (p > buf.length) return null;
  const pairs = (n: number): [number, number][] => {
    const a: [number, number][] = [];
    for (let k = 0; k < n; k++) { let x, y; [x, p] = readUleb128(buf, p); [y, p] = readUleb128(buf, p); if (p > buf.length) throw new Error('eof'); a.push([x, y]); }
    return a;
  };
  const meths = (n: number) => {
    const a: { diff: number; af: number; co: number; midx: number }[] = [];
    let midx = 0;
    for (let k = 0; k < n; k++) {
      let diff, af, co; [diff, p] = readUleb128(buf, p); midx += diff; [af, p] = readUleb128(buf, p); [co, p] = readUleb128(buf, p);
      if (p > buf.length) throw new Error('eof');
      a.push({ diff, af, co, midx });
    }
    return a;
  };
  try {
    const staticFields = pairs(sf), instanceFields = pairs(inf);
    const direct = meths(dm), virt = meths(vm);
    return { sf, inf, dm, vm, staticFields, instanceFields, direct, virt, end: p };
  } catch { return null; }
}

export interface LayoutCheck { ok: boolean; errors: string[]; mapEntries: number; classDataItems: number; codeItems: number; }
// Structural self-check for a rebuilt dex: the map must exist, list each item type once and be
// sorted by offset; the class_data/code_item regions it names must walk exactly; every class_def
// must point at a listed class_data item and every method's code_off at a listed code_item; and the
// checksum/signature must match the bytes. "The map was rebuilt" is only a claim when this passes.
export function verifyDexLayout(buf: Buffer): LayoutCheck {
  const errors: string[] = [];
  const push = (msg: string) => { if (errors.length < 50) errors.push(msg); };
  let mapEntries = 0, classDataItems = 0, codeItems = 0;
  if (buf.length < 112) { push('not a dex (too short)'); return { ok: false, errors, mapEntries, classDataItems, codeItems }; }
  const u32 = (o: number) => buf.readUInt32LE(o);
  const mapOff = u32(52);
  if (!mapOff || mapOff + 4 > buf.length) { push('map_off is 0 or out of range'); return { ok: false, errors, mapEntries, classDataItems, codeItems }; }
  const n = u32(mapOff);
  mapEntries = n;
  const seen = new Set<number>();
  let last = -1, cdOff = 0, cdCount = 0, ciOff = 0, ciCount = 0;
  for (let i = 0; i < n; i++) {
    const e = mapOff + 4 + i * 12;
    if (e + 12 > buf.length) { push('a map entry runs past the end of the file'); break; }
    const type = buf.readUInt16LE(e), size = buf.readUInt32LE(e + 4), off = buf.readUInt32LE(e + 8);
    if (seen.has(type)) push(`map lists type 0x${type.toString(16)} more than once`);
    seen.add(type);
    if (off < last) push(`map is not sorted by offset (type 0x${type.toString(16)})`);
    last = off;
    if (off > buf.length) push(`map entry 0x${type.toString(16)} points past the end of the file`);
    if (type === 0x2000) { cdOff = off; cdCount = size; }
    if (type === 0x2001) { ciOff = off; ciCount = size; }
  }
  const codeStarts = new Set<number>(), classDataStarts = new Set<number>();
  let p = ciOff;
  for (let i = 0; i < ciCount; i++) {
    const end = codeItemEnd(buf, p);
    if (end == null) { push(`code_item #${i} at 0x${p.toString(16)} does not parse`); break; }
    codeStarts.add(p); codeItems++;
    p = (end + 3) & ~3;                            // code_item entries are 4-byte aligned
  }
  p = cdOff;
  for (let i = 0; i < cdCount; i++) {
    const cd = readClassDataItem(buf, p);
    if (!cd) { push(`class_data_item #${i} at 0x${p.toString(16)} does not parse`); break; }
    classDataStarts.add(p); classDataItems++;
    p = cd.end;
  }
  const classDefsSize = u32(96), classDefsOff = u32(100);
  let sawClassData = false, sawCode = false;
  for (let i = 0; i < classDefsSize; i++) {
    const co = u32(classDefsOff + i * 32 + 24);
    if (!co) continue;
    sawClassData = true;
    if (!classDataStarts.has(co)) push(`class_def #${i} points at class_data 0x${co.toString(16)}, which the map does not list`);
    const cd = readClassDataItem(buf, co);
    if (!cd) { push(`class_def #${i}: class_data at 0x${co.toString(16)} does not parse`); continue; }
    for (const m of [...cd.direct, ...cd.virt]) {
      if (!m.co) continue;
      sawCode = true;
      if (!codeStarts.has(m.co)) push(`method #${m.midx}: code_off 0x${m.co.toString(16)} is not a code_item the map lists`);
    }
  }
  if (sawClassData && cdCount === 0) push('class_defs reference class_data items but the map lists no class_data region');
  if (sawCode && ciCount === 0) push('methods reference code_items but the map lists no code_item region');
  // P2-1: the header's own bookkeeping has to match the bytes too.
  if (u32(32) !== buf.length) push(`file_size (${u32(32)}) does not match the buffer length (${buf.length})`);
  const dataOff = u32(108), dataSize = u32(104);
  if (dataOff > buf.length) push(`data_off (${dataOff}) is past the end of the file`);
  else if (dataOff + dataSize !== buf.length) push(`data_size (${dataSize}) does not cover the data section (file has ${buf.length - dataOff} bytes past data_off)`);
  // P2-2: sections the header says exist must appear in the map, and a class_def/method that points
  // at class_data/code_item must find its region listed - the old `set.size &&` guard skipped the
  // whole check when the map simply lacked the two types.
  const requiredSections: [number, number, string][] = [
    [u32(56), 0x0001, 'string_id'], [u32(64), 0x0002, 'type_id'], [u32(72), 0x0003, 'proto_id'],
    [u32(80), 0x0004, 'field_id'], [u32(88), 0x0005, 'method_id'], [u32(96), 0x0006, 'class_def'],
    [u32(56), 0x2002, 'string_data'],
  ];
  for (const [count, type, name] of requiredSections)
    if (count > 0 && !seen.has(type)) push(`the map does not list ${name} although the header says ${count} exist`);
  if (u32(8) !== adler32(buf.subarray(12))) push('checksum does not match the file bytes');
  if (!createHash('sha1').update(buf.subarray(32)).digest().equals(buf.subarray(12, 32))) push('signature (SHA-1) does not match the file bytes');
  return { ok: errors.length === 0, errors, mapEntries, classDataItems, codeItems };
}

// Structurally merge captured CodeItems (keyed by method_idx) into the base dex. Everything that
// ends up referenced is written at the END of the file and the map_list is rebuilt to name the new
// regions, so the result is a dex whose map describes its own contents (before v5.01 the appended
// items were invisible to the map and only our class_defs walker could find them):
//   [original bytes] [relocated code_items, 4-aligned] [rewritten class_data items] [new map_list]
// Every class_def's class_data_off and every method's code_off is patched to the new copy; the
// original class_data/code_item bytes stay behind as unreferenced slack that the map no longer
// lists. A dex without a map_list still rebuilds, but reports mapRebuilt:false.
// Fixes file_size / data_size / map_off / signature (SHA-1) / checksum (Adler-32).
export function rebuildStandardDex(base: Buffer, captures: { midx: number; codeItemHex: string }[]):
    { dex: Buffer; injected: number; classesRewritten: number; relocatedCodeItems: number; relocatedClassData: number;
      mapRebuilt: boolean; mapEntries: number; unmatchedCaptures: number; skippedCaptures: number[];
      duplicateCaptures: number[]; layout: LayoutCheck } {
  const capMap = new Map<number, Buffer>();
  const skippedCaptures: number[] = [];
  const duplicateCaptures: number[] = [];
  for (const c of captures) {
    if (!c.codeItemHex) { skippedCaptures.push(c.midx); continue; }   // reported, never silently dropped
    if (capMap.has(c.midx)) { duplicateCaptures.push(c.midx); continue; }   // first wins; the rest are reported
    const ci = Buffer.from(c.codeItemHex, 'hex');
    // Fail loud: a capture that is not a complete code_item (truncated insns, half a handler
    // list, odd-length hex) would be appended verbatim and produce a dex that only looks rebuilt.
    const parsed = readCodeItem(ci, 0);
    if (!parsed || parsed.size !== ci.length) {
      throw new Error(`capture for method #${c.midx} is not a complete code_item ` +
                      `(${parsed ? `${parsed.size}B parsed of ${ci.length}B` : `${ci.length}B, unparseable`})`);
    }
    capMap.set(c.midx, ci);
  }
  if (base.length < 112) throw new Error('not a dex (too short)');
  const u32 = (o: number) => base.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  const chunks: Buffer[] = [base]; let len = base.length;
  const pad = (align: number) => { const r = len % align; if (r) { const q = Buffer.alloc(align - r); chunks.push(q); len += q.length; } };

  // pass 1: every class_data_item the file references
  const classes: { idx: number; cd: ClassDataItem }[] = [];
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24);
    if (!cdOff) continue;
    const cd = readClassDataItem(base, cdOff);
    if (!cd) throw new Error(`class #${i}: class_data_item at 0x${cdOff.toString(16)} is truncated or malformed`);
    classes.push({ idx: i, cd });
  }

  // pass 2: relocate every code_item that is still referenced (a capture wins over the base copy)
  const newCodeOff = new Map<number, number>();
  const captured = new Set<number>();
  let injected = 0, relocatedCodeItems = 0, codeItemStart = 0;
  for (const { cd } of classes) {
    for (const m of [...cd.direct, ...cd.virt]) {
      const cap = capMap.get(m.midx);
      if (!m.co && !cap) continue;
      if (newCodeOff.has(m.midx)) continue;
      let item: Buffer;
      if (cap) { item = cap; injected++; captured.add(m.midx); }
      else {
        const ci = readCodeItem(base, m.co);
        if (!ci) throw new Error(`method #${m.midx}: code_item at 0x${m.co.toString(16)} is truncated or malformed`);
        item = Buffer.from(ci.hex, 'hex');
      }
      pad(4);
      if (!relocatedCodeItems) codeItemStart = len;
      newCodeOff.set(m.midx, len);
      chunks.push(item); len += item.length; relocatedCodeItems++;
    }
  }

  // pass 3: rewrite every class_data_item with the relocated code_off values
  const classDataStart = len;
  const newCdOff = new Map<number, number>();
  let relocatedClassData = 0, classesRewritten = 0;
  for (const { idx, cd } of classes) {
    const parts: Buffer[] = [writeUleb128(cd.sf), writeUleb128(cd.inf), writeUleb128(cd.dm), writeUleb128(cd.vm)];
    for (const [x, y] of [...cd.staticFields, ...cd.instanceFields]) parts.push(writeUleb128(x), writeUleb128(y));
    let touched = false;
    const emit = (arr: typeof cd.direct) => {
      for (const m of arr) {
        if (captured.has(m.midx)) touched = true;
        parts.push(writeUleb128(m.diff), writeUleb128(m.af), writeUleb128(newCodeOff.get(m.midx) ?? m.co));
      }
    };
    emit(cd.direct); emit(cd.virt);
    if (touched) classesRewritten++;
    const bytes = Buffer.concat(parts);
    newCdOff.set(idx, len);
    chunks.push(bytes); len += bytes.length; relocatedClassData++;
  }

  // pass 4: the new map_list names the two relocated regions (plus every untouched entry)
  const mapOff = u32(52);
  let mapRebuilt = false, mapEntries = 0, newMapOff = 0;
  if (mapOff && mapOff + 4 <= base.length) {
    const n = base.readUInt32LE(mapOff);
    const entries: { type: number; size: number; off: number }[] = [];
    let readEntries = 0;
    for (let i = 0; i < n; i++) {
      const e = mapOff + 4 + i * 12;
      if (e + 12 > base.length) break;
      readEntries++;
      const type = base.readUInt16LE(e), size = base.readUInt32LE(e + 4), off = base.readUInt32LE(e + 8);
      if (type === 0x1000 || type === 0x2000 || type === 0x2001) continue;   // map_list / the two relocated types
      entries.push({ type, size, off });
    }
    // A truncated source map would silently produce a NEW map that lists only the entries we managed
    // to read (the sandbox dex lost 11 of 17 types in review testing) while still reporting
    // mapRebuilt:true. Refuse instead: the caller's input is damaged, and a green rebuild flag on an
    // incomplete map is exactly the kind of lie this work exists to remove.
    if (readEntries !== n) {
      throw new Error(`the base dex map_list is truncated (${readEntries} of ${n} entries readable) - refusing to claim a rebuilt map`);
    }
    pad(4);                                        // map_list itself is 4-byte aligned
    newMapOff = len;
    if (relocatedCodeItems) entries.push({ type: 0x2001, size: relocatedCodeItems, off: codeItemStart });
    if (relocatedClassData) entries.push({ type: 0x2000, size: relocatedClassData, off: classDataStart });
    entries.push({ type: 0x1000, size: 1, off: newMapOff });
    const mapBuf = Buffer.alloc(4 + entries.length * 12);
    mapBuf.writeUInt32LE(entries.length, 0);
    entries.forEach((en, i) => {
      const o = 4 + i * 12;
      mapBuf.writeUInt16LE(en.type, o); mapBuf.writeUInt32LE(en.size, o + 4); mapBuf.writeUInt32LE(en.off, o + 8);
    });
    chunks.push(mapBuf); len += mapBuf.length;
    mapRebuilt = true; mapEntries = entries.length;
  }

  const out = Buffer.concat(chunks);
  for (const [idx, off] of newCdOff) out.writeUInt32LE(off, classDefsOff + idx * 32 + 24);
  if (mapRebuilt) out.writeUInt32LE(newMapOff, 52);                    // header map_off
  out.writeUInt32LE(out.length, 32);                                   // file_size
  const dataOff = out.readUInt32LE(108);
  if (dataOff && dataOff < out.length) out.writeUInt32LE(out.length - dataOff, 104);  // data_size
  createHash('sha1').update(out.subarray(32)).digest().copy(out, 12);  // signature
  out.writeUInt32LE(adler32(out.subarray(12)), 8);                     // checksum
  const matched = new Set<number>();
  for (const { cd } of classes) for (const m of [...cd.direct, ...cd.virt]) if (capMap.has(m.midx)) matched.add(m.midx);
  return { dex: out, injected, classesRewritten, relocatedCodeItems, relocatedClassData,
           mapRebuilt, mapEntries, unmatchedCaptures: capMap.size - matched.size, skippedCaptures, duplicateCaptures,
           layout: verifyDexLayout(out) };
}

// Return the full code_item bytes for a given method_idx, or '' when this image has nothing
// usable for it. Used to lift a CodeItem out of a RESTORED snapshot without assuming anything
// about the base image. codeItemOfDetailed() carries the reason for the '' case.
export function codeItemOf(buf: Buffer, midx: number): string {
  const r = codeItemOfDetailed(buf, midx);
  return r.ok ? r.hex : '';
}
export function codeItemOfDetailed(buf: Buffer, midx: number):
    { ok: true; hex: string; size: number; tries: number } | { ok: false; reason: string } {
  const u32 = (o: number) => buf.readUInt32LE(o);
  if (buf.length < 112) return { ok: false, reason: 'not a dex (too short)' };
  const classDefsSize = u32(96), classDefsOff = u32(100);
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24); if (!cdOff) continue;
    let p = cdOff; let sf, inf, dm, vm;
    [sf, p] = readUleb128(buf, p); [inf, p] = readUleb128(buf, p);
    [dm, p] = readUleb128(buf, p); [vm, p] = readUleb128(buf, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(buf, p); [, p] = readUleb128(buf, p); }
    for (const count of [dm, vm]) {
      let mi = 0;
      for (let k = 0; k < count; k++) {
        let diff, af, co; [diff, p] = readUleb128(buf, p); mi += diff; [af, p] = readUleb128(buf, p); [co, p] = readUleb128(buf, p);
        if (p > buf.length) break;                   // bounded: see extractMethodCode
        if (mi === midx) {
          if (!co) return { ok: false, reason: 'code_off is 0 (method extracted or has no code)' };
          const ci = readCodeItem(buf, co);
          if (!ci) return { ok: false, reason: `code_item at 0x${co.toString(16)} is truncated or has a malformed handler list` };
          return { ok: true, hex: ci.hex, size: ci.size, tries: ci.tries };
        }
      }
    }
  }
  return { ok: false, reason: 'method_idx not found in this dex' };
}

// Zero a method's code_off IN PLACE (redundant-uleb of the SAME byte length, so class_data
// doesn't shift) — simulates a gen-2 "extracted" method for testing the recovery loop.
export function stripMethodCode(buf: Buffer, midx: number): Buffer {
  const out = Buffer.from(buf);
  const u32 = (o: number) => out.readUInt32LE(o);
  const classDefsSize = u32(96), classDefsOff = u32(100);
  for (let i = 0; i < classDefsSize; i++) {
    const cdOff = u32(classDefsOff + i * 32 + 24); if (!cdOff) continue;
    let p = cdOff; let sf, inf, dm, vm;
    [sf, p] = readUleb128(out, p); [inf, p] = readUleb128(out, p);
    [dm, p] = readUleb128(out, p); [vm, p] = readUleb128(out, p);
    for (let k = 0; k < sf + inf; k++) { [, p] = readUleb128(out, p); [, p] = readUleb128(out, p); }
    for (const count of [dm, vm]) {
      let mi = 0;
      for (let k = 0; k < count; k++) {
        let diff, af; [diff, p] = readUleb128(out, p); mi += diff; [af, p] = readUleb128(out, p);
        const coStart = p; let co; [co, p] = readUleb128(out, p);
        if (p > out.length) break;                   // bounded: see extractMethodCode
        if (mi === midx && co) {
          const len = p - coStart;                        // keep byte count identical
          for (let b = 0; b < len - 1; b++) out[coStart + b] = 0x80;
          out[coStart + len - 1] = 0x00;                  // redundant-zero uleb
          createHash('sha1').update(out.subarray(32)).digest().copy(out, 12);
          out.writeUInt32LE(adler32(out.subarray(12)), 8);
          return out;
        }
      }
    }
  }
  return out;
}

export interface RecoverResult { recovered: number; stillMissing: number; missingTotal: number; missingListed: number;
  captured: { midx: number; method: string }[];
  unresolvable: { midx: number; method: string; reason: string }[]; }
// Passive gen-2 recovery: lift CodeItems for BASE_EMPTY methods out of a RESTORED snapshot
// (the runtime-captured image) and merge them into the base — never assumes the base itself
// was refilled. Returns the captures ready for rebuildStandardDex.
export function recoverFromSnapshots(base: Buffer, restored: Buffer, d: ParsedDex):
    { captures: { midx: number; codeItemHex: string }[]; report: RecoverResult } {
  const cov = analyzeCoverage(base, d);
  const captures: { midx: number; codeItemHex: string }[] = [];
  const captured: { midx: number; method: string }[] = [];
  const unresolvable: { midx: number; method: string; reason: string }[] = [];
  for (const m of cov.missing) {
    const ci = codeItemOfDetailed(restored, m.midx);
    if (ci.ok) { captures.push({ midx: m.midx, codeItemHex: ci.hex }); captured.push(m); }
    else unresolvable.push({ midx: m.midx, method: m.method, reason: ci.reason });
  }
  return { captures, report: { recovered: captures.length, stillMissing: cov.missingTotal - captures.length,
                               missingTotal: cov.missingTotal, missingListed: cov.missing.length, captured, unresolvable } };
}

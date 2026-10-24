// Host-only, explicitly paired crypto evidence. A symbol name, nearby timestamp or common TID
// is never an algorithm proof. Keep raw material on disk; ordinary replies contain fingerprints.
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const CRYPTO_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'hmac-md5', 'hmac-sha1',
  'hmac-sha256', 'hmac-sha512', 'xor', 'add-xor', 'hex-lower', 'hex-upper', 'base64', 'identity'] as const;
export type CryptoAlgorithm = typeof CRYPTO_ALGORITHMS[number];
export const CRYPTO_EVIDENCE_LIMITS = { observations: 128, chunks: 16, fieldBytes: 65536,
  totalBytes: 1048576, links: 256, page: 16, records: 64, fileBytes: 8388608, diskBytes: 67108864 } as const;
export const CRYPTO_EVIDENCE_CAVEAT = 'Verification covers only supplied complete, explicitly paired bytes. ' +
  'A verified intermediate primitive is not a verified final signature. Byte-equality links prove equal ' +
  'content, not execution order, causal flow, parameter derivation or coverage of missing captures.';

export interface EvidenceSource {
  kind: 'capture' | 'hook-window' | 'oracle' | 'manual' | 'derived';
  session?: string; pid?: number; tid?: number; hookId?: number; seq?: number;
  callId?: string; captureId?: number | string; phase?: string; slot?: string; note?: string;
}
export interface EvidenceBytes {
  /** Exactly one encoding. utf8 is literal text; hex-lower/base64 outputs are themselves text bytes. */
  hex?: string; b64?: string; utf8?: string;
  /** Omission is unknown, not complete. expectedBytes can independently establish the length. */
  complete?: boolean; expectedBytes?: number; source: EvidenceSource;
}
export interface CryptoObservation {
  id: string; input?: EvidenceBytes | EvidenceBytes[]; output?: EvidenceBytes; key?: EvidenceBytes;
  params?: { add?: EvidenceBytes; xor?: EvidenceBytes };
  algorithms?: CryptoAlgorithm[]; role?: 'intermediate' | 'final' | 'unspecified'; parameterLabel?: string;
  /** For bytes paired by an analyst rather than a recorded invocation, require an explanation.
   * Explicitly contradictory recorded identities are still rejected. */
  pairing?: { basis: 'analyst'; note: string };
}
export interface CryptoEvidenceInput {
  observations: CryptoObservation[]; candidates?: CryptoAlgorithm[];
  loss?: { complete?: boolean; dropped?: number; storeLoss?: string | null; note?: string };
}
type Decoded = { bytes?: Buffer; complete: boolean; reason?: string; source?: EvidenceSource };
type Check = { algorithm: CryptoAlgorithm; status: 'matched' | 'mismatched' | 'unavailable'; reason?: string;
  parameterFingerprint?: string; expected?: { bytes: number; sha256: string } };
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const boundedInt = (n: unknown, fallback: number, lo: number, hi: number, label: string): number => {
  if (n === undefined) return fallback;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < lo || n > hi) throw new Error(`${label} must be ${lo}..${hi}`);
  return n;
};

function decode(value: EvidenceBytes | undefined): Decoded {
  if (!value || typeof value !== 'object') return { complete: false, reason: 'missing bytes' };
  const source = value.source;
  if (!source || !['capture', 'hook-window', 'oracle', 'manual', 'derived'].includes(source.kind))
    return { complete: false, reason: 'missing or invalid parameter/data source' };
  const fields = ['hex', 'b64', 'utf8'].filter(k => value[k] !== undefined);
  if (fields.length !== 1 || typeof value[fields[0]] !== 'string') return { complete: false, source, reason: 'choose exactly one byte encoding' };
  const text = value[fields[0]] as string;
  // Check the encoded length before allocating a Buffer.
  if (text.length > CRYPTO_EVIDENCE_LIMITS.fieldBytes * 2) throw new Error('evidence field exceeds byte limit');
  let bytes: Buffer;
  if (fields[0] === 'hex') {
    if (text.length % 2 || !/^[0-9a-f]*$/i.test(text)) return { complete: false, source, reason: 'invalid hex' };
    bytes = Buffer.from(text, 'hex');
  } else if (fields[0] === 'b64') {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text))
      return { complete: false, source, reason: 'invalid canonical base64' };
    bytes = Buffer.from(text, 'base64');
    if (bytes.toString('base64') !== text) return { complete: false, source, reason: 'invalid canonical base64' };
  } else bytes = Buffer.from(text, 'utf8');
  if (bytes.length > CRYPTO_EVIDENCE_LIMITS.fieldBytes) throw new Error('evidence field exceeds byte limit');
  if (value.expectedBytes !== undefined && (!Number.isSafeInteger(value.expectedBytes) || value.expectedBytes < 0))
    return { bytes, complete: false, source, reason: 'invalid expectedBytes' };
  if (value.expectedBytes !== undefined && bytes.length !== value.expectedBytes)
    return { bytes, complete: false, source, reason: `length ${bytes.length} differs from expected ${value.expectedBytes}` };
  if (value.complete === false) return { bytes, complete: false, source, reason: 'source reports incomplete/truncated bytes' };
  if (value.complete !== true && value.expectedBytes === undefined)
    return { bytes, complete: false, source, reason: 'byte completeness was not established' };
  return { bytes, complete: true, source };
}

function descriptor(d: Decoded) {
  return { ...(d.bytes ? { bytes: d.bytes.length, sha256: sha(d.bytes) } : {}), complete: d.complete,
    ...(d.reason ? { reason: d.reason } : {}), ...(d.source ? { source: d.source } : {}) };
}

/** Match only recorded identities. Same-thread/time alone deliberately has no branch here. */
function pairingOf(data: Decoded[], observation: CryptoObservation): { paired: boolean; basis: string; reason?: string } {
  const sources = data.map(d => d.source).filter((s): s is EvidenceSource => !!s);
  const conflict = (key: keyof EvidenceSource) => new Set(sources.map(s => s[key]).filter(v => v !== undefined && v !== '')).size > 1;
  if (conflict('session') || conflict('pid')) return { paired: false, basis: 'unpaired', reason: 'input/output have conflicting session or PID identities' };
  const sharedCall = sources.length === data.length && sources.every(s => s.session && s.callId &&
    s.session === sources[0].session && s.callId === sources[0].callId);
  if (sharedCall) return { paired: true, basis: 'shared-call-id' };
  if (conflict('callId') || conflict('tid') || conflict('hookId') || conflict('seq'))
    return { paired: false, basis: 'unpaired', reason: 'input/output have conflicting invocation identities; no shared outer callId' };
  if (sources.length === data.length && sources.every(s => s.session && s.captureId !== undefined &&
      s.captureId === sources[0].captureId && s.session === sources[0].session))
    return { paired: true, basis: 'single-rich-capture' };
  if (sources.length === data.length && sources.every(s => s.session && s.tid !== undefined && s.hookId !== undefined && s.seq !== undefined &&
      s.session === sources[0].session && s.tid === sources[0].tid && s.hookId === sources[0].hookId && s.seq === sources[0].seq))
    return { paired: true, basis: 'same-hook-invocation' };
  if (observation.pairing?.basis === 'analyst' && typeof observation.pairing.note === 'string' && observation.pairing.note.trim())
    return { paired: true, basis: 'analyst-declared', reason: observation.pairing.note };
  return { paired: false, basis: 'unpaired', reason: 'need shared callId, same hook invocation, rich capture or explained explicit pairing' };
}

function algorithmsOf(a: unknown, keyed: boolean): CryptoAlgorithm[] {
  const values = a === undefined ? ['md5', 'sha1', 'sha256', 'sha512', ...(keyed ? ['hmac-md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'] : [])] : a;
  if (!Array.isArray(values) || !values.length || values.length > CRYPTO_ALGORITHMS.length || values.some(v => !CRYPTO_ALGORITHMS.includes(v)))
    throw new Error('algorithms must be a non-empty list of supported explicit candidates');
  return [...new Set(values)] as CryptoAlgorithm[];
}

function compute(algorithm: CryptoAlgorithm, input: Buffer, key: Decoded, add: Decoded, xor: Decoded) {
  const needed = algorithm.startsWith('hmac-') ? [['key', key] as const]
    : algorithm === 'xor' ? [['xor', xor] as const]
    : algorithm === 'add-xor' ? [['add', add] as const, ['xor', xor] as const] : [];
  for (const [name, d] of needed) if (!d.complete || !d.bytes) return { reason: `${name}: ${d.reason ?? 'missing bytes'}` };
  const fp = createHash('sha256').update(algorithm);
  for (const [name, d] of needed) fp.update(`:${name}:${d.bytes!.length}:`).update(d.bytes!);
  const parameterFingerprint = fp.digest('hex');
  let expected: Buffer;
  if (algorithm.startsWith('hmac-')) expected = createHmac(algorithm.slice(5), key.bytes!).update(input).digest();
  else if (['md5', 'sha1', 'sha256', 'sha512'].includes(algorithm)) expected = createHash(algorithm).update(input).digest();
  else if (algorithm === 'hex-lower' || algorithm === 'hex-upper') expected = Buffer.from(algorithm === 'hex-lower' ? input.toString('hex') : input.toString('hex').toUpperCase(), 'ascii');
  else if (algorithm === 'base64') expected = Buffer.from(input.toString('base64'), 'ascii');
  else if (algorithm === 'identity') expected = Buffer.from(input);
  else {
    if (xor.bytes!.length !== input.length || (algorithm === 'add-xor' && add.bytes!.length !== input.length))
      return { reason: 'bytewise masks must have exactly the input length; mask repetition is never inferred' };
    expected = Buffer.alloc(input.length);
    for (let i = 0; i < input.length; i++) expected[i] = ((input[i] + (algorithm === 'add-xor' ? add.bytes![i] : 0)) & 255) ^ xor.bytes![i];
  }
  return { expected, parameterFingerprint };
}

export function analyzeCryptoEvidence(input: CryptoEvidenceInput) {
  if (!input || !Array.isArray(input.observations) || !input.observations.length || input.observations.length > CRYPTO_EVIDENCE_LIMITS.observations)
    throw new Error(`observations must contain 1..${CRYPTO_EVIDENCE_LIMITS.observations} explicit pairs`);
  if (JSON.stringify(input).length > CRYPTO_EVIDENCE_LIMITS.fileBytes / 2) throw new Error('evidence request exceeds encoded size limit');
  if (input.candidates !== undefined) algorithmsOf(input.candidates, false);
  if (input.loss?.dropped !== undefined && (!Number.isSafeInteger(input.loss.dropped) || input.loss.dropped < 0)) throw new Error('loss.dropped must be nonnegative');
  const ids = new Set<string>(); let totalBytes = 0;
  const byAlgorithm = new Map<string, { algorithm: string; tested: number; matched: number; mismatched: number; unavailable: number }>();
  const parameterGroups = new Map<string, { algorithm: string; fingerprint: string; labels: string[]; observations: string[]; keySources: EvidenceSource[] }>();
  const prepared = input.observations.map(o => {
    if (!o || typeof o.id !== 'string' || !o.id.trim() || o.id.length > 128 || ids.has(o.id)) throw new Error('each observation needs a unique id of 1..128 characters');
    ids.add(o.id);
    if (o.role !== undefined && !['intermediate', 'final', 'unspecified'].includes(o.role)) throw new Error('invalid observation role');
    const chunks = o.input === undefined ? [] : Array.isArray(o.input) ? o.input : [o.input];
    if (chunks.length > CRYPTO_EVIDENCE_LIMITS.chunks) throw new Error('too many input chunks');
    const parts = chunks.map(decode), output = decode(o.output), key = decode(o.key), add = decode(o.params?.add), xor = decode(o.params?.xor);
    for (const d of [...parts, output, key, add, xor]) totalBytes += d.bytes?.length ?? 0;
    if (totalBytes > CRYPTO_EVIDENCE_LIMITS.totalBytes) throw new Error('evidence request exceeds total byte limit');
    const merged = parts.length && parts.every(d => d.complete && d.bytes) ? Buffer.concat(parts.map(d => d.bytes!)) : undefined;
    const pairing = parts.length ? pairingOf([...parts, output], o) : { paired: false, basis: 'unpaired', reason: 'missing input' };
    const unavailable = !parts.length ? 'missing input' : !merged ? 'input: ' + parts.filter(d => !d.complete).map(d => d.reason).join('; ')
      : !output.complete || !output.bytes ? 'output: ' + (output.reason ?? 'missing bytes') : !pairing.paired ? pairing.reason : undefined;
    const checks: Check[] = algorithmsOf(o.algorithms ?? input.candidates, !!o.key).map(algorithm => {
      let check: Check;
      if (unavailable) check = { algorithm, status: 'unavailable', reason: unavailable };
      else {
        const computed = compute(algorithm, merged!, key, add, xor);
        check = computed.expected ? { algorithm, status: computed.expected.equals(output.bytes!) ? 'matched' : 'mismatched',
          parameterFingerprint: computed.parameterFingerprint, expected: { bytes: computed.expected.length, sha256: sha(computed.expected) } }
          : { algorithm, status: 'unavailable', reason: computed.reason };
      }
      const group = byAlgorithm.get(algorithm) ?? { algorithm, tested: 0, matched: 0, mismatched: 0, unavailable: 0 };
      group[check.status]++; if (check.status !== 'unavailable') group.tested++;
      byAlgorithm.set(algorithm, group);
      if (check.parameterFingerprint) {
        const p = parameterGroups.get(check.parameterFingerprint) ?? { algorithm, fingerprint: check.parameterFingerprint, labels: [], observations: [], keySources: [] };
        if (o.parameterLabel && !p.labels.includes(o.parameterLabel)) p.labels.push(o.parameterLabel);
        p.observations.push(o.id);
        if (algorithm.startsWith('hmac-') && key.source && !p.keySources.some(s => JSON.stringify(s) === JSON.stringify(key.source))) p.keySources.push(key.source);
        parameterGroups.set(check.parameterFingerprint, p);
      }
      return check;
    });
    return { o, parts, merged, output, key, add, xor, pairing, checks };
  });
  const contentLinks: Array<{ from: string; to: string; destination: string; bytes: number; sha256: string; sharedCallId: boolean }> = [];
  let totalLinks = 0;
  const outputs = new Map<string, typeof prepared>();
  for (const p of prepared) if (p.output.complete && p.output.bytes?.length) {
    const h = sha(p.output.bytes); const bucket = outputs.get(h) ?? []; bucket.push(p); outputs.set(h, bucket);
  }
  for (const p of prepared) for (const [destination, bytes, source] of [
    ['input', p.merged, p.parts[0]?.source], ['key', p.key.complete ? p.key.bytes : undefined, p.key.source],
    ['add', p.add.complete ? p.add.bytes : undefined, p.add.source], ['xor', p.xor.complete ? p.xor.bytes : undefined, p.xor.source],
  ] as Array<[string, Buffer | undefined, EvidenceSource | undefined]>) {
    if (!bytes?.length) continue;
    const h = sha(bytes);
    for (const from of outputs.get(h) ?? []) {
      if (from.o.id === p.o.id || !from.output.bytes!.equals(bytes)) continue;
      totalLinks++;
      if (contentLinks.length < CRYPTO_EVIDENCE_LIMITS.links) contentLinks.push({ from: from.o.id, to: p.o.id, destination,
        bytes: bytes.length, sha256: h, sharedCallId: destination === 'input'
          ? p.parts.every(part => !!(part.source?.session && part.source.callId && part.source.session === from.output.source?.session && part.source.callId === from.output.source?.callId))
          : !!(source?.session && source.callId && source.session === from.output.source?.session && source.callId === from.output.source?.callId) });
    }
  }
  const rows = prepared.map(p => ({ id: p.o.id, role: p.o.role ?? 'unspecified', parameterLabel: p.o.parameterLabel,
    pairing: p.pairing, input: p.parts.map(descriptor), output: descriptor(p.output),
    ...(p.o.key ? { key: descriptor(p.key) } : {}),
    ...(p.o.params ? { parameters: { ...(p.o.params.add ? { add: descriptor(p.add) } : {}), ...(p.o.params.xor ? { xor: descriptor(p.xor) } : {}) } } : {}),
    checks: p.checks, matched: p.checks.filter(c => c.status === 'matched').map(c => c.algorithm) }));
  const tested = rows.filter(r => r.checks.some(c => c.status !== 'unavailable')).length;
  const matched = rows.filter(r => r.matched.length > 0).length;
  const loss = input.loss ?? {};
  const analysisComplete = !rows.some(r => r.checks.some(c => c.status === 'unavailable'));
  const captureCollectionComplete = loss.complete === false || !!loss.dropped || !!loss.storeLoss ? false
    : loss.complete === true ? true : null;
  return { version: 1 as const, caveat: CRYPTO_EVIDENCE_CAVEAT,
    scope: 'provided paired observations only; final/intermediate roles are caller declarations',
    analysisComplete, captureCollectionComplete, complete: analysisComplete && captureCollectionComplete === true,
    loss, counts: { observations: rows.length, paired: rows.filter(r => r.pairing.paired).length, tested, matched,
      mismatched: tested - matched, unavailable: rows.length - tested, bytes: totalBytes },
    algorithms: [...byAlgorithm.values()], parameterGroups: [...parameterGroups.values()], rows,
    contentLinks, totalLinks, linksTruncated: totalLinks > contentLinks.length };
}
export type CryptoEvidenceReport = ReturnType<typeof analyzeCryptoEvidence>;

export interface EvidenceCapture {
  id: number | string; sessionId?: string; pid?: number; tid?: number; hookId?: number; seq?: number;
  phase?: string; func: string; hex: string; inl?: number; keyHex?: string; outHex?: string;
}
export interface CaptureByteSelector {
  captureId: number | string; field?: 'payload' | 'key' | 'output' | 'mem';
  reg?: string; offset?: number; windowIndex?: number;
  /** For key/output fields the old capture format carries no original length: caller must supply it. */
  expectedBytes?: number;
}

/** Explicit adapter, not an automatic pairer: never choose "the closest" record or fallback hook. */
export function selectCaptureBytes(records: readonly EvidenceCapture[], selector: CaptureByteSelector): EvidenceBytes {
  const matches = records.filter(c => c.id === selector.captureId);
  if (matches.length !== 1) throw new Error(`captureId ${selector.captureId} is missing or ambiguous`);
  const c = matches[0], field = selector.field ?? 'payload';
  if (!['payload', 'key', 'output', 'mem'].includes(field)) throw new Error('invalid capture field');
  const source: EvidenceSource = { kind: field === 'mem' ? 'hook-window' : 'capture', captureId: c.id,
    session: c.sessionId, pid: c.pid, tid: c.tid, hookId: c.hookId, seq: c.seq, phase: c.phase, slot: field };
  if (field !== 'mem') {
    const hex = field === 'payload' ? c.hex : field === 'key' ? c.keyHex : c.outHex;
    if (hex === undefined) return { hex: '', complete: false, source: { ...source, note: `missing ${field} field` } };
    const recordedLength = field === 'payload' ? c.inl : undefined;
    if (selector.expectedBytes !== undefined && recordedLength !== undefined && selector.expectedBytes !== recordedLength)
      throw new Error('expectedBytes disagrees with captured original length; truncated payloads cannot be relabeled complete');
    const expectedBytes = recordedLength ?? selector.expectedBytes;
    return { hex, ...(expectedBytes !== undefined ? { expectedBytes } : {}), source };
  }
  if (c.func !== 'NATIVE_HOOK_MEM' || !/^(?:[0-9a-f]{2})*$/i.test(c.hex)) throw new Error('mem selector requires an intact NATIVE_HOOK_MEM record');
  let event: any;
  try { event = JSON.parse(Buffer.from(c.hex, 'hex').toString('utf8')); } catch { throw new Error('native memory record is truncated or invalid JSON'); }
  const windows = Array.isArray(event.mem) ? event.mem : [];
  let selected: any;
  if (selector.windowIndex !== undefined) {
    const i = boundedInt(selector.windowIndex, 0, 0, windows.length - 1, 'windowIndex'); selected = windows[i];
    if ((selector.reg !== undefined && selected.reg !== selector.reg) || (selector.offset !== undefined && Number(selected.offset ?? 0) !== selector.offset))
      throw new Error('windowIndex disagrees with reg/offset selector');
  } else {
    if (typeof selector.reg !== 'string' || !selector.reg) throw new Error('mem selector requires reg or windowIndex');
    const selectedWindows = windows.filter(w => w.reg === selector.reg && Number(w.offset ?? 0) === (selector.offset ?? 0));
    if (selectedWindows.length !== 1) throw new Error('memory window is missing or ambiguous; provide windowIndex');
    selected = selectedWindows[0];
  }
  for (const k of ['hookId', 'seq'] as const) {
    if (c[k] !== undefined && event[k] !== undefined && c[k] !== event[k]) throw new Error(`capture metadata ${k} disagrees with payload`);
    if (event[k] !== undefined) source[k] = Number(event[k]);
  }
  source.phase = event.phase ?? source.phase;
  if (c.phase !== undefined && event.phase !== undefined && c.phase !== event.phase) throw new Error('capture metadata phase disagrees with payload');
  source.slot = `mem:${selected.reg ?? '?'}:${Number(selected.offset ?? 0)}`;
  if (selected.error) source.note = String(selected.error);
  if (selector.expectedBytes !== undefined && selected.requested !== undefined && selector.expectedBytes !== selected.requested)
    throw new Error('expectedBytes disagrees with recorded requested window length');
  const expectedBytes = selected.requested ?? selector.expectedBytes;
  const gotMismatch = selected.got !== undefined && selected.got !== (typeof selected.hex === 'string' ? selected.hex.length / 2 : 0);
  return { hex: typeof selected.hex === 'string' ? selected.hex : '',
    complete: selected.error || selected.short === true || gotMismatch ? false : undefined,
    ...(expectedBytes !== undefined ? { expectedBytes } : {}), source };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function folder(dataDir: string) { return join(resolve(dataDir), 'crypto-evidence'); }
function fileOf(dataDir: string, id: string) {
  if (typeof id !== 'string' || !UUID.test(id)) throw new Error('invalid crypto evidence id');
  return join(folder(dataDir), `${id}.json`);
}
function files(dataDir: string) {
  let names: string[];
  try { names = readdirSync(folder(dataDir)).filter(n => n.endsWith('.json') && UUID.test(n.slice(0, -5))); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []; throw e; }
  return names.map(name => ({ name, path: join(folder(dataDir), name) }));
}
function load(dataDir: string, id: string): { id: string; createdAt: number; label: string; input: CryptoEvidenceInput; report: CryptoEvidenceReport } {
  const path = fileOf(dataDir, id);
  if (statSync(path).size > CRYPTO_EVIDENCE_LIMITS.fileBytes) throw new Error('stored evidence exceeds file limit');
  const saved = JSON.parse(readFileSync(path, 'utf8'));
  if (saved.version !== 1 || saved.id !== id || !Array.isArray(saved.report?.rows)) throw new Error('invalid crypto evidence record');
  return saved;
}
function summary(saved: { id: string; createdAt: number; label: string; report: CryptoEvidenceReport }) {
  const r = saved.report;
  return { id: saved.id, createdAt: saved.createdAt, label: saved.label, complete: r.complete,
    analysisComplete: r.analysisComplete, captureCollectionComplete: r.captureCollectionComplete, counts: r.counts,
    loss: r.loss, algorithms: r.algorithms, parameterGroups: r.parameterGroups.map(g => ({ algorithm: g.algorithm,
      fingerprint: g.fingerprint, labels: g.labels, observations: g.observations.length })),
    totalLinks: r.totalLinks, linksTruncated: r.linksTruncated, caveat: r.caveat };
}

/** Raw bytes/keys live only beneath DATA_DIR; never copied into a report's default reply. */
export function saveCryptoEvidence(dataDir: string, input: CryptoEvidenceInput, label = '') {
  if (typeof label !== 'string' || label.length > 256) throw new Error('label must be at most 256 characters');
  const report = analyzeCryptoEvidence(input), id = randomUUID(), createdAt = Date.now();
  const saved = { version: 1, id, createdAt, label, input, report };
  const text = JSON.stringify(saved);
  if (Buffer.byteLength(text) > CRYPTO_EVIDENCE_LIMITS.fileBytes) throw new Error('evidence record exceeds file limit');
  const existing = files(dataDir);
  if (existing.length >= CRYPTO_EVIDENCE_LIMITS.records) throw new Error('crypto evidence record limit reached; drop an old record explicitly');
  const diskBytes = existing.reduce((n, f) => n + statSync(f.path).size, 0);
  if (diskBytes + Buffer.byteLength(text) > CRYPTO_EVIDENCE_LIMITS.diskBytes) throw new Error('crypto evidence disk limit reached');
  mkdirSync(folder(dataDir), { recursive: true });
  writeFileSync(fileOf(dataDir, id), text, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return { ok: true, ...summary(saved), file: fileOf(dataDir, id) };
}
export function readCryptoEvidence(dataDir: string, id: string, options: { offset?: number; limit?: number; includePayload?: boolean } = {}) {
  const saved = load(dataDir, id), offset = boundedInt(options.offset, 0, 0, CRYPTO_EVIDENCE_LIMITS.observations, 'offset'),
    limit = boundedInt(options.limit, 8, 1, CRYPTO_EVIDENCE_LIMITS.page, 'limit');
  const rows = saved.report.rows.slice(offset, offset + limit), rowIds = new Set(rows.map(r => r.id));
  return { ...summary(saved), offset, nextOffset: offset + rows.length < saved.report.rows.length ? offset + rows.length : null,
    rows, contentLinks: saved.report.contentLinks.filter(l => rowIds.has(l.to)),
    ...(options.includePayload === true ? { observations: saved.input.observations.slice(offset, offset + limit) } : {}) };
}
export function listCryptoEvidence(dataDir: string, options: { offset?: number; limit?: number } = {}) {
  const offset = boundedInt(options.offset, 0, 0, CRYPTO_EVIDENCE_LIMITS.records, 'offset'), limit = boundedInt(options.limit, 8, 1, 16, 'limit');
  const all = files(dataDir).map(f => load(dataDir, f.name.slice(0, -5))).sort((a, b) => b.createdAt - a.createdAt || a.id.localeCompare(b.id));
  return { total: all.length, offset, nextOffset: offset + limit < all.length ? offset + limit : null, records: all.slice(offset, offset + limit).map(summary) };
}
export function dropCryptoEvidence(dataDir: string, id: string) {
  const path = fileOf(dataDir, id); unlinkSync(path); return { ok: true, id };
}

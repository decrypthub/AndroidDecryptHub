// Trace data belongs on the Host. Agent pages are drained before returning a small receipt.
import { mkdirSync, writeFileSync, renameSync, readFileSync, readdirSync, createWriteStream, createReadStream, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { once } from 'node:events';
import { createInterface } from 'node:readline';

export interface StoredInsn { seq: number; addr: string; text: string }
type Command = (op: string, args: Record<string, unknown>, timeout?: number) => Promise<any>;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function dir(root: string) { return join(root, 'traces'); }
function file(root: string, id: string, ext: string) { if (!UUID.test(id)) throw new Error('invalid trace id'); return join(dir(root), `${id}.${ext}`); }
function integer(v: unknown, fallback: number, lo: number, hi: number, name: string): number {
  const n = v === undefined ? fallback : v;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < lo || n > hi) throw new Error(`${name} must be ${lo}..${hi}`);
  return n;
}
function address(v: unknown) {
  if (typeof v !== 'string' || !/^(?:0x)?[a-f0-9]{1,16}$/i.test(v)) throw new Error('invalid instruction address');
  return `0x${BigInt(/^0x/i.test(v) ? v : `0x${v}`).toString(16)}`;
}
export function traceMetadata(root: string, id: string) { return JSON.parse(readFileSync(file(root, id, 'json'), 'utf8')); }
export function listTraces(root: string) {
  try { return readdirSync(dir(root)).filter(n => n.endsWith('.json')).map(n => traceMetadata(root, n.slice(0, -5))).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 100); }
  catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []; throw e; }
}
export function dropTrace(root: string, id: string) { traceMetadata(root, id); rmSync(file(root, id, 'jsonl')); rmSync(file(root, id, 'json')); return { ok: true, id }; }

/** Explicit active call, not a recording of the original application's execution. */
export async function recordTrace(root: string, session: string, opts: Record<string, any>, cmd: Command) {
  if (opts.confirm !== true) throw new Error('trace record actively invokes the function; confirm:true required');
  const budget = integer(opts.budget, 200000, 1, 1000000, 'budget');
  const timeMs = integer(opts.timeMs, 4000, 1, 10000, 'timeMs');
  const capacity = integer(opts.capacity, 65536, 1, 65536, 'capacity');
  if (!opts.addr && (!opts.symLib || !opts.symbol)) throw new Error('addr or symLib+symbol required');
  if (!Array.isArray(opts.args ?? []) || (opts.args ?? []).length > 8) throw new Error('args must contain at most 8 unsigned integer/pointer values');
  const args = (opts.args ?? []).map((v: unknown) => {
    if ((typeof v !== 'string' && typeof v !== 'number') || !/^(0x[0-9a-f]+|[0-9]+)$/i.test(String(v))) throw new Error('args must be unsigned integer/pointer strings');
    if (typeof v === 'number' && !Number.isSafeInteger(v)) throw new Error('large arguments require strings');
    if (BigInt(v) > 0xffffffffffffffffn) throw new Error('argument exceeds uint64');
    return String(v);
  }).join(',');
  const raw = await cmd('qbdi_trace', { symLib: opts.symLib ?? '', symbol: opts.symbol ?? '', addr: opts.addr ? address(opts.addr) : '', args, paged: 'true', budget, timeMs, capacity }, timeMs + 10000);
  if (raw.ok === false || !Number.isSafeInteger(raw.traceId) || !Number.isSafeInteger(raw.count) || raw.count < 0 || raw.count > capacity) throw new Error(raw.error ?? 'agent does not support paged traces; deploy current agent');
  const id = randomUUID(), path = file(root, id, 'jsonl'), tmp = path + '.partial';
  let writer: ReturnType<typeof createWriteStream>;
  try {
    mkdirSync(dir(root), { recursive: true });
    writer = createWriteStream(tmp, { flags: 'wx', mode: 0o600 });
  } catch(e) {
    try { await cmd('qbdi_read', { traceId:raw.traceId, release:'true' }, 5000); }
    catch(releaseError) { throw new Error(`${(e as Error).message}; agent release failed: ${(releaseError as Error).message}`); }
    throw e;
  }
  let writeError: Error | null = null;
  writer.on('error', e => { writeError = e; });
  let offset = 0, error = '', released = false;
  const drainDeadline = Date.now() + 30000;
  try {
    await once(writer, 'open');
    while (offset < raw.count) {
      const remaining = drainDeadline - Date.now();
      if (remaining <= 0) throw new Error('trace drain exceeded its 30 second Host budget');
      const page = await cmd('qbdi_read', { traceId: raw.traceId, offset, limit: 128 }, Math.min(10000, remaining));
      if (page.ok !== true || page.traceId !== raw.traceId || page.offset !== offset || page.total !== raw.count || !Array.isArray(page.insns) || page.insns.length === 0 || page.insns.length > 128 || page.nextOffset !== offset + page.insns.length || page.nextOffset > raw.count) throw new Error(page.error ?? 'trace page discontinuity');
      const lines = page.insns.map((r: any, i: number) => {
        if (r.seq !== offset + i || typeof r.text !== 'string' || r.text.length > 56) throw new Error('invalid trace instruction');
        return JSON.stringify({ seq: r.seq, addr: address(r.addr), text: r.text.trim() });
      }).join('\n') + '\n';
      if (writeError) throw writeError;
      if (!writer.write(lines)) await once(writer, 'drain');
      offset = page.nextOffset;
    }
  } catch (e) { error = (e as Error).message; }
  finally {
    try {
      writer.end();
      if (!writer.closed) await once(writer, 'close');
    } catch(e) { error ||= `trace file failed: ${(e as Error).message}`; }
    finally {
      try { released = (await cmd('qbdi_read', { traceId: raw.traceId, release: 'true' }, 5000)).ok === true; }
      catch (e) { error ||= `agent release failed: ${(e as Error).message}`; }
    }
  }
  if (writeError) error ||= (writeError as Error).message;
  renameSync(tmp, path);
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  const { insns: _insns, ...metadata } = raw;
  const receipt = { ...metadata, id, session, createdAt: new Date().toISOString(), execution: 'active-call', coverage: 'instrumented-module',
    recorded: offset, complete: raw.complete === true && offset === raw.count && !error,
    transportComplete: offset === raw.count && !error, released, sha256: hash.digest('hex'), ...(error ? { error } : {}),
    limits: ['Invokes the function on a virtual stack with integer arguments; not the original call context.', 'Only instructions instrumented by QBDI are recorded; external modules and native transfers are outside this coverage.', 'The execution time guard runs at instrumented instructions and cannot interrupt a blocking external native call.', 'Memory values and full register states are not recorded. Text fields are bounded to 55 characters.', 'Host page drain has a 30 second budget; incomplete transfers remain incomplete.'] };
  writeFileSync(file(root, id, 'json.tmp'), JSON.stringify(receipt, null, 2), { mode: 0o600 });
  renameSync(file(root, id, 'json.tmp'), file(root, id, 'json'));
  return receipt;
}

export async function queryTrace(root: string, id: string, opts: Record<string, unknown> = {}) {
  const meta = traceMetadata(root, id);
  const afterSeq = integer(opts.afterSeq, -1, -1, 65536, 'afterSeq');
  const limit = integer(opts.limit, 32, 1, 128, 'limit');
  const pc = opts.pc === undefined ? null : address(opts.pc);
  const lo = opts.minPc === undefined ? null : BigInt(address(opts.minPc));
  const hi = opts.maxPc === undefined ? null : BigInt(address(opts.maxPc));
  if (lo !== null && hi !== null && lo >= hi) throw new Error('minPc must precede maxPc');
  const mnemonic = opts.mnemonic === undefined ? '' : String(opts.mnemonic).trim().toLowerCase();
  if (mnemonic && !/^[a-z][a-z0-9.]{0,23}$/.test(mnemonic)) throw new Error('invalid mnemonic');
  const rows: StoredInsn[] = [];
  const stream = createReadStream(file(root, id, 'jsonl'));
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  let more = false;
  try { for await (const line of lines) {
    const r: StoredInsn = JSON.parse(line);
    if (r.seq <= afterSeq || (pc && r.addr !== pc) || (lo !== null && BigInt(r.addr) < lo) || (hi !== null && BigInt(r.addr) >= hi) || (mnemonic && r.text.split(/\s/)[0].toLowerCase() !== mnemonic)) continue;
    if (rows.length === limit) { more = true; break; }
    rows.push(r);
  } } finally { lines.close(); stream.destroy(); }
  return { id, complete: meta.complete, coverage: meta.coverage, afterSeq, nextAfterSeq: rows.at(-1)?.seq ?? afterSeq, more, rows };
}

export async function traceStats(root: string, id: string) {
  const meta = traceMetadata(root, id), mnemonics = new Map<string, number>(), pcs = new Map<string, number>(), blocks = new Map<string, number>();
  let previous: StoredInsn | null = null, count = 0;
  const stream = createReadStream(file(root, id, 'jsonl')), lines = createInterface({ input: stream, crlfDelay: Infinity });
  try { for await (const line of lines) {
    const r: StoredInsn = JSON.parse(line), m = r.text.split(/\s/)[0].toLowerCase(); count++;
    mnemonics.set(m, (mnemonics.get(m) ?? 0) + 1); pcs.set(r.addr, (pcs.get(r.addr) ?? 0) + 1);
    if (!previous || BigInt(previous.addr) + 4n !== BigInt(r.addr) || /^(b(?:\..+)?|bl|blr|br|ret|cbz|cbnz|tbz|tbnz)\b/i.test(previous.text)) blocks.set(r.addr, (blocks.get(r.addr) ?? 0) + 1);
    previous = r;
  } } finally { lines.close(); stream.destroy(); }
  const top = (m: Map<string, number>) => [...m].sort((a,b) => b[1]-a[1]).slice(0,32).map(([value,count]) => ({value,count}));
  return { ...meta, count, uniquePcs: pcs.size, mnemonics: top(mnemonics), hotPcs: top(pcs), observedBlockEntries: top(blocks) };
}

const regName = (s: string) => /^w([0-9]+)$/.test(s) ? 'x' + s.slice(1) : s === 'wsp' ? 'sp' : s === 'fp' ? 'x29' : s === 'lr' ? 'x30' : s;
/** Conservative register dependency slice: no invented memory aliases or external-call effects. */
export async function sliceTrace(root: string, id: string, opts: Record<string, unknown>) {
  const meta = traceMetadata(root, id), beforeSeq = integer(opts.beforeSeq, meta.recorded, 0, 65536, 'beforeSeq'), maxScan = integer(opts.maxScan, 4096, 1, 16384, 'maxScan');
  const seed = regName(String(opts.register ?? '').toLowerCase());
  if (!/^(x(?:[0-9]|[12][0-9]|30)|sp)$/.test(seed)) throw new Error('register must be x0..x30/w0..w30/sp');
  const rows: StoredInsn[] = [], stream = createReadStream(file(root,id,'jsonl')), lines = createInterface({input:stream,crlfDelay:Infinity});
  try { for await (const line of lines) { const r: StoredInsn = JSON.parse(line); if (r.seq >= beforeSeq) break; if (r.seq >= beforeSeq-maxScan) rows.push(r); } }
  finally { lines.close(); stream.destroy(); }
  const needed = new Set([seed]), selected: any[] = []; let barrier: any = null;
  const harmless = /^(nop|hint|ret|b|b\.[a-z]+|cbz|cbnz|tbz|tbnz|str|strb|strh|stur|stp|cmp|cmn|tst)$/;
  const supported = /^(mov|movz|movn|movk|add|adds|sub|subs|eor|and|orr|orn|bic|lsl|lsr|asr|ror|uxtb|uxth|ubfx|adr|adrp|madd|mul)$/;
  for (let i=rows.length-1;i>=0 && needed.size;i--) {
    const r=rows[i], [m,...rest]=r.text.toLowerCase().split(/\s+/), operands=rest.join(' '), regs=[...operands.matchAll(/\b(?:[xw](?:[12]?[0-9]|30)|wsp|sp|fp|lr)\b/g)].map(x=>regName(x[0]));
    if (harmless.test(m) && !/\]!|\],/.test(operands)) continue;
    if (/^ld/.test(m) && regs.some(r=>needed.has(r))) { selected.push({...r,reason:'memory input'}); barrier={seq:r.seq,reason:'memory provenance requires recorded access addresses and values'}; break; }
    if (!supported.test(m)) { barrier={seq:r.seq,reason:`unsupported instruction or call: ${m}`}; break; }
    const destination=operands.split(',')[0].trim();
    if(destination==='xzr'||destination==='wzr') continue;
    const dst=regName(destination); if (!/^(x(?:[0-9]|[12][0-9]|30)|sp)$/.test(dst)) { barrier={seq:r.seq,reason:'unrecognized destination operand'}; break; }
    if (!needed.has(dst)) continue;
    selected.push(r); needed.delete(dst);
    if (m==='movk') needed.add(dst);
    for(const source of regs.slice(1)) needed.add(source);
  }
  return { id, register:seed, beforeSeq, scanned:rows.length, selected:selected.reverse(), unresolved:[...needed], barrier,
    complete: !barrier && needed.size===0, sourceComplete:meta.complete,
    limits:['Register dependencies only; memory aliases, conditional flag dependencies, vector state and external calls require additional evidence.'] };
}

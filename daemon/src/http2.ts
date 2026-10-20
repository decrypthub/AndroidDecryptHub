// HTTP/2 frames on one direction of an SSL connection, turned into whole messages.
// The caller concatenates SSL_write (client) or SSL_read (server) first. HPACK state
// stays inside this parse: header blocks are decoded in the order they sit in `buf`.
import { createHpackDecoder, type HpackField } from './hpack.ts';

export interface Http2Message {
  streamId: number;
  startLine: string;
  headerText: string;
  headers: Map<string, string>;
  body: Buffer;
  complete: boolean;
  note?: string;
  method?: string;
  status?: number;
}

const PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
const MAX_FRAME = 16 * 1024 * 1024;
const MAX_BLOCK = 256 * 1024;
const MAX_STREAMS = 512;

const DATA = 0;
const HEADERS = 1;
const RST = 3;
const PUSH = 5;
const CONTINUATION = 9;

const END_STREAM = 0x1;
const END_HEADERS = 0x4;
const PADDED = 0x8;
const PRIORITY = 0x20;

interface StreamState {
  id: number;
  fields: HpackField[];
  body: Buffer[];
  end: boolean;
  reset: boolean;
}

interface OpenBlock {
  streamId: number;
  kind: 'headers' | 'push';
  endStream: boolean;
  parts: Buffer[];
}

function fragment(payload: Buffer, flags: number, type: number): { frag: Buffer; promised?: number } | string {
  let p = payload;
  let pad = 0;
  if (flags & PADDED) {
    if (!p.length) return '填充长度缺失';
    pad = p[0];
    p = p.subarray(1);
  }
  let promised: number | undefined;
  if (type === PUSH) {
    if (p.length < 4) return 'PUSH_PROMISE 太短';
    promised = p.readUInt32BE(0) & 0x7fffffff;
    p = p.subarray(4);
  } else if (flags & PRIORITY) {
    if (p.length < 5) return 'PRIORITY 太短';
    p = p.subarray(5);
  }
  if (pad > p.length) return '填充比帧还长';
  if (pad) p = p.subarray(0, p.length - pad);
  return { frag: p, promised };
}

function dataBytes(payload: Buffer, flags: number): Buffer | string {
  const got = fragment(payload, flags, DATA);
  if (typeof got === 'string') return got;
  return got.frag;
}

function headerLine(name: string, value: string): string {
  return `${name}: ${value}`;
}

function messageFrom(st: StreamState, role: 'client' | 'server'): Http2Message | null {
  if (!st.fields.length) return null;
  const headers = new Map<string, string>();
  const pseudo = new Map<string, string>();
  const lines: string[] = [];
  for (const f of st.fields) {
    const name = f.name.toLowerCase();
    if (name.startsWith(':')) {
      if (!pseudo.has(name)) pseudo.set(name, f.value);
      continue;
    }
    const prev = headers.get(name);
    headers.set(name, prev ? `${prev}, ${f.value}` : f.value);
    lines.push(headerLine(name, f.value));
  }
  const notes: string[] = [];
  if (st.reset) notes.push('对端重置了这条流');
  else if (!st.end) notes.push('正文还不完整');
  if (role === 'client') {
    const method = (pseudo.get(':method') || 'GET').toUpperCase();
    const path = pseudo.get(':path') || '/';
    if (pseudo.get(':scheme')) lines.unshift(headerLine(':scheme', pseudo.get(':scheme')!));
    if (pseudo.get(':authority')) lines.unshift(headerLine(':authority', pseudo.get(':authority')!));
    return {
      streamId: st.id,
      startLine: `${method} ${path} HTTP/2`,
      headerText: lines.join('\n'),
      headers,
      body: Buffer.concat(st.body),
      complete: st.end && !st.reset,
      method,
      ...(notes.length ? { note: notes.join('；') } : {}),
    };
  }
  const status = Number(pseudo.get(':status'));
  const statusOk = Number.isInteger(status) && status >= 100 && status <= 599;
  return {
    streamId: st.id,
    startLine: statusOk ? `HTTP/2 ${status}` : 'HTTP/2',
    headerText: lines.join('\n'),
    headers,
    body: Buffer.concat(st.body),
    complete: st.end && !st.reset,
    ...(statusOk ? { status } : {}),
    ...(notes.length ? { note: notes.join('；') } : {}),
  };
}

/**
 * Parse one direction. `client` strips the connection preface; `server` starts at the first frame.
 * Messages are in the order their first header block finished.
 */
export function parseHttp2(buf: Buffer, role: 'client' | 'server'): { messages: Http2Message[]; note?: string } {
  let off = 0;
  if (role === 'client') {
    if (buf.length < PREFACE.length) {
      return { messages: [], ...(buf.length && PREFACE.subarray(0, buf.length).equals(buf) ? {} : { note: '没有 HTTP/2 前言' }) };
    }
    if (!buf.subarray(0, PREFACE.length).equals(PREFACE)) return { messages: [], note: '没有 HTTP/2 前言' };
    off = PREFACE.length;
  }
  const dec = createHpackDecoder();
  const streams = new Map<number, StreamState>();
  const order: number[] = [];
  let open: OpenBlock | null = null;
  let note: string | undefined;

  const touch = (id: number): StreamState | null => {
    const have = streams.get(id);
    if (have) return have;
    if (streams.size >= MAX_STREAMS) { note = '流太多'; return null; }
    const st: StreamState = { id, fields: [], body: [], end: false, reset: false };
    streams.set(id, st);
    order.push(id);
    return st;
  };

  const finish = (block: OpenBlock): boolean => {
    open = null;
    const blob = Buffer.concat(block.parts);
    if (blob.length > MAX_BLOCK) { note = '头部块过大'; return false; }
    const decoded = dec.decode(blob);
    if (!decoded.ok) { note = decoded.error; return false; }
    if (block.kind === 'push') return true;
    const st = touch(block.streamId);
    if (!st) return false;
    st.fields.push(...decoded.fields);
    if (block.endStream) st.end = true;
    return true;
  };

  while (off + 9 <= buf.length) {
    const len = buf.readUIntBE(off, 3);
    const type = buf[off + 3];
    const flags = buf[off + 4];
    const sid = buf.readUInt32BE(off + 5) & 0x7fffffff;
    if (len > MAX_FRAME) { note = '帧长度异常'; break; }
    if (off + 9 + len > buf.length) { note = '最后一帧还不完整'; break; }
    const payload = buf.subarray(off + 9, off + 9 + len);
    off += 9 + len;

    if (open && (type !== CONTINUATION || sid !== open.streamId)) {
      note = 'CONTINUATION 被别的帧打断';
      break;
    }
    if (type === CONTINUATION) {
      if (!open) { note = '孤立的 CONTINUATION'; break; }
      open.parts.push(payload);
      if (flags & END_HEADERS) { if (!finish(open)) break; }
      continue;
    }
    if (type === HEADERS || type === PUSH) {
      const got = fragment(payload, flags, type);
      if (typeof got === 'string') { note = got; break; }
      open = {
        streamId: type === PUSH ? (got.promised ?? sid) : sid,
        kind: type === PUSH ? 'push' : 'headers',
        endStream: type === HEADERS && (flags & END_STREAM) !== 0,
        parts: [got.frag],
      };
      if (flags & END_HEADERS) { if (!finish(open)) break; }
      continue;
    }
    if (type === DATA) {
      const bytes = dataBytes(payload, flags);
      if (typeof bytes === 'string') { note = bytes; break; }
      const st = streams.get(sid);
      // PUSH_PROMISE bodies and a DATA that raced ahead of its headers are not a request.
      // Dropping them keeps the rest of the connection decodable.
      if (!st) continue;
      if (bytes.length) st.body.push(bytes);
      if (flags & END_STREAM) st.end = true;
      continue;
    }
    if (type === RST) {
      const st = streams.get(sid);
      if (st) { st.reset = true; st.end = true; }
    }
  }
  if (!note && off < buf.length) note = '最后一帧还不完整';
  if (!note && open) note = '头部块还不完整';

  const messages: Http2Message[] = [];
  for (const id of order) {
    const st = streams.get(id);
    if (!st) continue;
    const msg = messageFrom(st, role);
    if (msg) messages.push(msg);
  }
  return { messages, ...(note ? { note } : {}) };
}

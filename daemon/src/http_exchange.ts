// http_exchange.ts — pair TLS plaintext into HTTP/1.1 exchanges.
//
// SSL_read and SSL_write are byte streams, one record per call. The agent stamps the SSL*
// on each record (`conn`). This module concatenates one connection's writes and reads
// separately, splits them on HTTP/1.1 framing (Content-Length or chunked), and pairs the
// Nth request with the Nth response. gzip / deflate / br are decoded here.
//
// HTTP/2 is detected (the client preface) and left unpaired: framing that needs a stream
// id and an HPACK table is a different parser. Records with no conn cannot be joined.
//
// Pure: no daemon state. Callers filter the capture store and pass the records in.
import zlib from 'node:zlib';

const TEXT_CAP = 65_536;
const H2_PREFACE = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
const REQUEST_LINE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT) (\S+) HTTP\/1\.[01]$/;
const STATUS_LINE = /^HTTP\/1\.[01] (\d{3})(?: |$)/;

export const HTTP_EXCHANGE_CAVEAT =
  '同一条 SSL 连接上，发送字节和接收字节各自按时间拼回去，再用 HTTP/1.1 的 Content-Length 或 chunked 拆开，按顺序配对。' +
  'gzip、deflate、br 在这里解开。HTTP/2 和没有连接号的记录不配对。';

export interface TlsChunk {
  id: number;
  sessionId: string;
  func: string;
  hex: string;
  /** Byte length of the original call. The hex may be shorter when the capture cap cut it. */
  inl: number;
  tsNs: number;
  ts?: number;
  /** SSL* as printed by the agent (`0x…`). Empty when this build did not stamp one. */
  conn?: string;
}

export interface HttpPart {
  startLine: string;
  headerText: string;
  bodyText: string;
  bodyBytes: number;
  binary: boolean;
  complete: boolean;
  textTruncated: boolean;
  contentEncoding?: string;
  decoded: boolean;
  note?: string;
}

export interface HttpExchange {
  id: string;
  sessionId: string;
  conn: string;
  label: string;
  status: string;
  ts: number;
  tsNs: number;
  captureIds: number[];
  request: HttpPart | null;
  response: HttpPart | null;
  note?: string;
}

export interface HttpAssembly {
  exchanges: HttpExchange[];
  /** TLS records that carried no SSL*. */
  noConn: number;
  /** Connections whose client bytes are an HTTP/2 preface. */
  http2: number;
  caveat: string;
}

interface RawMsg {
  startLine: string;
  headerText: string;
  headers: Map<string, string>;
  body: Buffer;
  complete: boolean;
  note?: string;
  method?: string;
  status?: number;
}

interface BuiltSide {
  buf: Buffer;
  ids: number[];
  hole: string | null;
  ts: number;
  tsNs: number;
}

function hexBytes(hex: string): Buffer | null {
  if (!hex || hex.length % 2) return null;
  return Buffer.from(hex, 'hex');
}

function headerValue(headers: Map<string, string>, name: string): string {
  return headers.get(name) ?? '';
}

function parseHeaderBlock(buf: Buffer, at: number):
  { startLine: string; headerText: string; headers: Map<string, string>; next: number } | 'need' | 'bad' {
  const end = buf.indexOf('\r\n\r\n', at);
  if (end < 0) return 'need';
  const raw = buf.subarray(at, end).toString('latin1');
  const lines = raw.split('\r\n');
  if (!lines[0]) return 'bad';
  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    const prev = headers.get(key);
    headers.set(key, prev ? `${prev}, ${value}` : value);
  }
  return { startLine: lines[0], headerText: lines.slice(1).join('\n'), headers, next: end + 4 };
}

function readChunked(buf: Buffer, at: number): { body: Buffer; end: number } | 'need' | 'bad' {
  const parts: Buffer[] = [];
  let i = at;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', i);
    if (lineEnd < 0) return 'need';
    const sizeHex = buf.subarray(i, lineEnd).toString('latin1').split(';')[0].trim();
    if (!/^[0-9a-fA-F]+$/.test(sizeHex)) return 'bad';
    const size = Number.parseInt(sizeHex, 16);
    const dataAt = lineEnd + 2;
    if (size === 0) {
      if (buf.length < dataAt + 2) return 'need';
      if (buf[dataAt] === 0x0d && buf[dataAt + 1] === 0x0a) return { body: Buffer.concat(parts), end: dataAt + 2 };
      const trailer = buf.indexOf('\r\n\r\n', dataAt);
      if (trailer < 0) return 'need';
      return { body: Buffer.concat(parts), end: trailer + 4 };
    }
    const dataEnd = dataAt + size;
    if (buf.length < dataEnd + 2) return 'need';
    if (buf[dataEnd] !== 0x0d || buf[dataEnd + 1] !== 0x0a) return 'bad';
    parts.push(buf.subarray(dataAt, dataEnd));
    i = dataEnd + 2;
  }
}

function takeBody(buf: Buffer, at: number, headers: Map<string, string>, kind: 'request' | 'response', method: string | undefined, status: number | undefined):
  { body: Buffer; end: number; complete: boolean; note?: string } | 'need' | 'bad' {
  if (kind === 'response' && status != null && ((status >= 100 && status < 200) || status === 204 || status === 304)) {
    return { body: Buffer.alloc(0), end: at, complete: true };
  }
  if (kind === 'response' && method === 'HEAD') return { body: Buffer.alloc(0), end: at, complete: true };
  const te = headerValue(headers, 'transfer-encoding').toLowerCase();
  if (te.split(',').some((part) => part.trim() === 'chunked')) {
    const chunked = readChunked(buf, at);
    if (chunked === 'need' || chunked === 'bad') return chunked;
    return { body: chunked.body, end: chunked.end, complete: true };
  }
  const cl = headerValue(headers, 'content-length').split(',')[0].trim();
  if (cl) {
    if (!/^\d+$/.test(cl)) return 'bad';
    const n = Number(cl);
    if (buf.length < at + n) return 'need';
    return { body: buf.subarray(at, at + n), end: at + n, complete: true };
  }
  if (kind === 'request') return { body: Buffer.alloc(0), end: at, complete: true };
  return {
    body: buf.subarray(at),
    end: buf.length,
    complete: false,
    note: '响应没有 Content-Length 或 chunked，正文要等到这条连接结束',
  };
}

function parseSide(buf: Buffer, kind: 'request' | 'response', methods: (string | undefined)[]): { messages: RawMsg[]; note?: string } {
  const messages: RawMsg[] = [];
  let at = 0;
  while (at < buf.length && messages.length < 500) {
    const head = parseHeaderBlock(buf, at);
    if (head === 'need') {
      return { messages, note: messages.length ? '下一条的头部还不完整' : undefined };
    }
    if (head === 'bad') return { messages, note: '头部无法解析' };
    const ok = kind === 'request' ? REQUEST_LINE.test(head.startLine) : STATUS_LINE.test(head.startLine);
    if (!ok) return { messages, note: messages.length ? '后面的字节不是下一条 HTTP/1.1' : undefined };
    const method = kind === 'request' ? head.startLine.slice(0, head.startLine.indexOf(' ')).toUpperCase() : methods[messages.length];
    const status = kind === 'response' ? Number(head.startLine.split(' ')[1]) : undefined;
    const body = takeBody(buf, head.next, head.headers, kind, method, status);
    if (body === 'bad') return { messages, note: '正文分块格式不对' };
    if (body === 'need') {
      messages.push({
        startLine: head.startLine, headerText: head.headerText, headers: head.headers,
        body: buf.subarray(head.next), complete: false, note: '正文还不完整', method, status,
      });
      return { messages };
    }
    messages.push({
      startLine: head.startLine, headerText: head.headerText, headers: head.headers,
      body: body.body, complete: body.complete, note: body.note, method, status,
    });
    at = body.end;
    if (!body.complete) return { messages };
  }
  return { messages };
}

function decodeBody(body: Buffer, encoding: string): { body: Buffer; decoded: boolean; note?: string } {
  const steps = encoding.split(',').map((s) => s.trim().toLowerCase()).filter((s) => s && s !== 'identity');
  let cur = body;
  for (const step of steps) {
    try {
      if (step === 'gzip' || step === 'x-gzip') cur = zlib.gunzipSync(cur);
      else if (step === 'deflate') {
        try { cur = zlib.inflateSync(cur); }
        catch { cur = zlib.inflateRawSync(cur); }
      } else if (step === 'br') cur = zlib.brotliDecompressSync(cur);
      else return { body: cur, decoded: false, note: `未解的 Content-Encoding: ${step}` };
    } catch {
      return { body: cur, decoded: false, note: `${step} 解开失败` };
    }
  }
  return { body: cur, decoded: steps.length > 0 };
}

function asText(body: Buffer): { text: string; binary: boolean; textTruncated: boolean } {
  const cut = body.subarray(0, TEXT_CAP);
  if (cut.includes(0)) return { text: '', binary: true, textTruncated: body.length > TEXT_CAP };
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(cut);
    return { text, binary: false, textTruncated: body.length > TEXT_CAP };
  } catch {
    return { text: '', binary: true, textTruncated: body.length > TEXT_CAP };
  }
}

function toPart(msg: RawMsg): HttpPart {
  const encoding = headerValue(msg.headers, 'content-encoding');
  const decoded = encoding && msg.complete
    ? decodeBody(msg.body, encoding)
    : { body: msg.body, decoded: false, note: encoding && !msg.complete ? '正文还不完整，先不解压' : undefined };
  const text = asText(decoded.body);
  const notes = [msg.note, decoded.note, text.textTruncated ? `正文只返回前 ${TEXT_CAP} 字符` : ''].filter(Boolean);
  return {
    startLine: msg.startLine,
    headerText: msg.headerText,
    bodyText: text.text,
    bodyBytes: decoded.body.length,
    binary: text.binary,
    complete: msg.complete,
    textTruncated: text.textTruncated,
    ...(encoding ? { contentEncoding: encoding } : {}),
    decoded: decoded.decoded,
    ...(notes.length ? { note: notes.join('；') } : {}),
  };
}

function requestLabel(startLine: string, headerText: string): string {
  const m = startLine.match(REQUEST_LINE);
  if (!m) return startLine;
  const method = m[1].toUpperCase();
  const target = m[2];
  if (/^https?:\/\//i.test(target)) return `${method} ${target}`;
  const host = headerText.match(/^host:\s*(\S+)/im)?.[1] ?? '';
  if (host && target.startsWith('/')) return `${method} https://${host}${target}`;
  return `${method} ${target}`;
}

function isH2(buf: Buffer): boolean {
  if (!buf.length) return false;
  if (buf.length >= H2_PREFACE.length) return buf.subarray(0, H2_PREFACE.length).equals(H2_PREFACE);
  return H2_PREFACE.subarray(0, buf.length).equals(buf);
}

function buildSide(chunks: TlsChunk[], func: string): BuiltSide {
  const mine = chunks.filter((c) => c.func === func);
  const parts: Buffer[] = [];
  const ids: number[] = [];
  let hole: string | null = null;
  let ts = mine.length ? (mine[0].ts ?? Math.floor(mine[0].tsNs / 1e6)) : 0;
  let tsNs = mine.length ? mine[0].tsNs : 0;
  for (const c of mine) {
    const bytes = hexBytes(c.hex);
    if (!bytes) {
      hole = `捕获 #${c.id} 的明文不是完整的十六进制，这条连接后面的字节不再拼进去`;
      break;
    }
    parts.push(bytes);
    ids.push(c.id);
    const at = c.ts ?? Math.floor(c.tsNs / 1e6);
    if (at && (ts === 0 || at < ts)) ts = at;
    if (c.tsNs && (tsNs === 0 || c.tsNs < tsNs)) tsNs = c.tsNs;
    const stored = bytes.length;
    const inl = c.inl > 0 ? c.inl : stored;
    if (stored < inl) {
      hole = `捕获 #${c.id} 只记下 ${stored}/${inl} 字节，这条连接后面的字节不再拼进去`;
      break;
    }
  }
  return { buf: Buffer.concat(parts), ids, hole, ts, tsNs };
}

function hasConn(conn: string | undefined): conn is string {
  return !!conn && conn !== '0' && conn !== '0x0' && conn !== '0x';
}

/**
 * Pair HTTP/1.1 messages that share an SSL*. Order inside one direction is timestamp, then id.
 */
export function assembleHttpExchanges(records: TlsChunk[]): HttpAssembly {
  let noConn = 0;
  let http2 = 0;
  const groups = new Map<string, TlsChunk[]>();
  for (const rec of records) {
    if (rec.func !== 'SSL_read' && rec.func !== 'SSL_write') continue;
    if (!hasConn(rec.conn)) { noConn++; continue; }
    const key = `${rec.sessionId}\n${rec.conn.toLowerCase()}`;
    const list = groups.get(key);
    if (list) list.push(rec);
    else groups.set(key, [rec]);
  }

  const exchanges: HttpExchange[] = [];
  for (const [key, chunks] of groups) {
    chunks.sort((a, b) => (a.tsNs - b.tsNs) || (a.id - b.id));
    const [sessionId, conn] = key.split('\n');
    const write = buildSide(chunks, 'SSL_write');
    const read = buildSide(chunks, 'SSL_read');
    if (isH2(write.buf)) { http2++; continue; }
    const requests = parseSide(write.buf, 'request', []);
    const responses = parseSide(read.buf, 'response', requests.messages.map((m) => m.method));
    if (!requests.messages.length && !responses.messages.length) continue;
    const captureIds = [...write.ids, ...read.ids];
    const hole = [write.hole, read.hole].filter(Boolean).join('；');
    const n = Math.max(requests.messages.length, responses.messages.length);
    for (let i = 0; i < n; i++) {
      const req = requests.messages[i];
      const res = responses.messages[i];
      const notes = [
        i === n - 1 ? hole : '',
        i === n - 1 ? requests.note : '',
        i === n - 1 ? responses.note : '',
      ].filter(Boolean);
      exchanges.push({
        id: `${sessionId}:${conn}:${i}`,
        sessionId,
        conn,
        label: req ? requestLabel(req.startLine, req.headerText) : (res?.startLine ?? 'HTTP'),
        status: res?.status != null ? String(res.status) : '',
        ts: write.ts || read.ts,
        tsNs: write.tsNs || read.tsNs,
        captureIds,
        request: req ? toPart(req) : null,
        response: res ? toPart(res) : null,
        ...(notes.length ? { note: notes.join('；') } : {}),
      });
    }
  }
  exchanges.sort((a, b) => (a.tsNs - b.tsNs) || a.id.localeCompare(b.id));
  return { exchanges, noConn, http2, caveat: HTTP_EXCHANGE_CAVEAT };
}

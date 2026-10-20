import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';

import { assembleHttpExchanges, type TlsChunk } from '../src/http_exchange.ts';

let seq = 1;
function chunk(func: 'SSL_write' | 'SSL_read', text: string | Buffer, extra: Partial<TlsChunk> = {}): TlsChunk {
  const buf = Buffer.isBuffer(text) ? text : Buffer.from(text, 'latin1');
  return {
    id: extra.id ?? seq++,
    sessionId: extra.sessionId ?? 's',
    func,
    hex: buf.toString('hex'),
    inl: extra.inl ?? buf.length,
    tsNs: extra.tsNs ?? seq * 1000,
    ts: extra.ts ?? seq,
    conn: extra.conn === undefined ? '0x10' : extra.conn,
  };
}

test('a split request and a gzip response on the same SSL become one exchange', () => {
  seq = 1;
  const body = Buffer.from('{"ok":1}');
  const gz = zlib.gzipSync(body);
  const head = 'POST /api/v549/user/login/password HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 7\r\n\r\n';
  const req = head + 'a=1&b=2';
  const mid = Math.floor(head.length / 2);
  const resp = Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${gz.length}\r\n\r\n`),
    gz,
  ]);
  const out = assembleHttpExchanges([
    chunk('SSL_write', req.slice(0, mid), { tsNs: 1 }),
    chunk('SSL_read', resp, { tsNs: 2 }),
    chunk('SSL_write', req.slice(mid), { tsNs: 3 }),
  ]);
  assert.equal(out.exchanges.length, 1);
  const ex = out.exchanges[0];
  assert.equal(ex.label, 'POST https://api.example.com/api/v549/user/login/password');
  assert.equal(ex.status, '200');
  assert.equal(ex.request?.bodyText, 'a=1&b=2');
  assert.equal(ex.request?.complete, true);
  assert.equal(ex.response?.bodyText, '{"ok":1}');
  assert.equal(ex.response?.decoded, true);
  assert.equal(ex.response?.complete, true);
});

test('chunked response bytes split across SSL_read calls reassemble', () => {
  seq = 1;
  const a = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n';
  const b = '0\r\n\r\n';
  const out = assembleHttpExchanges([
    chunk('SSL_write', 'GET /x HTTP/1.1\r\nHost: h\r\n\r\n', { tsNs: 1 }),
    chunk('SSL_read', a, { tsNs: 2 }),
    chunk('SSL_read', b, { tsNs: 3 }),
  ]);
  assert.equal(out.exchanges.length, 1);
  assert.equal(out.exchanges[0].response?.bodyText, 'hello');
  assert.equal(out.exchanges[0].response?.complete, true);
});

test('two exchanges on one connection stay in order, and a second connection stays apart', () => {
  seq = 1;
  const out = assembleHttpExchanges([
    chunk('SSL_write', 'GET /a HTTP/1.1\r\nHost: h\r\n\r\n', { conn: '0x1', tsNs: 1 }),
    chunk('SSL_write', 'GET /b HTTP/1.1\r\nHost: h\r\n\r\n', { conn: '0x2', tsNs: 2 }),
    chunk('SSL_read', 'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA', { conn: '0x1', tsNs: 3 }),
    chunk('SSL_write', 'POST /c HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nZ', { conn: '0x1', tsNs: 4 }),
    chunk('SSL_read', 'HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nB', { conn: '0x2', tsNs: 5 }),
    chunk('SSL_read', 'HTTP/1.1 204 No Content\r\n\r\n', { conn: '0x1', tsNs: 6 }),
  ]);
  const one = out.exchanges.filter((e) => e.conn === '0x1');
  const two = out.exchanges.filter((e) => e.conn === '0x2');
  assert.deepEqual(one.map((e) => e.label), ['GET https://h/a', 'POST https://h/c']);
  assert.deepEqual(one.map((e) => e.status), ['200', '204']);
  assert.equal(one[0].response?.bodyText, 'A');
  assert.equal(one[1].request?.bodyText, 'Z');
  assert.equal(one[1].response?.bodyBytes, 0);
  assert.equal(two.length, 1);
  assert.equal(two[0].label, 'GET https://h/b');
  assert.equal(two[0].status, '201');
});

test('HEAD does not swallow the next response, even when Content-Length is set', () => {
  seq = 1;
  const out = assembleHttpExchanges([
    chunk('SSL_write', 'HEAD /b HTTP/1.1\r\nHost: h\r\n\r\n', { tsNs: 1 }),
    chunk('SSL_read', 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n', { tsNs: 2 }),
  ]);
  assert.equal(out.exchanges.length, 2);
  assert.equal(out.exchanges[0].request?.startLine.startsWith('HEAD '), true);
  assert.equal(out.exchanges[0].response?.bodyBytes, 0);
  assert.equal(out.exchanges[0].response?.complete, true);
  assert.equal(out.exchanges[1].status, '204');
});

test('a truncated capture stops the stream and does not glue the next request onto it', () => {
  seq = 1;
  const first = 'GET /a HTTP/1.1\r\nHost: h\r\n\r\n';
  const cut = Buffer.from('POST /secret HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nABCD', 'latin1');
  const out = assembleHttpExchanges([
    chunk('SSL_write', first, { id: 1, tsNs: 1 }),
    chunk('SSL_write', cut.subarray(0, 8), { id: 2, tsNs: 2, inl: cut.length }),
    chunk('SSL_write', 'GET /after HTTP/1.1\r\nHost: h\r\n\r\n', { id: 3, tsNs: 3 }),
    chunk('SSL_read', 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', { id: 4, tsNs: 4 }),
  ]);
  assert.equal(out.exchanges.length, 1);
  assert.equal(out.exchanges[0].label, 'GET https://h/a');
  assert.match(out.exchanges[0].note ?? '', /#2/);
  assert.equal(out.exchanges[0].captureIds.includes(3), false);
});

function h2Frame(type: number, flags: number, stream: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(9 + payload.length);
  h.writeUIntBE(payload.length, 0, 3);
  h[3] = type;
  h[4] = flags;
  h.writeUInt32BE(stream & 0x7fffffff, 5);
  payload.copy(h, 9);
  return h;
}

test('HTTP/2 streams split across SSL records become whole requests, paired by stream id', () => {
  seq = 1;
  const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  const settings = h2Frame(4, 0, 0, Buffer.alloc(0));
  const authority = Buffer.from('418cf1e3c2e5f23a6ba0ab90f4ff', 'hex');
  const postHeaders = Buffer.concat([
    Buffer.from('8387', 'hex'),
    Buffer.from([0x44, 0x08]), Buffer.from('/v1/feed'),
    authority,
  ]);
  const post = h2Frame(1, 0x4, 1, postHeaders);
  const postBody = h2Frame(0, 0x1, 1, Buffer.from('a=1&b=2'));
  // Stream 3 reuses the dynamic-table :authority from stream 1 (index 62).
  const getHeaders = Buffer.concat([
    Buffer.from('8287be', 'hex'),
    Buffer.from([0x44, 0x07]), Buffer.from('/health'),
  ]);
  const get = h2Frame(1, 0x5, 3, getHeaders);
  const client = Buffer.concat([preface, settings, post, postBody, get]);
  const cut = 40;
  const gz = zlib.gzipSync(Buffer.from('{"ok":1}'));
  const res1Headers = Buffer.concat([
    Buffer.from([0x48, 0x03]), Buffer.from('201'),
    Buffer.from([0x40, 0x10]), Buffer.from('content-encoding'),
    Buffer.from([0x04]), Buffer.from('gzip'),
  ]);
  const server = Buffer.concat([
    settings,
    h2Frame(1, 0x5, 3, Buffer.from([0x88])),
    h2Frame(1, 0x4, 1, res1Headers),
    h2Frame(0, 0x1, 1, gz),
  ]);
  const out = assembleHttpExchanges([
    chunk('SSL_write', client.subarray(0, cut), { tsNs: 1 }),
    chunk('SSL_write', client.subarray(cut), { tsNs: 2 }),
    chunk('SSL_read', server, { tsNs: 3 }),
  ]);
  assert.equal(out.http2, 1);
  assert.equal(out.http2Idle, 0);
  assert.equal(out.exchanges.length, 2);
  const [first, second] = out.exchanges;
  assert.equal(first.label, 'POST https://www.example.com/v1/feed');
  assert.equal(first.status, '201');
  assert.equal(first.request?.bodyText, 'a=1&b=2');
  assert.equal(first.request?.complete, true);
  assert.equal(first.response?.bodyText, '{"ok":1}');
  assert.equal(first.response?.decoded, true);
  assert.equal(second.label, 'GET https://www.example.com/health');
  assert.equal(second.status, '200');
  assert.equal(second.request?.complete, true);
  assert.equal(second.response?.bodyBytes, 0);
  assert.equal(out.consumedIds.length, 0);
});

test('an HTTP/2 connection that has not sent a request does not stay as raw frames', () => {
  seq = 1;
  const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  const settings = Buffer.alloc(9);
  settings[3] = 4;
  const out = assembleHttpExchanges([
    chunk('SSL_write', Buffer.concat([preface, settings]), { id: 7, tsNs: 1 }),
  ]);
  assert.equal(out.http2, 1);
  assert.equal(out.http2Idle, 1);
  assert.equal(out.exchanges.length, 0);
  assert.deepEqual(out.consumedIds, [7]);
});

test('an HTTP/2 GOAWAY is not a request', () => {
  seq = 1;
  const goaway = Buffer.from('0000080700000000000000001300000000', 'hex');
  const out = assembleHttpExchanges([
    chunk('SSL_read', goaway, { id: 528, tsNs: 1 }),
  ]);
  assert.equal(out.exchanges.length, 0);
  assert.deepEqual(out.consumedIds, [528]);
});

test('HTTP/2 preface is counted and not turned into a fake HTTP/1 exchange', () => {
  seq = 1;
  const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
  const out = assembleHttpExchanges([
    chunk('SSL_write', preface + '\x00\x00\x00\x04', { tsNs: 1 }),
    chunk('SSL_read', 'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nZ', { tsNs: 2 }),
  ]);
  assert.equal(out.http2, 1);
  assert.equal(out.exchanges.length, 0);
});

test('records without an SSL pointer are counted and not paired', () => {
  seq = 1;
  const out = assembleHttpExchanges([
    chunk('SSL_write', 'GET /a HTTP/1.1\r\nHost: h\r\n\r\n', { conn: '', tsNs: 1 }),
    chunk('SSL_read', 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', { conn: '', tsNs: 2 }),
  ]);
  assert.equal(out.noConn, 2);
  assert.equal(out.exchanges.length, 0);
});

test('deflate response body is inflated', () => {
  seq = 1;
  const raw = Buffer.from('hello-deflate');
  const z = zlib.deflateSync(raw);
  const resp = Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: ${z.length}\r\n\r\n`),
    z,
  ]);
  const out = assembleHttpExchanges([
    chunk('SSL_write', 'GET /d HTTP/1.1\r\nHost: h\r\n\r\n', { tsNs: 1 }),
    chunk('SSL_read', resp, { tsNs: 2 }),
  ]);
  assert.equal(out.exchanges[0].response?.bodyText, 'hello-deflate');
  assert.equal(out.exchanges[0].response?.decoded, true);
});

import test from 'node:test';
import assert from 'node:assert/strict';

import { httpCapturePreview, previewForCapture } from '../src/state.ts';

test('request preview is the method plus URL, using the Host header', () => {
  const text = [
    'GET /api/v549/user/push/setting/get HTTP/1.1',
    'request-page: Android_IMChat',
    'Host: api.example.com',
    '',
  ].join('\r\n');
  assert.equal(httpCapturePreview(text), 'GET https://api.example.com/api/v549/user/push/setting/get');
});

test('dotted list preview still yields the request target when Host was truncated', () => {
  const dotted = 'GET /api/v549/user/push/setting/get HTTP/1.1..request-page: Android_IMChat...';
  assert.equal(httpCapturePreview(dotted), 'GET /api/v549/user/push/setting/get');
});

test('response preview is only the status line', () => {
  assert.equal(
    httpCapturePreview('HTTP/1.1 200 OK\r\nServer: openresty/1.9.15.1\r\n\r\n'),
    'HTTP/1.1 200 OK',
  );
});

test('TLS ingest stores the URL instead of the raw header dump', () => {
  const raw = 'POST /index/manbo HTTP/1.1\r\nHost: live.example\r\n\r\n';
  const hex = Buffer.from(raw, 'latin1').toString('hex');
  assert.equal(previewForCapture('SSL_write', hex), 'POST https://live.example/index/manbo');
  assert.equal(previewForCapture('EVP_DigestUpdate', hex).startsWith('POST'), true);
});

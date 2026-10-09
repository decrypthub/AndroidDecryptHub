import test from 'node:test';
import assert from 'node:assert/strict';
import { listDeviceDir, readDeviceFile, summarizeFile } from '../src/fs_browse.ts';

test('an empty path is refused before anything is sent to the agent', async () => {
  let calls = 0;
  const deps = { send: async () => { calls++; return { ok: true }; } };
  await assert.rejects(() => listDeviceDir('s1', '', deps), /need path/);
  await assert.rejects(() => readDeviceFile('s1', '', {}, deps), /need path/);
  assert.equal(calls, 0);
});

test('directory listings pass entries and the truncation flag through unchanged', async () => {
  const r = await listDeviceDir('s1', '/data/local/tmp', {
    send: async (_s, op, args) => {
      assert.equal(op, 'list_dir');
      assert.equal(args.path, '/data/local/tmp');
      return { ok: true, path: '/data/local/tmp', count: 2, truncated: true, entries: [
        { name: 'a.so', type: 'f', size: 10, mode: 420, mtime: 1 },
        { name: 'sub', type: 'd', size: -1, mode: 493, mtime: 2 },
      ] };
    },
  });
  assert.equal(r.truncated, true);
  assert.equal(r.count, 2);
  assert.deepEqual(r.entries.map((e) => e.name), ['a.so', 'sub']);
});

test('a failed listing fails loud with the errno message', async () => {
  await assert.rejects(() => listDeviceDir('s1', '/nope', { send: async () => ({ ok: false, error: 'opendir errno 13 (Permission denied)' }) }), /opendir errno 13/);
});

test('reading a text file decodes it and reports the bytes honestly', async () => {
  const body = 'hello\nworld\n';
  const r = await readDeviceFile('s1', '/data/local/tmp/x.txt', {}, {
    send: async (_s, op, args) => {
      assert.equal(op, 'read_file');
      assert.equal(args.path, '/data/local/tmp/x.txt');
      return { ok: true, path: args.path, size: body.length, truncated: false, b64: Buffer.from(body).toString('base64') };
    },
  });
  assert.equal(r.bytes, body.length);
  assert.equal(r.binary, false);
  assert.equal(r.textPreview, body);
  assert.equal(r.lineCount, 3);
  assert.equal(r.b64, undefined);   // base64 is opt-in: a 1MB blob must not ride along by default
});

test('binary detection and the printable preview come from the bytes, not from the file name', () => {
  const bin = summarizeFile(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x41, 0xff]));
  assert.equal(bin.binary, true);
  assert.equal(bin.textPreview, '.ELF..A.');
  const text = summarizeFile(Buffer.from('abc\tdef'));
  assert.equal(text.binary, false);
  assert.equal(text.textPreview, 'abc\tdef');
});

test('a truncated read is reported as truncated, never as the whole file', async () => {
  const r = await readDeviceFile('s1', '/big.bin', { includeBase64: true }, {
    send: async () => ({ ok: true, path: '/big.bin', size: 1048576, truncated: true, b64: Buffer.alloc(8, 65).toString('base64') }),
  });
  assert.equal(r.truncated, true);
  assert.equal(r.size, 1048576);
  assert.equal(r.bytes, 8);
  assert.equal(typeof r.b64, 'string');
});

test('a malformed base64 payload is refused instead of decoded into garbage', async () => {
  await assert.rejects(() => readDeviceFile('s1', '/x', {}, { send: async () => ({ ok: true, path: '/x', size: 3, b64: 'not-base64!' }) }), /malformed base64/);
});

test('includeText returns the whole text file, and omits it with a reason when it cannot', async () => {
  const send = (body: Buffer) => async () => ({ ok: true, path: '/f', size: body.length, truncated: false, b64: body.toString('base64') });
  const text = await readDeviceFile('s1', '/f', { includeText: true }, { send: send(Buffer.from('line1\nline2\n')) });
  assert.equal(text.text, 'line1\nline2\n');

  const bin = await readDeviceFile('s1', '/f', { includeText: true }, { send: send(Buffer.from([1, 0, 2])) });
  assert.equal(bin.text, undefined);
  assert.match(String(bin.textOmitted), /binary content/);

  const big = await readDeviceFile('s1', '/f', { includeText: true }, { send: send(Buffer.alloc(300_000, 65)) });
  assert.equal(big.text, undefined);
  assert.match(String(big.textOmitted), /300000 bytes/);

  const quiet = await readDeviceFile('s1', '/f', {}, { send: send(Buffer.from('abc')) });
  assert.equal(quiet.text, undefined);
  assert.equal(quiet.textOmitted, undefined);   // not asked for, so nothing to explain
});

import test from 'node:test';
import assert from 'node:assert/strict';

import { createHpackDecoder } from '../src/hpack.ts';

test('RFC 7541 C.4.1 then C.4.2: Huffman authority and the dynamic table', () => {
  const dec = createHpackDecoder();
  const first = Buffer.from('828684418cf1e3c2e5f23a6ba0ab90f4ff', 'hex');
  const a = dec.decode(first);
  assert.equal(a.ok, true);
  if (!a.ok) return;
  assert.deepEqual(a.fields.map((f) => `${f.name}: ${f.value}`), [
    ':method: GET',
    ':scheme: http',
    ':path: /',
    ':authority: www.example.com',
  ]);
  const second = Buffer.from('828684be5886a8eb10649cbf', 'hex');
  const b = dec.decode(second);
  assert.equal(b.ok, true);
  if (!b.ok) return;
  assert.deepEqual(b.fields.map((f) => `${f.name}: ${f.value}`), [
    ':method: GET',
    ':scheme: http',
    ':path: /',
    ':authority: www.example.com',
    'cache-control: no-cache',
  ]);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { scopeWithPackages, writeScopePackages } from '../src/scope_list.ts';

const original = {
  version: 2, mode: 'allowlist', packages: ['com.example.old'],
  policy: { 'com.example.old': { c: { d: false, h: false, t: false }, future: [1, { enabled: false }] } },
  futureExtension: { flags: [false, '值'], revision: 19 },
};

test('the production scope writer retains phone policy and unknown fields, including removed packages', async () => {
  let body = JSON.stringify(original), writes = 0;
  const io = { read: async () => 'su: warning\n' + body, write: async (text: string) => { writes++; body = text; } };
  const out = await writeScopePackages(['com.example.new', 'com.example.new', 'bad name', 'com.adh.manager'], {}, io);
  assert.equal(out.ok, true); assert.equal(writes, 1);
  assert.deepEqual(JSON.parse(body), { ...original, packages: ['com.example.new'] });
  assert.deepEqual(original.packages, ['com.example.old']);
  assert.equal(scopeWithPackages(body, [], { version: 1 }).version, 2, 'current document wins over stale metadata');
});

test('unreadable/corrupt/empty scope refuses to write instead of replacing it with defaults', async () => {
  for (const raw of ['', '{broken', '[]', '{"packages":null}']) {
    let writes = 0;
    const out = await writeScopePackages(['com.example.new'], {}, { read: async () => raw, write: async () => { writes++; } });
    assert.equal(out.ok, false); assert.equal(writes, 0);
  }
  const out = await writeScopePackages([], {}, { read: async () => { throw new Error('denied'); }, write: async () => assert.fail('must not write') });
  assert.equal(out.ok, false); assert.match(out.error!, /denied/);
});

test('a matching package readback does not hide lost hook policy', async () => {
  let reads = 0;
  const out = await writeScopePackages(['com.example.new'], {}, {
    read: async () => JSON.stringify(reads++ ? { version: 2, mode: 'allowlist', packages: ['com.example.new'] } : original),
    write: async () => {},
  });
  assert.equal(out.ok, false); assert.match(out.error!, /complete document differs/);
});

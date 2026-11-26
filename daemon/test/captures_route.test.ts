// The footer "共 N 条" must not become "whatever this page happened to return":
// `matched` counts the filtered selection in the retained window, independent of the page cursor.
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { handleHttp } from '../src/http/router.ts';
import { captures, pushCapture } from '../src/state.ts';

const saved = captures.slice();
const server = http.createServer((req, res) => {
  handleHttp(req, res).catch((e) => { res.writeHead(500); res.end(JSON.stringify({ error: String(e) })); });
});
let base = '';

before(async () => {
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
});
after(async () => {
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
  captures.length = 0;
  for (const c of saved) captures.push(c);
});

function seed() {
  captures.length = 0;
  for (let i = 0; i < 25; i++) {
    pushCapture({
      id: 5000 + i, sessionId: 'route-test', package: 'com.test.route', ts: 1000 + i,
      source: 'native', category: i % 5 === 0 ? 'net' : 'crypto', algo: 'A', op: 'o', func: 'f', hex: '',
    } as never);
  }
}

const get = async (query: string) => (await (await fetch(`${base}/api/captures?${query}`)).json()) as Record<string, any>;

test('matched counts the selection, and the page cursor does not change it', async () => {
  seed();
  const page1 = await get('package=com.test.route&category=crypto&limit=2');
  assert.equal(page1.returned, 2);
  assert.equal(page1.matched, 20, 'crypto records in the retained window, not the page length');
  assert.equal(page1.hasMore, true);
  const older = await get(`package=com.test.route&category=crypto&limit=2&beforeId=${page1.nextBeforeId}`);
  assert.equal(older.matched, 20, 'paging back must not shrink the total');
  assert.ok(older.returned > 0 && older.captures[0].id < page1.captures[0].id);
});

test('matched follows the same filters as the page, and total stays the whole package', async () => {
  seed();
  const both = await get('package=com.test.route&limit=5');
  assert.equal(both.matched, 25, 'no category filter: the whole package');
  assert.equal(both.total, 25);

  const q = await get('package=com.test.route&category=crypto&q=nothing-matches-this&limit=5');
  assert.equal(q.matched, 0, 'a query that matches nothing must report zero, not the page size');

  const ranged = await get('package=com.test.route&category=crypto&fromTs=1015&limit=5');
  assert.equal(ranged.matched, 8, 'fromTs narrows the selection the same way it narrows the page');
});

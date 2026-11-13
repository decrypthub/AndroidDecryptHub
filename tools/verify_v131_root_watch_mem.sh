#!/usr/bin/env bash
# Root-side hardware observation with extra slots and memory windows.
# The acceptance signal is the collector reading the bytes the sampled registers point at,
# at the moment of the hit, on a real thread - not a later re-read of a changed buffer.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_unit_pass 'root watch memory windows' root_watch.test.ts 3 || exit 1
cd "$ROOT"
if ! node --input-type=module - "$BASE" "$SERIAL" "$ROOT" <<'EOF'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pickSession } from './daemon/src/cli.ts';
const [base, serial, repo] = process.argv.slice(2);
const skip = reason => { console.log(`SKIP verify_v131_root_watch_mem (${reason})`); process.exit(0); };
if (!serial || !existsSync(join(repo, 'agent/build/adh-root-watch'))) skip('device and built root collector required');
const adb = args => { const r = spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8', timeout: 20000, windowsHide: true }); if (r.error || r.status !== 0) throw new Error(String(r.error ?? r.stderr)); return r.stdout.trim(); };
if (adb(['shell', 'su', '-c', 'id -u']) !== '0') skip('rooted verification device required');
const agents = await (await fetch(`${base}/api/agents`)).json();
if (!agents.some(a => a.online && a.package === 'com.adh.nativefixture')) skip('no online dedicated native verification host; never starts another process');
const target = pickSession(agents, 'com.adh.nativefixture', process.env.ADH_TEST_SESSION);
if (!target.starttimeTicks) skip('current agent hello starttimeTicks required');
const call = async (name, args = {}) => {
  const res = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session: target.sessionId, ...args } } }) });
  const r = await res.json(); if (r.error) throw new Error(JSON.stringify(r.error));
  const text = r.result?.content?.find(c => c.type === 'text')?.text;
  if (r.result?.isError) throw new Error(text);
  const value = JSON.parse(text); if (value.ok === false) throw new Error(JSON.stringify(value)); return value;
};
const uint = r => BigInt(r.result ?? r.resultDecimal);
const prepare = await call('root_watch', { action: 'prepare', serial });
assert.equal(prepare.selfTest.selfTest, true);
const lib = `/data/local/tmp/verify-v131-${Date.now()}.so`;
adb(['push', join(repo, 'agent/build/libadh_native_controls.so'), lib]);
await call('load_library', { path: lib });
const module = lib.split('/').at(-1);
const native = symbol => call('native_call', { module, symbol, args: [], confirm: true });
const tid = Number(uint(await native('adh_watch_start')));
const address = '0x' + uint(await native('adh_watch_address')).toString(16);
assert.notEqual(address, '0x0');
const run = await call('root_watch', {
  action: 'start', serial, tid, addr: address, width: 8, mode: 'w', durationMs: 3000, maxEvents: 8, stackBytes: 0,
  breakpoints: [{ addr: address, width: 8, mode: 'w' }],
  mem: ['x0:8', '@x0:8'],
});
// A daemon that predates this slice drops the new arguments; refuse to pretend it verified them.
if (!run.breakpoints || !run.mem) {
  await call('root_watch', { action: 'stop', id: run.id }).catch(() => {});
  skip('running daemon predates root_watch memory windows; restart the Host ADH Daemon and rerun');
}
assert.deepEqual(run.breakpoints, [`bp=${address}:8:w`]);
assert.deepEqual(run.mem, ['x0:8', '@x0:8']);
await native('adh_watch_trigger');
let status;
for (let i = 0; i < 120; i++) { status = await call('root_watch', { action: 'status', id: run.id }); if (!status.running) break; await new Promise(r => setTimeout(r, 50)); }
assert.equal(status.error, undefined);
assert.equal(status.summary.samples, 4, 'two writes x two hardware slots');
assert.equal(status.summary.malformed, 0);
const page = await call('root_watch', { action: 'read', id: run.id, limit: 32 });
assert.equal(page.events.length, 4);
assert.deepEqual([...new Set(page.events.map(e => e.bp))].sort(), [0, 1]);
const expected = ['8877665544332211', '1122334455667788'];
for (const event of page.events) {
  assert.equal(event.regs, undefined, 'registers must stay opt-in');
  assert.equal(event.mem.length, 2);
  assert.equal(event.mem[0].spec, 'x0:8');
  assert.equal(event.mem[0].addr, address, 'x0 held the watched address at the hit');
  assert.equal(event.mem[1].spec, '@x0:8');
  assert.equal(event.mem[1].addr, address, 'the dereferenced window is the same buffer');
  assert.ok(expected.includes(event.mem[1].hex), `unexpected stored value ${event.mem[1].hex}`);
}
console.log(`PASS verify_v131_root_watch_mem (${page.events.length} events, 2 slots, 2 memory windows, values ${expected.join('/')})`);
EOF
then
  exit 1
fi

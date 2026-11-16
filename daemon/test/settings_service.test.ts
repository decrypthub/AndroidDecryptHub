import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { promisify } from 'node:util';
import { mkdirSync, existsSync, readFileSync, rmSync, statSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const realExec = cp.execFile;
const realSpawn = cp.spawn;
cp.execFile = (() => { throw Error('ADB/device calls forbidden in settings fixture'); }) as unknown as typeof cp.execFile;
Object.defineProperty(cp.execFile, promisify.custom, { value: async (file: string, args: string[]) => {
  if (file === 'adb' && args.some(a => a.includes('cat /data/adb/adh/scope.json'))) {
    return { stdout: JSON.stringify({ version: 2, mode: 'allowlist', packages: ['com.example.fixture'] }), stderr: '' };
  }
  throw Error('real subprocess execution forbidden in settings fixture');
} });
cp.spawn = (() => { throw Error('child execution forbidden in settings fixture'); }) as unknown as typeof cp.spawn;
syncBuiltinESMExports();
// Block subprocesses BEFORE service modules capture/promisify the builtin bindings.
const { handleHttp } = await import('../src/http/router.ts');
const { handleMcp } = await import('../src/mcp.ts');
const { patchSettings } = await import('../src/settings_service.ts');
const { drainSession, forgetCaptureSession, startCaptureLoop } = await import('../src/service.ts');
const { appendCaptureLine } = await import('../src/capture_persist.ts');
const { agentSockets, captureTimers, captures, DATA_DIR, DEFAULT_SETTINGS, pending, sessions, SETTINGS_FILE, settings } = await import('../src/state.ts');

const server = http.createServer((req, res) => { handleHttp(req, res).catch(error => { res.writeHead(500); res.end(String(error)); }); });
let address: string;
before(async () => {
  assert.ok(resolve(DATA_DIR).startsWith(resolve(tmpdir()) + '\\') || resolve(DATA_DIR).startsWith(resolve(tmpdir()) + '/'), 'tests require a temporary data root');
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done));
  address = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
after(async () => {
  cp.execFile = realExec; cp.spawn = realSpawn; syncBuiltinESMExports();
  for (const timer of captureTimers.values()) clearInterval(timer);
  captureTimers.clear(); agentSockets.clear(); sessions.clear();
  await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
});

function reset() {
  for (const timer of captureTimers.values()) clearInterval(timer);
  captureTimers.clear(); forgetCaptureSession('fixture');
  Object.assign(settings, structuredClone(DEFAULT_SETTINGS));
  sessions.clear(); agentSockets.clear(); captures.length = 0;
  if (existsSync(SETTINGS_FILE)) {
    // This path was verified as temporary before any test could run.
    const st = statSync(SETTINGS_FILE);
    if (st.isDirectory()) rmSync(SETTINGS_FILE, { recursive: true }); else unlinkSync(SETTINGS_FILE);
  }
}

function fakeAgent(fail = false, native: any[] = []) {
  const calls: string[] = [];
  sessions.set('fixture', { sessionId: 'fixture', online: true, package: 'com.example.fixture', process: 'com.example.fixture', pid: 1 } as any);
  agentSockets.set('fixture', { destroyed: false, write(frame: Buffer) {
    const msg = JSON.parse(frame.subarray(5).toString('utf8')); calls.push(msg.op);
    queueMicrotask(() => pending.get(msg.id)?.resolve(msg.op === 'capture_drain'
      ? { ok: true, jcaptures: [], captures: native, count: native.length, complete: true, dropped: 0, seq: native.length, backlog: 0, drained: native.length }
      : fail ? { ok: false, error: 'fixture refused capture_stop' }
      : msg.op === 'capture_start' ? { ok: true, evp: 1 } : { ok: true }));
    return true;
  } } as any);
  startCaptureLoop('fixture', { skipArm: true });
  return calls;
}

async function via(entry: string, patch: unknown): Promise<{ status: number; body: any; isError?: boolean }> {
  if (entry === 'mcp') {
    let output: any;
    const response = { writeHead() { return this; }, end(text: string) { output = JSON.parse(text); } };
    await handleMcp(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'settings', arguments: { action: 'patch', patch } } }), response as any);
    return { status: 200, body: JSON.parse(output.result.content[0].text), isError: output.result.isError };
  }
  const response = await fetch(address + entry, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
  return { status: response.status, body: await response.json() };
}

for (const entry of ['mcp', '/api/config', '/api/settings/import']) {
  test(`${entry}: enable installs on the simulated scoped target`, async () => {
    reset(); settings.capture.enabled = false; const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: true } });
    assert.equal(result.body.ok, true); assert.equal(result.body.runtimeApplied, true);
    assert.ok(calls.includes('capture_start')); assert.equal(result.body.runtime.targets[0].ok, true);
    assert.equal(settings.capture.enabled, true);
  });

  test(`${entry}: disable waits for drain+stop and returns actual runtime application`, async () => {
    reset(); const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: false } });
    assert.equal(result.body.ok, true); assert.equal(result.body.persisted, true);
    assert.deepEqual(calls, ['capture_drain', 'capture_stop']);
    assert.deepEqual(result.body.runtime.targets, [{ session: 'fixture', ok: true }]);
    assert.equal(JSON.parse(readFileSync(SETTINGS_FILE, 'utf8')).capture.enabled, false);
  });

  test(`${entry}: saved config does not hide a failed target operation`, async () => {
    reset(); const calls = fakeAgent(true);
    const result = await via(entry, { capture: { enabled: false } });
    assert.equal(result.body.ok, false); assert.equal(result.body.persisted, true);
    assert.equal(result.body.runtimeApplied, false); assert.equal(result.body.runtime.targets[0].ok, false);
    assert.match(result.body.runtime.targets[0].error, /fixture refused/);
    assert.equal(entry === 'mcp' ? result.isError : result.status, entry === 'mcp' ? true : 502);
    assert.deepEqual(calls, ['capture_drain', 'capture_stop']);
  });

  test(`${entry}: persist failure changes neither live settings nor target`, async () => {
    reset(); mkdirSync(SETTINGS_FILE, { recursive: true }); const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: false } });
    assert.equal(result.body.ok, false); assert.equal(result.body.persisted, false);
    assert.equal(settings.capture.enabled, true); assert.deepEqual(calls, []);
    assert.equal(entry === 'mcp' ? result.isError : result.status, entry === 'mcp' ? true : 500);
    rmSync(SETTINGS_FILE, { recursive: true });
  });

  test(`${entry}: retention/UI patch preserves disk evidence and does not reinstall hooks`, async () => {
    reset(); const calls = fakeAgent();
    const pkg = 'com.example.retention';
    appendCaptureLine(DATA_DIR, { id: 1, ts: 1000, package: pkg, sessionId: 'old', hex: '41' } as any);
    const path = join(DATA_DIR, 'packages', pkg, 'captures.jsonl');
    const before = readFileSync(path);
    const result = await via(entry, { capture: { retain: 50, maxAgeDays: 1 }, ui: { displayCap: 70 } });
    assert.equal(result.body.ok, true); assert.equal(result.body.maintenanceRequired, true);
    assert.deepEqual(readFileSync(path), before); assert.deepEqual(calls, []);
    assert.equal(settings.ui.displayCap, 70);
  });
}

test('overlapping settings patches serialize persistence and runtime application', async () => {
  reset();
  let release!: () => void; let started!: () => void;
  const ready = new Promise<void>(r => { started = r; });
  const gate = new Promise<void>(r => { release = r; });
  const first = patchSettings({ capture: { enabled: false } }, async () => { started(); await gate; return { ok: true, targets: [] }; });
  await ready;
  const second = patchSettings({ ui: { displayCap: 77 } });
  await Promise.resolve();
  assert.equal(settings.ui.displayCap, DEFAULT_SETTINGS.ui.displayCap);
  release(); await first; await second;
  assert.equal(settings.ui.displayCap, 77); assert.equal(settings.capture.enabled, false);
});

test('invalid sections do not save a config or issue target operations', async () => {
  reset(); const calls = fakeAgent();
  const out = await patchSettings({ capture: [] });
  assert.equal(out.ok, false); assert.equal(out.persisted, false);
  assert.deepEqual(calls, []); assert.equal(existsSync(SETTINGS_FILE), false);
});

test('capture IDs continue above restored history after explicit initialization', async () => {
  reset(); captures.push({ id: 900000, package: 'com.example.old' } as any);
  fakeAgent(false, [{ func: 'SSL_write', hex: '41', tid: 1 }]);
  const out = await drainSession('fixture');
  assert.equal(out.ok, true);
  const emitted = captures.find(c => c.sessionId === 'fixture');
  assert.ok(emitted && emitted.id > 900000, 'new records must not reuse persisted capture IDs');
});

test('MCP and HTTP maintenance default to preview; deleting requires explicit confirmation', async () => {
  reset(); const calls = fakeAgent();
  const pkg = 'com.example.maintenance';
  appendCaptureLine(DATA_DIR, { id: 1, ts: 1000, package: pkg, hex: '41' } as any);
  const path = join(DATA_DIR, 'packages', pkg, 'captures.jsonl'); const bytes = readFileSync(path);
  for (const args of [{ action: 'maintenance' }, { action: 'maintenance', dryRun: false }]) {
    let response: any;
    await handleMcp(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'settings', arguments: args } }), {
      writeHead() { return this; }, end(text: string) { response = JSON.parse(text); },
    } as any);
    const body = JSON.parse(response.result.content[0].text);
    assert.equal(body.ok, args.dryRun === undefined);
    assert.deepEqual(readFileSync(path), bytes);
  }
  const preview = await (await fetch(address + '/api/maintenance')).json() as { dryRun: boolean; ok: boolean };
  assert.equal(preview.dryRun, true); assert.equal(preview.ok, true);
  const refused = await fetch(address + '/api/maintenance', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"dryRun":false}' });
  assert.equal(refused.status, 400); assert.deepEqual(readFileSync(path), bytes); assert.deepEqual(calls, []);
});

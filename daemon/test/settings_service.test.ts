import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import cp from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { promisify } from 'node:util';
import { mkdirSync, existsSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const sourceRoot=process.env.ADH_REFINEMENT_ROOT ? pathToFileURL(process.env.ADH_REFINEMENT_ROOT.replace(/\/$/,'')+'/daemon/src/') : new URL('../src/',import.meta.url);
const loadSource=(name:string)=>import(new URL(name,sourceRoot).href);
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
const { handleHttp } = await loadSource('http/router.ts');
const { handleMcp } = await loadSource('mcp.ts');
const { applyCaptureSettingsOnConnect, patchSettings } = await loadSource('settings_service.ts');
const { getOperations, operationsRoot } = await loadSource('operation_host.ts');
const { initializeOperatorAccess } = await loadSource('access_context.ts');
const operatorKey=initializeOperatorAccess(operationsRoot);
const { drainSession, forgetCaptureSession, startCaptureLoop } = await loadSource('service.ts');
const { appendCaptureLine } = await loadSource('capture_persist.ts');
const { agentSockets, captureTimers, captures, DATA_DIR, DEFAULT_SETTINGS, pending, restoreHostState, sessions, SETTINGS_FILE, settings } = await loadSource('state.ts');

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
  captureTimers.clear();
  for (const sid of sessions.keys()) forgetCaptureSession(sid);
  Object.assign(settings, structuredClone(DEFAULT_SETTINGS));
  sessions.clear(); agentSockets.clear(); captures.length = 0;
  if (existsSync(SETTINGS_FILE)) {
    // This path was verified as temporary before any test could run.
    const st = statSync(SETTINGS_FILE);
    if (st.isDirectory()) rmSync(SETTINGS_FILE, { recursive: true }); else unlinkSync(SETTINGS_FILE);
  }
}

function fakeAgent(fail = false, native: any[] = [], { sid = 'fixture', pkg = 'com.example.fixture' } = {}) {
  const calls: string[] = [];
  sessions.set(sid, { sessionId: sid, online: true, package: pkg, process: pkg, pid: sessions.size + 1, uid: 10001, starttimeTicks: '1' } as any);
  agentSockets.set(sid, { destroyed: false, write(frame: Buffer) {
    const msg = JSON.parse(frame.subarray(5).toString('utf8')); calls.push(msg.op);
    queueMicrotask(() => pending.get(msg.id)?.resolve(msg.op === 'capture_drain'
      ? { ok: true, jcaptures: [], captures: native, count: native.length, complete: true, dropped: 0, seq: native.length, backlog: 0, drained: native.length }
      : fail ? { ok: false, error: 'fixture refused capture_stop' }
      : msg.op === 'capture_start' ? { ok: true, evp: 1 } : { ok: true }));
    return true;
  } } as any);
  startCaptureLoop(sid, { skipArm: true });
  return calls;
}

async function via(entry: string, patch: unknown, withOperator = true): Promise<{ status: number; body: any; isError?: boolean }> {
  const snapshot=getOperations().snapshot('host');
  const metadata={expectedRevision:snapshot.revision,controlEpoch:snapshot.epoch,hostEpoch:snapshot.hostEpoch};
  if (entry === 'mcp') {
    let output: any;
    const response = { writeHead() { return this; }, end(text: string) { output = JSON.parse(text); } };
    await handleMcp(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'settings', arguments: { action: 'patch', patch, _operation:metadata } } }), response as any,{principal:{role:'operator',id:'test',source:'mcp-test'}});
    return { status: 200, body: JSON.parse(output.result.content[0].text), isError: output.result.isError };
  }
  const response = await fetch(address + entry, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Adh-Operation': JSON.stringify(metadata), ...(withOperator ? { 'X-Adh-Operator-Key': operatorKey } : {}) }, body: JSON.stringify(patch) });
  return { status: response.status, body: await response.json() };
}

for (const entry of ['mcp', '/api/config', '/api/settings/import']) {
  test(`${entry}: enable resumes draining without installing legacy Hook defaults`, async () => {
    reset(); settings.capture.enabled = false; const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: true } });
    assert.equal(result.body.ok, true); assert.equal(result.body.runtimeApplied, true);
    assert.deepEqual(calls, []); assert.equal(result.body.runtime.targets[0].ok, true);
    assert.equal(result.body.runtime.targets[0].skipped, 'drain-only; explicit hook plan required');
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
    reset(); settings.capture.enabled = true; mkdirSync(SETTINGS_FILE, { recursive: true }); const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: false } });
    assert.equal(result.body.ok, false); assert.equal(result.body.persisted, false);
    assert.equal(settings.capture.enabled, true); assert.deepEqual(calls, []);
    assert.equal(entry === 'mcp' ? result.isError : result.status, entry === 'mcp' ? true : 500);
    rmSync(SETTINGS_FILE, { recursive: true });
  });

  test(`${entry}: checking one algorithm installs that family`, async () => {
    reset(); const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: true, families: { digest: false, hmac: false, symmetric: true, asymmetric: false, tls: false, aead: false } } });
    assert.equal(result.body.ok, true);
    assert.equal(settings.capture.enabled, true);
    assert.equal(settings.capture.families.symmetric, true);
    assert.equal(settings.capture.families.digest, false);
    assert.ok(calls.includes('capture_policy'));
    assert.ok(calls.includes('capture_start'));
    assert.ok(calls.indexOf('capture_policy') < calls.indexOf('capture_start'));
  });

  test(`${entry}: clearing every algorithm records the empty policy and does not install`, async () => {
    reset(); settings.capture.enabled = true; const calls = fakeAgent();
    const result = await via(entry, { capture: { enabled: false, families: { digest: false, hmac: false, symmetric: false, asymmetric: false, tls: false, aead: false } } });
    assert.equal(result.body.ok, true);
    assert.equal(settings.capture.enabled, false);
    assert.equal(settings.capture.families.symmetric, false);
    assert.ok(calls.includes('capture_stop'));
    assert.ok(calls.includes('capture_policy'));
    assert.equal(calls.includes('capture_start'), false);
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

test('the first algorithm check stores only that family', async () => {
  reset(); settings.capture.enabled = false; const calls = fakeAgent();
  const result = await patchSettings({ capture: { families: { symmetric: true } } });
  assert.equal(result.ok, true);
  assert.equal(settings.capture.enabled, true);
  assert.equal(settings.capture.families.symmetric, true);
  assert.equal(settings.capture.families.digest, false);
  assert.equal(settings.capture.families.hmac, false);
  assert.ok(calls.includes('capture_policy'));
  assert.ok(calls.includes('capture_start'));
});

test('an open hook plan keeps its session when another algorithm is checked', async () => {
  reset(); const calls = fakeAgent();
  sessions.set('planned', { sessionId: 'planned', online: true, package: 'com.example.planned', process: 'planned', pid: 2, policy: 'd=1,h=0,s=0,a=0,t=0,e=0,y=0' } as any);
  agentSockets.set('planned', { destroyed: false, write(frame: Buffer) {
    const msg = JSON.parse(frame.subarray(5).toString('utf8')); calls.push('planned:' + msg.op);
    queueMicrotask(() => pending.get(msg.id)?.resolve({ ok: true }));
    return true;
  } } as any);
  const dir = join(DATA_DIR, 'hook-plans', 'runs');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'run-1.json'), JSON.stringify({ session: 'planned', state: 'applied' }));
  const result = await patchSettings({ capture: { enabled: true, families: { digest: false, hmac: false, symmetric: true, asymmetric: false, tls: false, aead: false } } });
  assert.equal(result.ok, true);
  assert.equal(calls.filter(call => call.startsWith('planned:')).length, 0);
  assert.ok('runtime' in result && result.runtime);
  assert.equal(result.runtime.targets.find((row: { session: string }) => row.session === 'planned').skipped, 'hook-plan');
  assert.ok(calls.includes('capture_policy'));
});

test('clearing the last algorithm does not stop a session owned by an open hook plan', async () => {
  reset(); settings.capture.enabled = true;
  for (const key of Object.keys(settings.capture.families)) settings.capture.families[key] = false;
  settings.capture.families.symmetric = true;
  const calls = fakeAgent();
  sessions.set('planned', { sessionId: 'planned', online: true, package: 'com.example.planned', process: 'planned', pid: 2 } as any);
  agentSockets.set('planned', { destroyed: false, write(frame: Buffer) {
    const msg = JSON.parse(frame.subarray(5).toString('utf8')); calls.push('planned:' + msg.op);
    queueMicrotask(() => pending.get(msg.id)?.resolve({ ok: true }));
    return true;
  } } as any);
  const dir = join(DATA_DIR, 'hook-plans', 'runs');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'run-clear.json'), JSON.stringify({ session: 'planned', state: 'applied' }));
  const result = await patchSettings({ capture: { families: { symmetric: false } } });
  assert.equal(result.ok, true);
  assert.equal(settings.capture.enabled, false);
  assert.equal(calls.filter(call => call.startsWith('planned:')).length, 0);
  assert.ok('runtime' in result && result.runtime);
  assert.equal(result.runtime.targets.find((row: { session: string }) => row.session === 'planned').skipped, 'hook-plan');
  assert.ok(calls.includes('capture_stop'));
  assert.ok(calls.includes('capture_policy'));
});

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
  const snapshot=getOperations().snapshot('host');
  const refused = await fetch(address + '/api/maintenance', { method: 'POST', headers: { 'Content-Type': 'application/json','X-Adh-Operator-Key':operatorKey,'X-Adh-Operation':JSON.stringify({expectedRevision:snapshot.revision,controlEpoch:snapshot.epoch,hostEpoch:snapshot.hostEpoch}) }, body: '{"dryRun":false}' });
  assert.equal(refused.status, 400); assert.deepEqual(readFileSync(path), bytes); assert.deepEqual(calls, []);
});

const appFamiliesRoute = '/api/capture/families';
const appA = 'com.example.alpha';
const appB = 'com.example.beta';

function setOperatorControl(action: 'takeover' | 'release') {
  const engine = getOperations();
  const control = engine.snapshot('host');
  engine.control(action, 'host', { role: 'operator', id: 'test', source: 'settings-test' }, {
    expectedRevision: control.revision, controlEpoch: control.epoch, hostEpoch: control.hostEpoch,
  });
}

async function readAppFamilies(pkg: string) {
  const response = await fetch(address + appFamiliesRoute + '?package=' + encodeURIComponent(pkg));
  assert.equal(response.status, 200);
  const body = await response.json() as { package: string; capture: { enabled: boolean; families: Record<string, boolean> } };
  assert.equal(body.package, pkg);
  return body.capture;
}

test('an app family write requires a package and a single supported boolean', async () => {
  reset(); const calls = fakeAgent();
  setOperatorControl('takeover');
  const held = await via(appFamiliesRoute, { package: appA, family: 'digest', enabled: true }, false);
  assert.equal(held.body.code, 'CONTROL_HELD');
  setOperatorControl('release');
  for (const patch of [
    { family: 'digest', enabled: true },
    { package: '../wrong', family: 'digest', enabled: true },
    { package: appA, family: 'unknown', enabled: true },
    { package: appA, family: 'digest', enabled: 'false' },
    { package: appA, family: 'digest', enabled: true, capture: { enabled: true } },
  ]) {
    const result = await via(appFamiliesRoute, patch, false);
    assert.equal(result.status, 400);
    assert.equal(result.body.code, 'INVALID_SETTINGS');
  }
  assert.deepEqual(calls, []);
  assert.equal(existsSync(SETTINGS_FILE), false);
});

test('app family switches persist independently and dispatch only to that app', async () => {
  reset();
  const alpha = fakeAgent(false, [], { sid: 'alpha', pkg: appA });
  const alphaWorker = fakeAgent(false, [], { sid: 'alpha-worker', pkg: appA });
  const beta = fakeAgent(false, [], { sid: 'beta', pkg: appB });
  const betaBefore = await readAppFamilies(appB);

  const alphaResult = await via(appFamiliesRoute, { package: appA, family: 'digest', enabled: true }, false);
  assert.equal(alphaResult.status, 200, alphaResult.body.error);
  assert.deepEqual(alphaResult.body.runtime.targets.map(row => row.session), ['alpha', 'alpha-worker']);
  assert.deepEqual(alpha, ['capture_policy', 'capture_drain', 'capture_stop', 'capture_start']);
  assert.deepEqual(alphaWorker, alpha);
  assert.deepEqual(beta, []);
  assert.deepEqual(await readAppFamilies(appB), betaBefore);
  assert.equal(sessions.get('alpha')?.policy, 'd=1,h=0,s=0,a=0,t=0,e=0,y=0');

  const alphaBefore = await readAppFamilies(appA);
  const alphaCalls = [...alpha];
  const betaResult = await via(appFamiliesRoute, { package: appB, family: 'hmac', enabled: true }, false);
  assert.equal(betaResult.status, 200);
  assert.deepEqual(betaResult.body.runtime.targets.map(row => row.session), ['beta']);
  assert.deepEqual(await readAppFamilies(appA), alphaBefore);
  assert.deepEqual(alpha, alphaCalls);
  assert.equal(sessions.get('beta')?.policy, 'd=0,h=1,s=0,a=0,t=0,e=0,y=0');

  const dir = join(DATA_DIR, 'hook-plans', 'runs');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'alpha-worker.json'), JSON.stringify({ session: 'alpha-worker', state: 'applied' }));
  const betaCalls = [...beta];
  const stopped = await via(appFamiliesRoute, { package: appA, family: 'digest', enabled: false }, false);
  assert.equal(stopped.status, 200);
  assert.equal(stopped.body.runtime.targets.find(row => row.session === 'alpha-worker')?.skipped, 'hook-plan');
  assert.deepEqual(alpha.slice(alphaCalls.length), ['capture_drain', 'capture_stop', 'capture_policy']);
  assert.deepEqual(alphaWorker, alphaCalls);
  assert.deepEqual(beta, betaCalls);
  assert.equal(captureTimers.has('beta'), true);
  assert.equal(captureTimers.has('alpha-worker'), true);
  assert.equal((await readAppFamilies(appA)).enabled, false);
  const betaCapture = await readAppFamilies(appB);
  assert.equal(betaCapture.enabled, true);
  assert.equal(betaCapture.families.hmac, true);

  const disk = JSON.parse(readFileSync(SETTINGS_FILE, 'utf8'));
  assert.equal(disk.capture.enabled, false);
  assert.deepEqual(disk.capture.families, DEFAULT_SETTINGS.capture.families);
  assert.deepEqual(disk.capture.familiesByPackage[appA], stopped.body.capture.families);
  assert.deepEqual(disk.capture.familiesByPackage[appB], betaCapture.families);
  const legacyConfig = await (await fetch(address + '/api/config')).json() as { settings: { capture: object } };
  assert.equal(Object.hasOwn(legacyConfig.settings.capture, 'familiesByPackage'), false);
});

test('app selections restore before reconnect and retain an explicit all-off choice', async () => {
  reset();
  assert.equal((await via(appFamiliesRoute, { package: appA, family: 'digest', enabled: true }, false)).status, 200);
  assert.equal((await via(appFamiliesRoute, { package: appB, family: 'aead', enabled: true }, false)).status, 200);
  assert.equal((await via(appFamiliesRoute, { package: appB, family: 'aead', enabled: false }, false)).status, 200);
  const legacy = await via('/api/config', { capture: { enabled: true } }, false);
  assert.equal(legacy.status, 200);
  Object.assign(settings, structuredClone(DEFAULT_SETTINGS));
  restoreHostState();

  const alpha = fakeAgent(false, [], { sid: 'alpha-reconnected', pkg: appA });
  const beta = fakeAgent(false, [], { sid: 'beta-reconnected', pkg: appB });
  assert.equal((await applyCaptureSettingsOnConnect('alpha-reconnected'))?.ok, true);
  await applyCaptureSettingsOnConnect('beta-reconnected');
  assert.deepEqual(alpha, ['capture_policy', 'capture_drain', 'capture_stop', 'capture_start']);
  assert.equal(sessions.get('alpha-reconnected')?.policy, 'd=1,h=0,s=0,a=0,t=0,e=0,y=0');
  assert.deepEqual(beta, []);
  assert.equal((await readAppFamilies(appB)).enabled, false);
  assert.equal((await readAppFamilies('com.example.legacy')).enabled, true);
});

for(const entry of ['mcp','/api/config','/api/settings/import']){
 test(entry+': explicit disabled full snapshot preserves choices without starting capture',async()=>{
  reset();const calls=fakeAgent();const snapshot=structuredClone(DEFAULT_SETTINGS);snapshot.capture.enabled=false;
  const result=await via(entry,snapshot);
  assert.equal(result.body.ok,true);assert.equal(settings.capture.enabled,false);
  assert.deepEqual(settings.capture.families,DEFAULT_SETTINGS.capture.families);
  assert.equal(JSON.parse(readFileSync(SETTINGS_FILE,'utf8')).capture.enabled,false);
  assert.ok(calls.includes('capture_stop'));assert.equal(calls.includes('capture_start'),false);
 });
}

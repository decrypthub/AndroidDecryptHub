// Isolated upgrade rehearsal. Only the production scope initializer and loopback JVM run as children.
import assert from 'node:assert/strict';
import cp from 'node:child_process';
import {existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import http from 'node:http';
import {syncBuiltinESMExports} from 'node:module';
import type {AddressInfo} from 'node:net';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {FakeAdb, jvmManifest, startDeviceFixture} from '../device_fixture.ts';

assert.ok(existsSync(jvmManifest), 'Build :daemon:writeDeviceRpcFixtureClasspath first.');
const root = mkdtempSync(join(tmpdir(), 'adh-quick-start-'));
const deviceRoot = mkdtempSync(join(tmpdir(), 'adh-p3-jvm-'));
const hostRoot = join(root, 'adhd-data');
const stateFile = join(hostRoot, 'settings.json');
const scopeFile = join(deviceRoot, 'scope.json');
const endpointFile = join(deviceRoot, 'host.endpoint');
const legacySettings = {ui: {displayCap: 437}, capture: {enabled: false, autoDumpDex: false, retain: 73}};
const legacyScope = {
  version: 2, mode: 'allowlist', packages: ['com.example.sandbox'],
  policy: {'com.example.sandbox': {c: {d: false, h: true, s: true, a: true, t: true, e: true, y: true}}},
};
const settingsBytes = JSON.stringify(legacySettings, null, 2) + '\n';
const scopeBytes = JSON.stringify(legacyScope, null, 2) + '\n';
const endpointBytes = '127.0.0.1:8088\n';
const fakeAdb = new FakeAdb();
let device: Awaited<ReturnType<typeof startDeviceFixture>> | undefined;
let devices: import('../../src/devices.ts').Devices | undefined;
let engine: {close(): void} | undefined;
let server: http.Server | undefined;

function initializeScope(directory: string) {
  const script = fileURLToPath(new URL('../../../injector/zygisk/module/init-scope.sh', import.meta.url));
  const shell = process.env.ADH_UPGRADE_TEST_SHELL || (process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'sh');
  cp.execFileSync(shell, [script.replaceAll('\\', '/'), directory.replaceAll('\\', '/')], {timeout: 10000, windowsHide: true});
}

function assertPreserved() {
  assert.equal(readFileSync(stateFile, 'utf8'), settingsBytes);
  assert.equal(readFileSync(scopeFile, 'utf8'), scopeBytes);
  assert.equal(readFileSync(endpointFile, 'utf8'), endpointBytes);
}

try {
  mkdirSync(hostRoot);
  writeFileSync(stateFile, settingsBytes);
  writeFileSync(scopeFile, scopeBytes);
  writeFileSync(endpointFile, endpointBytes);
  initializeScope(deviceRoot);
  assertPreserved();
  const freshDevice = join(root, 'fresh-device');
  initializeScope(freshDevice);
  assert.deepEqual(JSON.parse(readFileSync(join(freshDevice, 'scope.json'), 'utf8')), {version: 1, mode: 'allowlist', packages: []});
  console.log('PASS scope initializer: fresh default and byte-for-byte legacy scope/endpoint preservation');

  process.env.ADH_DATA_DIR = hostRoot;
  delete process.env.ADH_CAPTURES_DIR;
  delete process.env.ADH_OPERATOR_TOKEN;
  process.env.ADH_SKIP_ARTIFACT_LOAD = '1';
  device = await startDeviceFixture(deviceRoot);
  fakeAdb.add('fixture-usb', '11', device);
  const forbidden = () => {throw new Error('Real subprocesses are unavailable in the upgrade sandbox.');};
  cp.execFile = forbidden as unknown as typeof cp.execFile;
  cp.execFileSync = forbidden as typeof cp.execFileSync;
  cp.spawn = forbidden as typeof cp.spawn;
  cp.spawnSync = forbidden as typeof cp.spawnSync;
  syncBuiltinESMExports();

  const {initializeHost} = await import('../../src/host_lifecycle.ts');
  const {initializeOperations} = await import('../../src/operation_host.ts');
  const {handleHttp} = await import('../../src/http/router.ts');
  const {setDevicesForTests} = await import('../../src/device_host.ts');
  const {Devices} = await import('../../src/devices.ts');
  const {AdbDeviceTransport} = await import('../../src/transport/adb_device.ts');
  initializeHost();
  engine = initializeOperations();
  devices = new Devices(join(hostRoot, 'devices.json'), new AdbDeviceTransport(fakeAdb.run));
  setDevicesForTests(devices);
  const listener = http.createServer((req, res) => {
    handleHttp(req, res).catch(() => {
      res.writeHead(500, {'content-type': 'application/json'});
      res.end(JSON.stringify({ok: false, error: 'Upgrade sandbox request failed'}));
    });
  });
  server = listener;
  await new Promise<void>((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const url = `http://127.0.0.1:${(listener.address() as AddressInfo).port}`;

  async function request(path: string, init?: RequestInit) {
    const response = await fetch(url + path, {signal: AbortSignal.timeout(15000), ...init});
    const body = await response.json() as Record<string, any>;
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.notEqual(body.ok, false, JSON.stringify(body));
    return {body, response};
  }

  const {body: config} = await request('/api/config');
  assert.deepEqual(config.settings.ui, legacySettings.ui);
  for (const [key, value] of Object.entries(legacySettings.capture)) assert.equal(config.settings.capture[key], value);
  assertPreserved();
  console.log('PASS Host upgrade: legacy settings loaded through /api/config without changing the files');

  const {body: disconnected} = await request('/api/devices?action=list');
  assert.deepEqual(disconnected.devices, []);
  assert.deepEqual(fakeAdb.commands, []);
  console.log('PASS initial state: no verified device connection');

  async function connectAndRead() {
    const {response} = await request('/api/devices?action=list');
    const control = JSON.parse(response.headers.get('x-adh-control') || 'null');
    assert.equal(control.resource, 'host');
    const {body: connected} = await request('/api/devices', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-adh-operation': JSON.stringify({expectedRevision: control.revision, controlEpoch: control.epoch, hostEpoch: control.hostEpoch}),
      },
      body: JSON.stringify({action: 'connect', transport: 'adb', serial: 'fixture-usb', transportId: '11'}),
    });
    const {deviceId, connectionId} = connected;
    assert.equal(connected._operation.state, 'succeeded');
    assert.equal(deviceId, device!.deviceId);
    assert.equal(connected.identityVerified, true);
    console.log('PASS connection: production Host and JVM device authenticated through synthetic USB');

    const query = new URLSearchParams({deviceId, connectionId});
    const {body: scope} = await request('/api/devices?action=call&method=scope.get&' + query);
    assert.deepEqual(scope.result.document, legacyScope);
    assertPreserved();
    console.log('PASS device scope: production reader returned the complete legacy configuration');

    const {body: diagnostic} = await request('/api/devices?action=info&' + query);
    assert.equal(diagnostic.deviceId, deviceId);
    assert.equal(diagnostic.connectionId, connectionId);
    assert.deepEqual(diagnostic.result.info, {model: 'JVM fixture', synthetic: true});
    assert.equal(diagnostic.result.stateRevision, 0);
    console.log('PASS diagnostic receipt:', JSON.stringify(diagnostic.result.info));
  }

  await connectAndRead();
  if (process.argv.includes('--serve')) {
    console.log('QUICK_START_URL=' + url + '/workbench?view=quick-start');
    const input = createInterface({input: process.stdin});
    const stop = () => input.close();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    for await (const line of input) {
      if (line.trim() === 'stop') break;
      if (line.trim() === 'disconnect') {
        devices.close();
        await fakeAdb.close();
        console.log('Sandbox device disconnected');
      }
    }
    input.close();
  }
} finally {
  devices?.close();
  if (server?.listening) {
    server.closeAllConnections();
    await new Promise<void>(resolve => server!.close(() => resolve()));
  }
  engine?.close();
  await fakeAdb.close();
  if (device) await device.close();
  else rmSync(deviceRoot, {recursive: true, force: true});
  rmSync(root, {recursive: true, force: true});
}

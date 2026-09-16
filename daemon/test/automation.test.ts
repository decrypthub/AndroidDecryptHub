import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { AutomationHub } from '../src/automation.ts';
import { mergeSettings, settings } from '../src/state.ts';

function connect(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => resolve(socket));
    socket.once('error', reject);
  });
}

function writeLine(socket: net.Socket, value: unknown) {
  socket.write(JSON.stringify(value) + '\n');
}

function nextJson(socket: net.Socket): Promise<any> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      socket.off('data', onData);
      socket.off('error', onError);
      resolve(JSON.parse(buffer.slice(0, newline)));
    };
    const onError = (error: Error) => {
      socket.off('data', onData);
      reject(error);
    };
    socket.on('data', onData);
    socket.once('error', onError);
  });
}

test('automation hub registers a device and round-trips a command', async () => {
  const hub = new AutomationHub();
  const port = await hub.listen(0);
  const socket = await connect(port);
  writeLine(socket, {
    t: 'hello',
    deviceId: 'test-device',
    model: 'Unit Test Phone',
    sdk: 35,
    caps: { tree: true, screenshot: true, gestures: true, setText: true, maxNodes: 300 },
  });
  const helloAck = await nextJson(socket);
  assert.equal(helloAck.t, 'helloAck');
  assert.equal(helloAck.deviceId, 'test-device');
  assert.equal(hub.status().connected, true);
  assert.equal(hub.status().devices[0].model, 'Unit Test Phone');

  const commandPromise = hub.cmd('observe', { mode: 'auto' }, 2_000);
  const command = await nextJson(socket);
  assert.equal(command.t, 'cmd');
  assert.equal(command.op, 'observe');
  assert.deepEqual(command.args, { mode: 'auto' });
  writeLine(socket, { t: 'result', id: command.id, ok: true, result: { mode: 'tree', nodes: [] } });
  const result = await commandPromise;
  assert.equal(result.mode, 'tree');

  socket.destroy();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(hub.status().connected, false);
  await hub.close();
});

test('automation hub fails loudly when no device is connected', async () => {
  const hub = new AutomationHub();
  await hub.listen(0);
  await assert.rejects(() => hub.cmd('observe', {}, 100), /no automation device connected/);
  await hub.close();
});

test('automation settings merge is opt-in and bounded', () => {
  const before = JSON.stringify(settings.automation);
  const applied = mergeSettings({
    automation: {
      enabled: true,
      screenshot: false,
      packages: [' com.example.one ', 'com.example.one', 'com.example.two'],
      maxNodes: 5000,
      screenshotMaxDimension: 100,
    },
  });
  assert.ok(applied.includes('automation'));
  assert.equal(settings.automation.enabled, true);
  assert.equal(settings.automation.screenshot, false);
  assert.deepEqual(settings.automation.packages, ['com.example.one', 'com.example.two']);
  assert.equal(settings.automation.maxNodes, 2000);
  assert.equal(settings.automation.screenshotMaxDimension, 480);
  Object.assign(settings.automation, JSON.parse(before));
});

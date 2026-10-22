import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MCP_CLIENTS, MCP_SERVER_NAME, adhConnectTarget, baseFromHost, isValidPackage, mcpClientCommand, mcpEndpoint, mcpOnboarding,
} from '../src/mcp_onboarding.ts';

// The onboarding payload is what an operator pastes into a terminal, so these tests are about the
// pasted result. The invariant that matters most is the transport: the published `adh` CLI speaks
// stdio (`adh mcp`), and its README says not to point a client at HTTP `/mcp`. A "helpful" HTTP URL
// creeping back into a client command is exactly the regression this file exists to catch.

const BASE = 'http://192.168.200.108:8088';
const URL = `${BASE}/mcp`;
const PKG = 'com.jingdong.app.mall';

test('every client has a unique id and registers the adh CLI, never an HTTP transport', () => {
  assert.deepEqual(MCP_CLIENTS.map((c) => c.id), ['claude', 'codex', 'vscode', 'cursor', 'json']);
  for (const spec of MCP_CLIENTS) {
    const command = mcpClientCommand(spec);
    assert.ok(command.includes('adh'), `${spec.id} does not invoke adh: ${command}`);
    assert.ok(!command.includes('http://'), `${spec.id} leaks an HTTP endpoint into the client: ${command}`);
    assert.ok(!command.includes('--transport http'), `${spec.id} still uses the HTTP transport: ${command}`);
  }
});

test('claude and codex register `adh mcp` as a stdio command after --', () => {
  assert.equal(mcpClientCommand(MCP_CLIENTS.find((c) => c.id === 'claude')!),
    `claude mcp add --scope user ${MCP_SERVER_NAME} -- adh mcp`);
  assert.equal(mcpClientCommand(MCP_CLIENTS.find((c) => c.id === 'codex')!),
    `codex mcp add ${MCP_SERVER_NAME} -- adh mcp`);
});

test('code/cursor receive a parseable stdio definition, not a sentence', () => {
  for (const [id, bin] of [['vscode', 'code'], ['cursor', 'cursor']] as const) {
    const cmd = mcpClientCommand(MCP_CLIENTS.find((c) => c.id === id)!);
    // Single-quoted for PowerShell and bash alike; the JSON itself must survive the quoting.
    const quoted = /^(\S+) --add-mcp '(.*)'$/.exec(cmd);
    assert.ok(quoted, `${id}: unexpected shape: ${cmd}`);
    assert.equal(quoted[1], bin);
    assert.deepEqual(JSON.parse(quoted[2]), { name: MCP_SERVER_NAME, command: 'adh', args: ['mcp'] });
  }
});

test('the json client is a complete mcpServers document with a stdio command', () => {
  const spec = MCP_CLIENTS.find((c) => c.id === 'json')!;
  assert.equal(spec.multiline, true);
  assert.deepEqual(JSON.parse(mcpClientCommand(spec)), {
    mcpServers: { [MCP_SERVER_NAME]: { command: 'adh', args: ['mcp'] } },
  });
});

test('the payload installs and connects the CLI, and keeps the live endpoint for scripts', () => {
  const cfg = mcpOnboarding(BASE, { tools: 79 });
  assert.equal(cfg.install, 'python -m pip install -U android-decrypt-hub');
  assert.equal(cfg.connect, `adh connect 192.168.200.108:8088`);
  assert.equal(cfg.endpoint, URL);
  assert.equal(cfg.pinnedEndpoint, `${BASE}/<package>/mcp`);
  assert.equal(cfg.connectPinned, `adh connect 192.168.200.108:8088/<package>`);
  assert.equal(cfg.tools, 79);
  assert.equal(cfg.clients.length, MCP_CLIENTS.length);
  // The client commands do not depend on the address at all — that is the point of `adh connect`
  // having saved it. If one starts embedding the endpoint, the two halves have drifted.
  for (const client of cfg.clients) assert.ok(!client.command.includes(cfg.endpoint), client.id);
});

test('a pinned package pins BOTH the endpoint and the saved connection', () => {
  const cfg = mcpOnboarding(BASE, { package: PKG, tools: 79 });
  assert.equal(cfg.endpoint, `${BASE}/${PKG}/mcp`);
  assert.equal(cfg.connect, `adh connect 192.168.200.108:8088/${PKG}`);
  assert.equal(cfg.pinnedEndpoint, null);
  assert.equal(cfg.connectPinned, null);
  // Pinning must not change the client registration: `adh mcp` reads the saved address.
  for (const client of cfg.clients) assert.ok(!client.command.includes(PKG), client.id);
});

test('an empty or whitespace package means "unpinned", not "/<empty>/mcp"', () => {
  for (const pkg of ['', '   ']) {
    const cfg = mcpOnboarding(BASE, { package: pkg });
    assert.equal(cfg.endpoint, URL);
    assert.equal(cfg.connect, 'adh connect 192.168.200.108:8088');
  }
});

test('the connect target drops the scheme and any trailing slash', () => {
  assert.equal(adhConnectTarget(`${BASE}/`), '192.168.200.108:8088');
  assert.equal(adhConnectTarget(`${BASE}//`, PKG), `192.168.200.108:8088/${PKG}`);
  assert.equal(adhConnectTarget('http://[::1]:8088'), '[::1]:8088');
});

test('a trailing slash on the base never becomes a doubled slash', () => {
  assert.equal(mcpEndpoint(`${BASE}/`), URL);
  assert.equal(mcpEndpoint(`${BASE}//`, 'com.a'), `${BASE}/com.a/mcp`);
});

test('package names are validated before they reach a URL path', () => {
  for (const ok of ['com.a', PKG, 'a_b.c1', 'x']) assert.equal(isValidPackage(ok), true, ok);
  for (const bad of ['', ' com.a', 'com.a ', 'com..a', 'com/a', 'com a', '../etc', 'com.a?x=1', '.com.a']) {
    assert.equal(isValidPackage(bad), false, bad);
  }
});

test('the Host header is the base only when it is a bare host[:port]', () => {
  assert.equal(baseFromHost('127.0.0.1:8088'), 'http://127.0.0.1:8088');
  assert.equal(baseFromHost('192.168.200.108:8088'), 'http://192.168.200.108:8088');
  assert.equal(baseFromHost('adb.local:8088'), 'http://adb.local:8088');
  assert.equal(baseFromHost('[::1]:8088'), 'http://[::1]:8088');
  // Anything that could smuggle a path, a scheme or a credential is refused, not "cleaned".
  for (const bad of ['', '   ', 'evil.example/x', 'user@host:8088', 'http://host:8088', 'host:99999', '[::1', 'host:']) {
    assert.equal(baseFromHost(bad), null, bad);
  }
});

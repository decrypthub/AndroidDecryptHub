import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MCP_CLIENTS, MCP_SERVER_NAME, baseFromHost, isValidPackage, mcpClientCommand, mcpEndpoint, mcpOnboarding,
} from '../src/mcp_onboarding.ts';

// The onboarding payload is what an operator pastes into a terminal, so these tests are about the
// pasted result, not about our formatting: each client command must contain a URL that was actually
// handed out, and the JSON-shaped ones must parse back into the object the client expects. A typo in
// a flag is not caught by typechecking and, unlike a broken route, it fails at the user's prompt with
// the client's own confusing error message.

const BASE = 'http://127.0.0.1:8088';
const URL = `${BASE}/mcp`;

test('every client has a unique id and a paste-able command containing the endpoint', () => {
  assert.deepEqual(MCP_CLIENTS.map((c) => c.id), ['claude', 'codex', 'vscode', 'cursor', 'json']);
  for (const spec of MCP_CLIENTS) {
    const command = mcpClientCommand(spec, URL);
    assert.ok(command.includes(URL), `${spec.id} does not carry the endpoint: ${command}`);
    assert.ok(command.length > URL.length, `${spec.id} is only a URL, not an install command`);
  }
});

test('the claude line registers an HTTP server at user scope', () => {
  const cmd = mcpClientCommand(MCP_CLIENTS.find((c) => c.id === 'claude')!, URL);
  assert.equal(cmd, `claude mcp add --transport http --scope user ${MCP_SERVER_NAME} ${URL}`);
});

test('the codex line uses its --url form (a stdio-style "codex mcp add adh <cmd>" would be wrong)', () => {
  const cmd = mcpClientCommand(MCP_CLIENTS.find((c) => c.id === 'codex')!, URL);
  assert.equal(cmd, `codex mcp add ${MCP_SERVER_NAME} --url ${URL}`);
});

test('code/cursor receive the server definition as parseable JSON, not as a sentence', () => {
  for (const [id, bin] of [['vscode', 'code'], ['cursor', 'cursor']] as const) {
    const cmd = mcpClientCommand(MCP_CLIENTS.find((c) => c.id === id)!, URL);
    // Single-quoted for PowerShell and bash alike; the JSON itself must survive the quoting.
    const quoted = /^(\S+) --add-mcp '(.*)'$/.exec(cmd);
    assert.ok(quoted, `${id}: unexpected shape: ${cmd}`);
    assert.equal(quoted[1], bin);
    assert.deepEqual(JSON.parse(quoted[2]), { name: MCP_SERVER_NAME, type: 'http', url: URL });
  }
});

test('the json client is a complete mcpServers document, parseable and name-keyed', () => {
  const spec = MCP_CLIENTS.find((c) => c.id === 'json')!;
  assert.equal(spec.multiline, true);
  const parsed = JSON.parse(mcpClientCommand(spec, URL));
  assert.deepEqual(parsed, { mcpServers: { [MCP_SERVER_NAME]: { type: 'http', url: URL } } });
});

test('the payload carries the endpoint, the pinned form and the live tool count', () => {
  const cfg = mcpOnboarding(BASE, { tools: 79 });
  assert.equal(cfg.guide, 'adh mcp');
  assert.equal(cfg.endpoint, URL);
  assert.equal(cfg.pinnedEndpoint, `${BASE}/<package>/mcp`);
  assert.equal(cfg.tools, 79);
  assert.equal(cfg.clients.length, MCP_CLIENTS.length);
  // Every client is built against the SAME endpoint the panel shows — no client drifts to a
  // different host, which is the failure that would silently point the AI at another machine.
  for (const client of cfg.clients) assert.ok(client.command.includes(cfg.endpoint), client.id);
});

test('a pinned package rewrites the endpoint everywhere and drops the placeholder line', () => {
  const cfg = mcpOnboarding(BASE, { package: 'com.jingdong.app.mall', tools: 79 });
  assert.equal(cfg.endpoint, `${BASE}/com.jingdong.app.mall/mcp`);
  assert.equal(cfg.pinnedEndpoint, null);
  for (const client of cfg.clients) {
    assert.ok(client.command.includes('/com.jingdong.app.mall/mcp'), `${client.id}: ${client.command}`);
    assert.ok(!client.command.includes('<package>'), `${client.id} still carries the placeholder`);
  }
  // The JSON client must still be valid JSON after the URL substitution.
  assert.equal(
    JSON.parse(cfg.clients.find((c) => c.id === 'json')!.command).mcpServers.adh.url,
    `${BASE}/com.jingdong.app.mall/mcp`,
  );
});

test('an empty or whitespace package means "unpinned", not "/<empty>/mcp"', () => {
  for (const pkg of ['', '   ']) assert.equal(mcpOnboarding(BASE, { package: pkg }).endpoint, URL);
});

test('a trailing slash on the base never becomes a doubled slash', () => {
  assert.equal(mcpEndpoint(`${BASE}/`), URL);
  assert.equal(mcpEndpoint(`${BASE}//`, 'com.a'), `${BASE}/com.a/mcp`);
});

test('package names are validated before they reach a URL path', () => {
  for (const ok of ['com.a', 'com.jingdong.app.mall', 'a_b.c1', 'x']) assert.equal(isValidPackage(ok), true, ok);
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

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  MCP_SERVER_NAME, adhClientConfig, adhConnectTarget, baseFromHost, isValidPackage, mcpOnboarding,
} from '../src/mcp_onboarding.ts';

// The onboarding payload is what an operator pastes into a terminal, so these tests are about the
// pasted result. Two invariants matter: the client config must be a stdio command (`adh mcp`), never
// an HTTP URL — the `adh` CLI's README forbids pointing a client at `/mcp` — and the panel's
// hard-coded default block must stay byte-identical to what the API generates, or the two halves
// drift the moment one is edited.

const BASE = 'http://192.168.200.108:8088';
const PKG = 'com.jingdong.app.mall';

test('the guide is three blocks: install, connect, config (and one footer line)', () => {
  const cfg = mcpOnboarding(BASE);
  assert.deepEqual(Object.keys(cfg).sort(), ['config', 'connect', 'install', 'note']);
  assert.equal(cfg.note, '仅限可信网络');
  assert.equal(cfg.install, 'pip install android-decrypt-hub');
  assert.equal(cfg.connect, 'adh connect 192.168.200.108:8088');
});

test('the client config is a stdio server, parseable, and carries no HTTP endpoint', () => {
  const cfg = mcpOnboarding(BASE);
  assert.ok(!cfg.config.includes('http'), 'an endpoint leaked into the client config');
  assert.deepEqual(JSON.parse(cfg.config), {
    mcpServers: { [MCP_SERVER_NAME]: { command: 'adh', args: ['mcp'] } },
  });
  // The label is what a human recognises in the client's MCP list.
  assert.equal(MCP_SERVER_NAME, 'adh');
});

test('a pinned package changes the connect target, and nothing else', () => {
  const plain = mcpOnboarding(BASE);
  const pinned = mcpOnboarding(BASE, { package: PKG });
  assert.equal(pinned.connect, `adh connect 192.168.200.108:8088/${PKG}`);
  assert.equal(pinned.install, plain.install);
  // `adh mcp` reads the saved address, so the client config cannot depend on the pin.
  assert.equal(pinned.config, plain.config);
});

test('an empty or whitespace package means "unpinned"', () => {
  for (const pkg of ['', '   ']) {
    assert.equal(mcpOnboarding(BASE, { package: pkg }).connect, 'adh connect 192.168.200.108:8088');
  }
});

test('the connect target drops the scheme and any trailing slash', () => {
  assert.equal(adhConnectTarget(`${BASE}/`), '192.168.200.108:8088');
  assert.equal(adhConnectTarget(`${BASE}//`, PKG), `192.168.200.108:8088/${PKG}`);
  assert.equal(adhConnectTarget('http://[::1]:8088'), '[::1]:8088');
});

test('the panel ships the same config block the API generates', () => {
  // The `<pre>` is filled from the API, but it also has a default so the panel still shows the paste
  // block before the fetch lands (or against a daemon that predates this route). A silent drift here
  // would hand the operator two different configs depending on timing.
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  // Line endings are not the contract: the checked-in page may use CRLF, and the browser normalises
  // `\r\n` to `\n` inside a <pre> anyway, so compare the text the operator would actually see.
  const block = (/<pre id="mcpConfig">([\s\S]*?)<\/pre>/.exec(html)?.[1] ?? '').replace(/\r\n/g, '\n');
  assert.equal(block, adhClientConfig());
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

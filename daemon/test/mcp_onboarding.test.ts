import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  MCP_SERVER_NAME, adhClientConfig, adhConnectTarget, baseFromHost, isValidPackage, mcpOnboarding,
} from '../src/mcp_onboarding.ts';

// The onboarding payload remains a stdio command (`adh mcp`) and takes its connection target
// from the Host request. Operators use the published CLI outside the analysis page.

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

test('analysis chrome has no onboarding; the opt-in advanced settings link is present in the built product', () => {
  const read=(file:string)=>readFileSync(new URL(file,import.meta.url),'utf8');
  const html=read('../public/index.html'),app=read('../../panel/src/App.vue'),advanced=read('../../panel/src/components/AdvancedHostSettings.vue');
  assert.doesNotMatch(html,/\bmcp(?:Btn|Mask|Install|Connect|Config)\b/);
  assert.doesNotMatch(app,/\/api\/mcp\/config|mcpOnboarding|McpOnboarding/);
  assert.match(advanced,/href="\/api\/mcp\/config" target="_blank"/);
  assert.doesNotMatch(advanced.split('</script>')[0],/\/api\/mcp\/config/);
  assert.ok(html.includes('/api/mcp/config'),'advanced action absent from built artifact');
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

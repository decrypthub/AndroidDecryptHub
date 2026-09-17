import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { AutomationHub } from '../src/automation.ts';
import { mergeSettings, settings } from '../src/state.ts';
import { agentWaitSightings, findAgentWaitMatch, hasAgentWaitFilters } from '../src/agent_events.ts';
import { implicitSelectorFor, selectorFrom } from '../src/phone_selectors.ts';
import { PhoneSkillStore, resolveSkillInputs, validateSkillName, validateSkillParams, validateSkillSteps } from '../src/phone_skills.ts';
import { renderScreenText } from '../src/phone_text.ts';
import { readPath, resolveTemplates } from '../src/phone_templates.ts';
import { normalizeAxis, swipePath } from '../src/phone_gestures.ts';
import { isSettled, noteSample, screenSignature } from '../src/phone_stability.ts';
import { blockedPackageFromError, isSystemPackage, needsDismissRetry, openOutcomeHint } from '../src/phone_foreground.ts';
import { blockedPackageNotices, clearBlockedPackages, recordBlockedPackage } from '../src/phone_blocked.ts';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

test('floating-window dismissal retry only targets system blockers', () => {
  assert.equal(isSystemPackage('com.oplus.battery'), true);
  assert.equal(isSystemPackage('com.android.settings'), true);
  assert.equal(isSystemPackage('com.heytap.quicksearchbox'), true);
  assert.equal(isSystemPackage('android'), true);
  assert.equal(isSystemPackage('com.tencent.mm'), false);
  assert.equal(isSystemPackage(''), false);
  assert.equal(needsDismissRetry('com.android.settings', 'com.oplus.battery'), true);
  assert.equal(needsDismissRetry('com.android.settings', 'com.android.settings'), false);
  assert.equal(needsDismissRetry('com.android.settings', 'com.tencent.mm'), false);
  assert.equal(needsDismissRetry('com.android.settings', null), false);
});
test('blocked package notices are bounded, deduped and reject junk', () => {
  clearBlockedPackages();
  assert.equal(recordBlockedPackage('com.oplus.battery'), true);
  assert.equal(recordBlockedPackage('com.oplus.battery'), true);
  assert.equal(recordBlockedPackage('not a package'), false);
  assert.equal(recordBlockedPackage(''), false);
  assert.equal(recordBlockedPackage('com.example.' + 'x'.repeat(200)), false);
  const notices = blockedPackageNotices();
  assert.equal(notices.length, 1);
  assert.equal(notices[0].package, 'com.oplus.battery');
  assert.equal(notices[0].count, 2);
  for (let index = 0; index < 20; index++) recordBlockedPackage(`com.example.p${index}`);
  assert.ok(blockedPackageNotices().length <= 8, 'notices stay bounded');
  // Newest first.
  assert.equal(blockedPackageNotices()[0].package, 'com.example.p19');
  clearBlockedPackages();
  assert.deepEqual(blockedPackageNotices(), []);
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


function waitEvent(seq: number, ts: number, type: string, data: any = {}) {
  return { seq, ts, type, data };
}

function waitCapture(id: number, ts: number, category: string, extra: any = {}) {
  return {
    id, ts, category, sessionId: 's_test', source: 'native', func: 'SSL_write', algo: 'tls', op: 'write',
    preview: 'GET /l', inl: 128, tid: 42, tsNs: 1, hex: 'ab'.repeat(400), ...extra,
  };
}

const T0 = 1_000_000;

test('agent wait filters are opt-in', () => {
  assert.equal(hasAgentWaitFilters({ textContains: 'Login' }), false);
  assert.equal(hasAgentWaitFilters({}), false);
  assert.equal(hasAgentWaitFilters({ captureCategory: 'crypto' }), true);
  assert.equal(hasAgentWaitFilters({ agentEvent: 'hook.hit' }), true);
});

test('agent wait matches a capture by category only after the wait started', () => {
  const old = waitCapture(1, T0 - 5_000, 'crypto');
  const fresh = waitCapture(2, T0 + 120, 'crypto', { algo: 'AES', preview: 'hello-world' });
  const hit = findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [old, fresh]);
  assert.equal(hit?.kind, 'capture');
  assert.equal(hit?.item.id, 2);
  assert.equal(hit?.item.preview, 'hello-world');
  assert.equal(hit?.item.hexLen, 800);
  assert.equal(hit?.item.hex, undefined);                          // oversized hex stays out of the payload
  assert.equal(findAgentWaitMatch({ captureCategory: 'net' }, { since: T0 }, [], [old, fresh]), null);
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 + 200 }, [], [old, fresh]), null);
});

test('agent wait ANDs same-kind filters and races event against capture', () => {
  const events = [waitEvent(7, T0 + 400, 'agent.maps', { count: 12 }), waitEvent(8, T0 + 900, 'hook.hit', { symbol: 'SSL_read' })];
  const captures = [waitCapture(3, T0 + 500, 'net', { func: 'SSL_write', preview: 'ADH_NET_MARKER_v1' })];
  assert.equal(findAgentWaitMatch({ captureCategory: 'net', captureContains: 'ADH_NET_MARKER_v1' }, { since: T0 }, events, captures)?.item.id, 3);
  assert.equal(findAgentWaitMatch({ captureCategory: 'net', captureContains: 'nope' }, { since: T0 }, events, captures), null);
  const newest = findAgentWaitMatch({ agentEventContains: 'hook.hit', captureCategory: 'net' }, { since: T0 }, events, captures);
  assert.equal(newest?.kind, 'event');
  assert.equal(newest?.item.type, 'hook.hit');
});

test('agent wait takes the newest exact event and compacts oversized data', () => {
  const big = { blob: 'x'.repeat(5_000) };
  const events = [waitEvent(1, T0 + 10, 'hook.hit', { symbol: 'first' }), waitEvent(2, T0 + 20, 'hook.hit', big)];
  const hit = findAgentWaitMatch({ agentEvent: 'hook.hit' }, { since: T0 }, events, []);
  assert.equal(hit?.item.seq, 2);
  assert.equal(hit?.item.data.truncated, true);
  assert.equal(hit?.item.data.bytes > 4_000, true);
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.miss' }, { since: T0 }, events, []), null);
});

test('agent wait cursor mode ignores the timestamp and only accepts newer records', () => {
  const older = waitCapture(41, T0 - 60_000, 'crypto', { preview: 'ADH手动_AES_#7_x' });
  const newer = waitCapture(42, T0 - 59_000, 'crypto', { preview: 'ADH手动_AES_#8_x' });
  const cursor = { afterCaptureId: 41 };
  const hit = findAgentWaitMatch({ captureCategory: 'crypto', captureContains: 'ADH手动_AES_#' }, cursor, [], [older, newer]);
  assert.equal(hit?.item.id, 42);
  const same = findAgentWaitMatch({ captureCategory: 'crypto' }, { afterCaptureId: 42 }, [], [older, newer]);
  assert.equal(same, null);
  const events = [waitEvent(9, T0 - 60_000, 'hook.hit', {}), waitEvent(10, T0 - 59_000, 'hook.hit', {})];
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.hit' }, { afterEventSeq: 9 }, events, [])?.item.seq, 10);
  assert.equal(findAgentWaitMatch({ agentEvent: 'hook.hit' }, { afterEventSeq: 10 }, events, []), null);
});

test('agent wait lookback still honours the timestamp window without a cursor', () => {
  const capture = waitCapture(50, T0 - 1_500, 'crypto');
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 - 5_000 }, [], [capture])?.item.id, 50);
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [capture]), null);
});

test('capture filters and payloads decode UTF-8 text out of the hex bytes', () => {
  const marker = 'ADH手动_AES_#7_订单金额=99.00元';
  const capture = waitCapture(60, T0 + 5, 'crypto', { hex: Buffer.from(marker, 'utf8').toString('hex'), preview: 'ADH......_AES_#7_............=99.00...' });
  const hit = findAgentWaitMatch({ captureCategory: 'crypto', captureContains: 'ADH手动_AES_#' }, { since: T0 }, [], [capture]);
  assert.equal(hit?.item.text, marker);
  const binary = waitCapture(61, T0 + 6, 'crypto', { hex: '00010203ff' });
  assert.equal(findAgentWaitMatch({ captureCategory: 'crypto' }, { since: T0 }, [], [binary])?.item.text, undefined);
});

test('a timed-out agent wait reports what actually arrived in the window', () => {
  const captures = [waitCapture(70, T0 + 100, 'net', { preview: 'GET /x' }), waitCapture(71, T0 + 200, 'crypto', { algo: 'MD5' })];
  const events = [waitEvent(10, T0 - 5_000, 'agent.hello', {}), waitEvent(11, T0 + 50, 'agent.maps', { count: 3 })];   // append order: oldest first
  const sightings = agentWaitSightings({ since: T0 }, events, captures, 2);
  assert.equal(sightings.totals.captures, 2);
  assert.equal(sightings.totals.events, 1);
  assert.deepEqual(sightings.captures.map((item: any) => item.id), [71, 70]);
  assert.equal(sightings.events[0].type, 'agent.maps');

  const cursorView = agentWaitSightings({ afterCaptureId: 70 }, [], captures, 2);
  assert.equal(cursorView.totals.captures, 1);
  assert.equal(cursorView.captures[0].id, 71);
});

test('agent wait sightings keep everything counted but bounded in size', () => {
  const captures = [waitCapture(80, T0 + 1, 'crypto'), waitCapture(81, T0 + 2, 'crypto'), waitCapture(82, T0 + 3, 'crypto')];
  const sightings = agentWaitSightings({ since: T0 }, [], captures, 2);
  assert.equal(sightings.captures.length, 2);
  assert.equal(sightings.totals.captures, 3);
});

test('set_text payload is never read as a selector', () => {
  // The field is targeted by id; `text` is what we are about to type, not a filter.
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed', resourceId: 'com.x:id/box' }), { resourceId: 'com.x:id/box' });
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed', editable: true }), { editable: true });
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'LSPosed' }), {});
  // An explicit selector still wins, including targeting a field by its, current text.
  assert.deepEqual(implicitSelectorFor('set_text', { action: 'set_text', text: 'new', selector: { text: 'old' } }), { text: 'old' });
});

test('other actions keep text as a selector and false stays a real filter', () => {
  assert.deepEqual(implicitSelectorFor('tap', { text: '搜索' }), { text: '搜索' });
  assert.deepEqual(implicitSelectorFor(undefined, { contentDescription: '搜索' }), { contentDescription: '搜索' });
  assert.deepEqual(selectorFrom({ text: 'a', clickable: false }), { text: 'a', clickable: false });
  assert.deepEqual(selectorFrom({ text: null, clickable: undefined }), {});
});

test('skill store validates, persists, lists and deletes recipes', () => {
  const file = join(mkdtempSync(join(tmpdir(), 'adh-skills-')), 'skills.json');
  const store = new PhoneSkillStore(file);
  assert.deepEqual(store.list(), []);

  store.save('open-crypto-tab', 'sandbox crypto tab', [{ type: 'act', args: { action: 'tap', text: '加解密' } }], false);
  assert.throws(() => store.save('open-crypto-tab', undefined, [{ type: 'act' }], false), /skill_exists/);

  const replaced = store.save('open-crypto-tab', 'v2', [{ type: 'wait', args: { activePackage: 'com.adh.sandbox' } }], true);
  assert.equal(replaced.steps.length, 1);
  assert.equal(store.get('open-crypto-tab')?.description, 'v2');
  store.noteRun('open-crypto-tab');

  const reloaded = new PhoneSkillStore(file);           // survives a daemon restart
  const listed = reloaded.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].name, 'open-crypto-tab');
  assert.equal(listed[0].runs, 1);
  assert.equal(reloaded.remove('open-crypto-tab'), true);
  assert.deepEqual(new PhoneSkillStore(file).list(), []);
});

test('skills reject unsupported steps, bad args and bad names', () => {
  assert.throws(() => validateSkillSteps([]), /non-empty/);
  assert.throws(() => validateSkillSteps([{ type: 'shell', args: { cmd: 'id' } }]), /unsupported type/);
  assert.throws(() => validateSkillSteps([{ type: 'act', args: 'nope' }]), /args must be an object/);
  assert.throws(() => validateSkillSteps(Array.from({ length: 31 }, () => ({ type: 'observe' }))), /at most 30/);
  assert.throws(() => validateSkillName('../etc/passwd'), /invalid_skill_name/);
  assert.throws(() => validateSkillName(''), /invalid_skill_name/);
  assert.equal(validateSkillName('open-crypto-tab'), 'open-crypto-tab');
});

test('a tampered skill file is dropped on load instead of executed', () => {
  const file = join(mkdtempSync(join(tmpdir(), 'adh-skills-')), 'skills.json');
  writeFileSync(file, JSON.stringify({ version: 1, skills: [{ name: 'evil', steps: [{ type: 'shell', args: { cmd: 'id' } }] }] }));
  assert.deepEqual(new PhoneSkillStore(file).list(), []);
  writeFileSync(file, 'not json at all');
  assert.deepEqual(new PhoneSkillStore(file).list(), []);
});

test('screen text rendering keeps refs, trims noise and stays bounded', () => {
  const tree = {
    activePackage: 'com.adh.sandbox',
    snapshotId: 's-1',
    truncated: false,
    screen: { width: 1080, height: 2412, rotation: 1 },
    cursor: { eventSeq: 7, captureId: 3 },
    nodes: [
      { ref: 'n0', className: 'android.widget.TextView', text: 'ADH · Android DecryptHub', bounds: [48, 126, 852, 214], enabled: true, clickable: false, actions: [] },
      { ref: 'n1', className: 'android.widget.EditText', hint: '搜索', resourceId: 'com.x:id/search_box', bounds: [1, 2, 3, 4], editable: true, clickable: true, enabled: true, actions: ['click', 'set_text'] },
      { ref: 'n2', className: 'android.widget.Button', contentDescription: '很长的描述'.repeat(30), bounds: [0, 0, 1, 1], enabled: false, actions: [] },
    ],
  };
  const text = renderScreenText(tree, { maxNodes: 2, maxTextLength: 20 });
  const lines = text.split('\n');
  assert.match(lines[0], /screen: com\.adh\.sandbox/);
  assert.match(lines[0], /1080x2412/);
  assert.match(lines[0], /cursor=7\/3/);
  assert.match(lines[1], /^\[n0\] TextView "ADH · Android Decry/);   // clipped to maxTextLength
  assert.match(lines[2], /\[n1\] EditText "搜索" id=search_box/);
  assert.match(lines[2], /editable/);
  assert.match(lines[2], /actions=set_text/);
  assert.equal(lines.filter((line) => line.startsWith('[')).length, 2);        // maxNodes respected
  assert.match(text, /1 more nodes/);
  assert.doesNotMatch(text, /clickable/);                                       // default click/enabled noise dropped
  assert.doesNotMatch(text, /\(enabled\)/);
});

test('screen text rendering survives an empty or malformed observation', () => {
  assert.match(renderScreenText({}), /screen: \?/);
  assert.match(renderScreenText({}), /\(no nodes\)/);
  assert.match(renderScreenText({ nodes: [], screenshot: { mimeType: 'image/jpeg', bytes: 10 } }), /screenshot: image\/jpeg 10B/);
});

test('open verification names the package that swallowed the launch', () => {
  const message = 'error: active package com.oplus.securitypermission is not in the automation allowlist';
  assert.equal(blockedPackageFromError(message), 'com.oplus.securitypermission');
  assert.equal(blockedPackageFromError('error: something else'), null);
  assert.equal(blockedPackageFromError(undefined), null);

  assert.equal(openOutcomeHint('com.adh.sandbox', 'com.adh.sandbox', false), '');
  const blocked = openOutcomeHint('org.matrix.vector.manager', 'com.oplus.securitypermission', true);
  assert.match(blocked, /open_blocked_by_system_dialog/);
  assert.match(blocked, /com\.oplus\.securitypermission/);
  assert.match(blocked, /v0\.3\.7/);
  assert.match(openOutcomeHint('com.x', 'com.y', false), /open_unverified: foreground is 'com\.y'/);
  assert.match(openOutcomeHint('com.x', null, false), /open_unverified: the foreground package could not be read/);
});

test('step templates resolve paths, keep raw types and stringify when embedded', () => {
  const outputs = {
    find_tab: {
      snapshotId: 's-42',
      count: 1,
      nodes: [{ ref: 'n7', text: '加解密', bounds: [1, 2, 3, 4] }],
    },
  };
  assert.deepEqual(resolveTemplates({ snapshotId: '{{find_tab.snapshotId}}', ref: '{{find_tab.nodes.0.ref}}' }, outputs), { snapshotId: 's-42', ref: 'n7' });
  assert.deepEqual(resolveTemplates({ nested: [{ value: '{{find_tab.count}}' }] }, outputs), { nested: [{ value: 1 }] });   // whole-string keeps the number
  assert.equal(resolveTemplates('tap {{find_tab.nodes.0.text}} now', outputs), 'tap 加解密 now');
  assert.equal(resolveTemplates({ plain: 'no templates' }, outputs).plain, 'no templates');
  assert.deepEqual(resolveTemplates({ whole: '{{find_tab}}' }, outputs).whole, outputs.find_tab);
  assert.equal(readPath(outputs.find_tab, 'nodes.0.bounds.3').value, 4);
  assert.equal(readPath(outputs.find_tab, 'nodes.9').found, false);
  assert.equal(readPath(outputs.find_tab, 'nope').found, false);
});

test('step templates fail loudly on unknown steps and missing paths', () => {
  assert.throws(() => resolveTemplates('{{later.ref}}', {}), /template_unknown_step/);
  assert.throws(() => resolveTemplates({ x: '{{known.missing}}' }, { known: { ref: 'n1' } }), /template_path_missing/);
  // a step cannot reference itself, because its own result is not in the map yet
  assert.throws(() => resolveTemplates('{{self.ref}}', {}), /template_unknown_step/);
});

test('skill params validate and inputs resolve with defaults, failing loudly when missing', () => {
  assert.deepEqual(validateSkillParams(undefined), []);
  assert.deepEqual(validateSkillParams(['tab', 'text-1']), ['tab', 'text-1']);
  assert.throws(() => validateSkillParams('tab'), /must be an array/);
  assert.throws(() => validateSkillParams(['input']), /reserved/);
  assert.throws(() => validateSkillParams(['ok', 'ok']), /duplicate/);
  assert.throws(() => validateSkillParams(['1bad']), /not a usable name/);
  assert.throws(() => validateSkillParams(Array.from({ length: 11 }, (_, i) => 'p' + i)), /at most 10/);

  const skill = { params: ['tab', 'text'], defaults: { text: 'hello' } };
  assert.deepEqual(resolveSkillInputs(skill, { tab: '加解密' }), { text: 'hello', tab: '加解密' });
  assert.deepEqual(resolveSkillInputs(skill, { tab: 'x', text: 'y' }), { text: 'y', tab: 'x' });
  assert.throws(() => resolveSkillInputs(skill, {}), /skill_missing_input: tab/);
  assert.throws(() => resolveSkillInputs(skill, 'nope'), /skill_missing_input: tab/);
  assert.deepEqual(resolveSkillInputs({ params: [] }, undefined), {});
});

test('a saved recipe keeps its param contract', () => {
  const file = join(mkdtempSync(join(tmpdir(), 'adh-skills-')), 'skills.json');
  const store = new PhoneSkillStore(file);
  store.save('open-tab', 'parametrised', [{ type: 'find', args: { contentDescription: '{{input.tab}}' } }], false, ['tab'], { tab: '状态' });
  const listed = new PhoneSkillStore(file).list();
  assert.deepEqual(listed[0].params, ['tab']);
  assert.deepEqual(listed[0].defaults, { tab: '状态' });
  assert.throws(() => store.save('bad', 'x', [{ type: 'observe' }], false, ['tab'], { nope: 1 }), /default for unknown param/);
});

test('gesture scroll geometry moves content the requested way', () => {
  const verticalForward = swipePath('vertical', true);
  assert.ok(verticalForward.y > verticalForward.y2, 'forward on a vertical list swipes up');
  const verticalBack = swipePath('vertical', false);
  assert.ok(verticalBack.y < verticalBack.y2, 'backward swipes down');
  const horizontalForward = swipePath('horizontal', true);
  assert.ok(horizontalForward.x > horizontalForward.x2, 'forward on a pager swipes left');
  const horizontalBack = swipePath('horizontal', false);
  assert.ok(horizontalBack.x < horizontalBack.x2, 'backward swipes right');
  for (const path of [verticalForward, verticalBack, horizontalForward, horizontalBack]) {
    for (const value of Object.values(path)) assert.ok(value > 0 && value < 1, 'fractions stay on screen');
  }
  assert.equal(normalizeAxis('horizontal'), 'horizontal');
  assert.equal(normalizeAxis('HORIZONTAL'), 'horizontal');
  assert.equal(normalizeAxis(undefined), 'vertical');
  assert.equal(normalizeAxis('nonsense'), 'vertical');
});

test('screen signature tracks visible changes and ignores volatile wrappers', () => {
  const base = {
    activePackage: 'com.adh.sandbox',
    snapshotId: 's-1',
    cursor: { eventSeq: 1, captureId: 1 },
    nodes: [
      { ref: 'n0', className: 'android.widget.TextView', text: 'ADH · Android DecryptHub', bounds: [1, 2, 3, 4], enabled: true },
      { ref: 'n1', className: 'android.widget.EditText', hint: '在这里输入…', bounds: [1, 5, 3, 9], editable: true, enabled: true },
    ],
  };
  const signature = screenSignature(base);
  assert.equal(screenSignature({ ...base, snapshotId: 's-2', cursor: { eventSeq: 9, captureId: 9 } }), signature, 'cursor/snapshot churn must not count');
  assert.equal(screenSignature({ ...base, nodes: [{ ...base.nodes[0], ref: 'nX' }, base.nodes[1]] }), signature, 'refs churn between snapshots and must not count');
  assert.notEqual(screenSignature({ ...base, nodes: [{ ...base.nodes[0], hint: 'changed hint' }, base.nodes[1]] }), signature);
  assert.notEqual(screenSignature({ ...base, nodes: [{ ...base.nodes[0], text: 'CHANGED' }, base.nodes[1]] }), signature);
  assert.notEqual(screenSignature({ ...base, activePackage: 'com.other' }), signature);
  assert.notEqual(screenSignature({ ...base, nodes: [base.nodes[0]] }), signature);
  assert.equal(screenSignature({}), screenSignature({ nodes: [] }));
});

test('settling needs the signature to hold still for the whole window', () => {
  const first = noteSample(null, 'sig-a', 1000);
  const same = noteSample(first, 'sig-a', 1300);
  assert.equal(same.changedAt, 1000, 'unchanged samples keep the original timestamp');
  assert.equal(isSettled(same, 1600, 600), true);
  assert.equal(isSettled(same, 1500, 600), false);
  const changed = noteSample(same, 'sig-b', 1700);
  assert.equal(changed.changedAt, 1700);
  assert.equal(isSettled(changed, 1800, 600), false);
});

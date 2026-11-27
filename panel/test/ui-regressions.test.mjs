import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const panel = resolve(process.env.ADH_PANEL_ROOT || fileURLToPath(new URL('../', import.meta.url)));
const require = createRequire(join(panel, 'package.json'));
const { reactive, ref, computed, watch } = require('vue');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const source = readFileSync(join(panel, 'src/components/AppDialog.vue'), 'utf8');
const api = await import(pathToFileURL(join(panel, 'src/api.ts')).href);

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  // Baseline fire-and-forget promises must not crash the test runner before assertions.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function dialog(overrides = {}) {
  const events = [];
  const store = reactive({
    apps: [{ package:'com.adh.sandbox', label:'Sandbox' }, { package:'com.example.other', label:'Other' }],
    chosenPkg:'com.adh.sandbox', scope:new Set(['com.adh.sandbox']),
    sessions:new Map(), devices:[{ key:'usb:test', serial:'TEST' }], selectedDeviceKey:'usb:test', localUsb:{},
  });
  const context = {
    computed, ref, watch,
    defineProps:() => reactive({ show:true }),
    defineEmits:() => (...args) => events.push(args),
    store, choosePackage:pkg => { store.chosenPkg = pkg; },
    appIconUrl:() => '', scopeAdd:async () => ({ok:true}), scopeRemove:async () => ({ok:true}),
    appControl:async () => ({ok:true}), observePackage:async () => ({ok:true}),
    ...overrides,
  };
  const script = parse(source).descriptor.scriptSetup.content.replace(/^import[^\n]*\n/gm, '');
  const js = ts.transpileModule(script, { compilerOptions:{ target:ts.ScriptTarget.ES2022, module:ts.ModuleKind.None } }).outputText;
  const load = new Function(...Object.keys(context), `${js}\nreturn { pick, toggleInject, control, apps, toastMsg, busy:typeof busy==='undefined'?null:busy, onlinePackages:typeof onlinePackages==='undefined'?null:onlinePackages };`);
  return { ...load(...Object.values(context)), store, events };
}

test('api: preserves a structured HTTP error instead of only its status', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error:'设备未就绪，请先重连' }), { status:409, statusText:'Conflict' });
  try { await assert.rejects(api.appControl('com.adh.sandbox','open'), { message:'设备未就绪，请先重连' }); }
  finally { globalThis.fetch = original; }
});

test('api: records exactly one performance sample for a failed request', async () => {
  const original = globalThis.fetch;
  const label = 'GET /api/ui-regression-failed';
  const before = api.perfStats().get(label)?.n || 0;
  globalThis.fetch = async () => new Response('{}', {status:503, statusText:'Service Unavailable'});
  try { await assert.rejects(api.api('/api/ui-regression-failed')); }
  finally { globalThis.fetch = original; }
  assert.equal(api.perfStats().get(label).n - before, 1);
});

test('api: non-JSON failures still retain a useful HTTP fallback', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response('upstream unavailable', {status:502, statusText:'Bad Gateway'});
  try { await assert.rejects(api.api('/api/ui-regression-fallback'), {message:'502 Bad Gateway'}); }
  finally { globalThis.fetch = original; }
});

test('pick: failure keeps the old application and the window open', async () => {
  const pending = deferred();
  const d = dialog({ observePackage:() => pending.promise });
  const result = d.pick('com.example.other');
  pending.reject(new Error('设备未就绪'));
  await result;
  assert.equal(d.store.chosenPkg, 'com.adh.sandbox');
  assert.equal(d.events.length, 0);
  assert.match(d.toastMsg.value, /设备未就绪/);
});

test('pick: a slow request does not submit another observation', async () => {
  const pending = deferred(); let calls = 0;
  const d = dialog({ observePackage:() => { calls++; return pending.promise; } });
  const a = d.pick('com.example.other');
  const b = d.pick('com.example.other');
  assert.equal(d.store.chosenPkg, 'com.adh.sandbox');
  assert.equal(calls, 1);
  pending.resolve({ok:true});
  await Promise.all([a,b]);
  assert.equal(d.store.chosenPkg, 'com.example.other');
  assert.equal(d.events.filter(e => e[0] === 'close').length, 1);
});

test('scope: a slow switch write cannot be submitted twice', async () => {
  const pending = deferred(); let calls = 0;
  const d = dialog({ scopeAdd:() => { calls++; return pending.promise; } });
  const a = d.toggleInject('com.example.other',true);
  const b = d.toggleInject('com.example.other',true);
  assert.equal(calls, 1);
  assert.equal(d.store.scope.has('com.example.other'), false);
  pending.resolve({ok:true}); await Promise.all([a,b]);
  assert.equal(d.store.scope.has('com.example.other'), true);
});

test('scope: preserves the daemon failure reason and does not change the switch', async () => {
  const d = dialog({ scopeAdd:async () => { throw new Error('手机已离线'); } });
  await d.toggleInject('com.example.other',true);
  assert.equal(d.store.scope.has('com.example.other'), false);
  assert.match(d.toastMsg.value, /手机已离线/);
});

test('control: open/restart/stop share one in-flight operation lock', async () => {
  const pending = deferred(); let calls = 0;
  const d = dialog({ appControl:() => { calls++; return pending.promise; } });
  const a = d.control('restart');
  const b = d.control('stop');
  assert.equal(calls, 1);
  pending.resolve({ok:true}); await Promise.all([a,b]);
  assert.match(d.toastMsg.value, /已重启/);
});

test('labels: injection permission is not described as a running injected session', () => {
  assert.match(source, /\['injected', '已开启'\]/);assert.match(source,/s\.deviceBinding\?\.serial===serial/);
  assert.match(source, /允许注入/);
  assert.match(source, /runningLabel\(a\)/);assert.doesNotMatch(source,/采集在线/);
});

test('controls: uses the component-library modal close and buttons', () => {
  assert.match(source, /preset="card"/);
  assert.doesNotMatch(source, /<button\b/);
  assert.match(source, /:loading=/);
});

test('pick: a changed device cannot receive the previous device selection', async () => {
  const pending = deferred();
  const d = dialog({ observePackage:() => pending.promise });
  const task = d.pick('com.example.other');
  d.store.selectedDeviceKey = 'usb:other';
  pending.resolve({ok:true}); await task;
  assert.equal(d.store.chosenPkg,'com.adh.sandbox');
  assert.equal(d.events.length,0);
});

test('scope: an unconfirmed reply is not shown as an enabled switch', async () => {
  const d = dialog({ scopeAdd:async () => ({}) });
  await d.toggleInject('com.example.other',true);
  assert.equal(d.store.scope.has('com.example.other'),false);
  assert.match(d.toastMsg.value,/未确认/);
});

test('feedback: success has a polite status rather than a hardcoded alert role', () => {
  assert.ok(/<p[^>]*role="status"/.test(source),'success must use a status element');
  assert.ok(!/<n-alert[^>]*:role=/.test(source),'NAlert owns role=alert and does not support overriding it');
});

test('settings: display pages do not repeat preference-storage rules', () => {
  const settings = readFileSync(join(panel,'src/components/SettingsPanel.vue'),'utf8');
  assert.ok(!settings.includes('外观与列表偏好仅保存在当前浏览器。'));
  assert.ok(!settings.includes('仅调整当前应用在此浏览器中的显示，不影响采集。'));
  assert.ok(settings.includes('settings-side-tabs'),'left settings navigation is retained on mobile');
});

test('status: online collection only uses the selected device session', () => {
  const d = dialog();
  d.store.devices[0].agent = {sessionId:'current'};
  d.store.sessions.set('current',{sessionId:'current',package:'com.adh.sandbox',online:true,deviceBinding:{serial:'TEST'}});
  d.store.sessions.set('foreign',{sessionId:'foreign',package:'com.example.other',online:true,deviceBinding:{serial:'OTHER'}});
  assert.ok(d.onlinePackages,'online state must be derived from sessions, not the injection scope');
  assert.equal(d.onlinePackages.value.has('com.adh.sandbox'),true);
  assert.equal(d.onlinePackages.value.has('com.example.other'),false);
});

test('switch: exposes its disabled state to assistive technology', () => {
  assert.ok(source.includes(':disabled="scopeDisabled(a.package)"'));
  assert.ok(source.includes(':aria-disabled="scopeDisabled(a.package)"'));
});

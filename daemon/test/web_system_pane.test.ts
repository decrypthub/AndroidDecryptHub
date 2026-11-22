// Web「系统」页的检测摘要是一行标题，但它和列表一样是 `.list-pane` 的直接子元素，而
// `.list-pane > div { flex:1 }` 给了所有子元素弹性 —— 没有显式 opt-out 时这一行会被撑成半个窗格，
// 列表连同里面的行都被挤到底部（真机截图里一眼能看出来）。这几条断言守住那个 opt-out，
// 以及「时间统一 24 小时制」这条同时改掉的显示规则。
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
// Comments are stripped so a selector group cannot swallow the `/* ... */` that precedes it.
const css = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/gi)]
  .map((m) => m[1]).join('\n').replace(/\/\*[\s\S]*?\*\//g, '');

/** Body of every rule whose selector matches exactly (`sel` is compared trimmed). */
function declared(sel: string): string {
  const out: string[] = [];
  for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) if (m[1].trim() === sel) out.push(m[2]);
  return out.join(';');
}
/** Class count: enough for the two selectors compared below. */
const classCount = (sel: string) => (sel.match(/\.[\w-]+/g) ?? []).length;

test('the detect summary opts out of the flex:1 the list needs', () => {
  const radar = declared('.list-pane > .detect-radar');
  assert.match(radar, /flex:\s*0\s+0\s+auto/, 'the summary must not grow: it is a title, not the list');
  assert.match(radar, /overflow:\s*visible/, 'the summary must not turn into a half-pane scroll box');
  assert.ok(classCount('.list-pane > .detect-radar') > classCount('.list-pane > div'),
    'two classes must beat `.list-pane > div`, so the layout does not depend on source order');
  assert.match(declared('.list-pane > div'), /flex:1/, 'the generic rule this opt-out exists for');
});

test('#sy-radar still sits above the banner and the list inside .list-pane', () => {
  assert.match(html,
    /<div class="list-pane">\s*<div class="capture-list-head">[\s\S]{0,160}?<\/div>\s*<div id="sy-radar"[^>]*>系统检测<\/div>\s*<div class="new-banner" id="sy-banner">[\s\S]{0,400}?<div id="sy-list"[^>]*><\/div>/);
});

test('the summary says what it is, and keeps the details in its tooltip', () => {
  assert.match(html, /function radarDetail\(r\)\{/);
  assert.match(html, /el\.textContent=state\?\('系统检测：'\+state\):'系统检测'/);
  assert.match(html, /el\.title=radarDetail\(r\)/);
});

test('capture rows render time through fmtTime, not the browser locale', () => {
  assert.doesNotMatch(html, /new Date\([^)]*\)\.toLocaleTimeString\(\)/,
    'a bare toLocaleTimeString() follows the browser locale and prints 12-hour AM/PM in a Chinese UI');
  assert.match(html, /function fmtTime\(ts\)\{[^\n]*hour12:false/);
});

test('the page script still parses as a classic script', () => {
  const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  assert.ok(blocks.length > 0, 'expected at least one inline script');
  for (const [i, src] of blocks.entries()) {
    assert.doesNotThrow(() => new vm.Script(src, { filename: `inline-${i}.js` }));
  }
});

test('device and APP context are separate and do not claim a legacy session binding', () => {
  const header=html.match(/<header>([\s\S]*?)<\/header>/)?.[1] ?? '';
  const app=html.match(/<section class="app-context"[^>]*>([\s\S]*?)<\/section>/)?.[1] ?? '';
  assert.match(header,/id="deviceContext"/);
  assert.doesNotMatch(header,/id="appBtn"|id="capStatePill"/);
  assert.match(app,/id="appBtn"/);
  assert.match(app,/id="capStatePill"/);
  assert.match(app,/设备归属未核验/);
  assert.match(html,/readPanelJson\('\/api\/devices\?action=list'\)/);
});

test('capture workbench places search, APP context and list tools in one toolbar', () => {
  assert.match(html,/<div class="filters" id="toolbar">[\s\S]*?id="tb-q"[\s\S]*?id="appContext"[\s\S]*?class="toolbar-actions capture-toolbar"/);
  assert.match(declared('.filters:not(.show) .capture-toolbar,.filters:not(.show) .advanced-filters'),/display:none/);
  assert.equal([...html.matchAll(/data-capture-back="(?:cc|sy|nt)"/g)].length,3);
});

test('the device display distinguishes verified connections, missing attribution data and a demo', () => {
  const fn=html.match(/(function describePanelDevices\(data\)\{[\s\S]*?\r?\n})\r?\nfunction renderPanelDeviceContext/)?.[1];
  assert.ok(fn);
  const describe=vm.runInNewContext('('+fn+')');
  const summarize=(data:unknown)=>JSON.parse(JSON.stringify(describe(data)));
  const peer={online:true,lastKnown:{info:{model:'甲型测试设备'}},
    connections:[{online:true,identityVerified:true,transport:'adb'}]};
  assert.deepEqual(summarize({ok:true,devices:[]}),{name:'设备未核验',link:''});
  assert.deepEqual(summarize({ok:true,devices:[peer]}),{name:'甲型测试设备',link:'USB'});
  assert.deepEqual(summarize({ok:true,devices:[peer,{...peer}]}),{name:'已核验 2 台',link:'在线'});
  assert.deepEqual(summarize({ok:true,devices:[{...peer,connections:[{online:true,identityVerified:false}]}]}),
    {name:'无在线设备',link:'有登记记录'});
  assert.deepEqual(summarize({ok:true,demo:true,devices:[]}),{name:'演示设备',link:'非真机',demo:true});
  assert.deepEqual(summarize(null),{name:'设备状态未知',link:'读取失败'});
});

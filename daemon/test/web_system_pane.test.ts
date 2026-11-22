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
    /<div class="list-pane">\s*<div class="capture-list-head">[\s\S]{0,160}?<\/div>\s*<div id="sy-radar"[^>]*>系统检测<\/div>\s*<div id="systemKinds"[\s\S]{0,510}?<\/div>\s*<div class="new-banner" id="sy-banner">[\s\S]{0,400}?<div id="sy-list"[^>]*><\/div>/);
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
  const connection=header.match(/class="header-context">([\s\S]*?)class="header-actions">/)?.[1] ?? '';
  const app=header.match(/<section class="app-context"[^>]*>([\s\S]*?)<\/section>/)?.[1] ?? '';
  assert.match(connection,/id="deviceContext"/);
  assert.doesNotMatch(connection,/id="appBtn"|id="capStatePill"/);
  assert.match(app,/id="appBtn"/);
  assert.match(app,/id="appChoices"[\s\S]*?当前 APP 会话[\s\S]*?id="sessRows"/);
  assert.match(app,/id="capStatePill"/);
  assert.match(app,/设备归属未核验/);
  assert.doesNotMatch(html,/id="processBtn"|id="processPopover"/);
  assert.match(html,/const menu=document\.getElementById\('appChoices'\)/);
  assert.match(html,/readPanelJson\('\/api\/devices\?action=list'\)/);
});

test('the narrow capture toolbar only filters the list and leaves APP scope in the header', () => {
  const toolbar=html.substring(html.indexOf('<div class="filters" id="toolbar">'),html.indexOf('<main>'));
  assert.match(toolbar,/id="tb-q"[\s\S]*?class="toolbar-actions capture-toolbar"/);
  assert.doesNotMatch(toolbar,/id="appContext"|id="appBtn"/);
  assert.match(declared('.filters'),/display:none/);
  assert.match(declared('.filters.show'),/display:flex/);
  assert.equal([...html.matchAll(/data-capture-back="(?:cc|sy|nt)"/g)].length,3);
});

test('record detail defaults to data, keeps an active view on refresh and resets on a new record', () => {
  const fn=html.match(/(function renderRecordDetail\([\s\S]*?\r?\n})\r?\nfunction selectRecordView/)?.[1];
  assert.ok(fn);
  const detail={dataset:{detailRecord:'',detailView:''},innerHTML:''};
  const render=vm.runInNewContext('('+fn+')',{document:{getElementById:()=>detail}});
  const views=[['data','数据详情','示例内容'],['event','事件信息','示例字段']];
  render('cc-detail','capture:1','',views);
  assert.equal(detail.dataset.detailView,'data');
  assert.match(detail.innerHTML,/data-record-view="data"[^>]*aria-selected="true"/);
  assert.match(detail.innerHTML,/data-record-panel="event"[^>]*hidden>示例字段/);
  assert.doesNotMatch(detail.innerHTML,/data-record-view="stack"/);
  detail.dataset.detailView='event';
  render('cc-detail','capture:1','',views);
  assert.match(detail.innerHTML,/data-record-view="event"[^>]*aria-selected="true"/);
  render('cc-detail','capture:2','',views);
  assert.equal(detail.dataset.detailView,'data');
});

test('same-model devices remain separate, mismatched connections stay offline and USB scope stays local', () => {
  const fn=html.match(/(function panelDeviceCatalog\(data\)\{[\s\S]*?\r?\n})\r?\nfunction panelDeviceStamp/)?.[1];
  assert.ok(fn);
  const catalog=vm.runInNewContext('('+fn+')');
  const device=(id:string,conn:Record<string,unknown>={})=>({
    deviceId:id,online:true,lastKnown:{info:{model:'同型号'}},
    connections:[{deviceId:id,connectionId:'connection-'+id,online:true,identityVerified:true,transport:'adb',...conn}],
  });
  const choices=catalog({ok:true,devices:[device('one'),device('two'),device('three',{deviceId:'wrong'})]});
  assert.equal(choices.length,4);
  assert.equal(choices[0].key,'device:one');
  assert.equal(choices[1].key,'device:two');
  assert.equal(choices[0].name,choices[1].name);
  assert.equal(choices[0].connectionId,'connection-one');
  assert.equal(choices[2].connectionId,'');
  assert.equal(choices[3].kind,'legacy');
  const local=catalog({ok:true,devices:[device('elsewhere')],localUsb:{model:'PGP110',online:true}});
  assert.equal(local.length,1);
  assert.equal(local[0].kind,'local');
  assert.equal(catalog(null).length,0);
});

test('device roster separates installed APPs and confirmed analysis scope membership', () => {
  const fn=html.match(/(function panelAppRoster\([\s\S]*?\r?\n})\r?\nfunction renderDeviceChrome/)?.[1];
  assert.ok(fn);
  const roster=vm.runInNewContext('('+fn+')');
  const list={applications:[{packageName:'com.example.a',label:'A'},{package:'com.example.b',label:'B'}]};
  const items=roster(list,{document:{packages:['com.example.b','com.example.scoped']}});
  assert.equal(items.find((item:any)=>item.package==='com.example.a').configured,false);
  assert.equal(items.find((item:any)=>item.package==='com.example.b').configured,true);
  assert.equal(items.find((item:any)=>item.package==='com.example.scoped').configured,true);
  assert.equal(roster(list,null)[0].configured,null);
});

test('late app and scope results do not bind to the next selected device', async () => {
  const fn=html.match(/(async function readRegisteredRoster\([\s\S]*?\r?\n})\r?\nfunction selectPanelDevice/)?.[1];
  assert.ok(fn);
  const a={key:'device:a',id:'a',connectionId:'conn-a',boot:'boot-a'};
  const b={key:'device:b',id:'b',connectionId:'conn-b',boot:'boot-b'};
  const pending:Array<() => void>=[];
  let active=a, renders=0;
  const c={
    URLSearchParams, registryApps:[] as unknown[], registryScopeError:'', rosterGeneration:1,
    currentDevice:()=>active, panelDeviceStamp:(d:typeof a)=>JSON.stringify(d),
    panelAppRoster:()=>[1], render:()=>{renders++},
    readPanelJson:(url:string)=>new Promise(resolve=>{
      const query=new URL(url,'http://localhost').searchParams;
      assert.equal(query.get('deviceId'),'a');
      assert.equal(query.get('connectionId'),'conn-a');
      assert.ok(['applications.list','scope.get'].includes(query.get('method')??''));
      pending.push(()=>resolve({ok:true,deviceId:'a',connectionId:'conn-a',bootId:'boot-a',result:{}}));
    }),
  };
  const read=vm.runInNewContext('('+fn+')',c);
  const request=read(a,1);
  assert.equal(pending.length,2);
  active=b;
  c.rosterGeneration++;
  pending.forEach(resolve=>resolve());
  await request;
  assert.deepEqual(c.registryApps,[]);
  assert.equal(renders,0);
});

test('file read/write events belong to system; files is a directory view, not an activity list', () => {
  const tab=html.match(/function mkTab\([\s\S]*?\r?\nTABS_MAIN\.forEach/)?.[0]??'';
  assert.match(tab,/loadArtifactLedger\(\)/);
  assert.doesNotMatch(tab,/loadInventory\(|filesInit\(|runOneClickUnpack\(/);
  assert.match(html,/makeCapPanel\('sy',\['system','file'\]\)/);
  assert.doesNotMatch(html,/makeCapPanel\('fl'|id="fl-list"/);
  assert.match(html,/id="systemKinds"[\s\S]{0,450}?data-system-kind="file"[^>]*>文件读写/);
  assert.match(html,/id="p-files"[\s\S]{0,250}?文件 · APP 目录/);
  assert.match(html,/id="directoryState" role="status"/);
  assert.match(html,/id="setScopeTab"[^>]*aria-label="分析范围"/);
  assert.match(html,/id="setCaptureTab"[^>]*aria-label="功能与 Hook 状态"/);
  assert.match(html,/id="setHooksTab"[^>]*aria-label="记录显示"/);
});

test('system type selection and directory availability refer to different data', () => {
  const kindFn=html.match(/(function matchesPanelKind\([\s\S]*?\r?\n})\r?\nfunction defaultRecordFilter/)?.[1];
  const dirFn=html.match(/(function appDirectoryStatus\([\s\S]*?\r?\n})\r?\nfunction renderAppDirectory/)?.[1];
  const accessFn=html.match(/(function hasAppDirectory\([\s\S]*?\r?\n})\r?\nfunction appDirectoryStatus/)?.[1];
  assert.ok(kindFn&&dirFn&&accessFn);
  const matches=vm.runInNewContext('('+kindFn+')');
  const hasAppDirectory=vm.runInNewContext('('+accessFn+')');
  const directory=vm.runInNewContext('('+dirFn+')',{hasAppDirectory});
  const system={key:'sy',cats:['system','file'],filter:{kind:'all'}};
  assert.equal(matches(system,'file'),true);
  assert.equal(matches(system,'system'),true);
  assert.equal(matches(system,'net'),false);
  system.filter.kind='file';
  assert.equal(matches(system,'system'),false);
  assert.equal(matches(system,'file'),true);
  assert.match(directory({kind:'local',online:true},'com.example.a'),/未接入目录读取.*目录内容未知/);
  assert.match(directory({kind:'local',online:false},'com.example.a'),/设备未连接/);
  assert.doesNotMatch(directory({kind:'local',online:true},'com.example.a'),/未上报|空目录/);
  assert.equal(hasAppDirectory({kind:'local',online:true,appFiles:true},'com.example.a'),true);
  assert.equal(hasAppDirectory({kind:'device',online:true,appFiles:true},'com.example.a'),false);
  assert.match(directory({kind:'local',online:true,appFiles:true},'com.example.a'),/授权的 APP files/);
});

test('artifact metadata requires the exact package and a known session', () => {
  const fn=html.match(/(function scopedArtifactRows\([\s\S]*?\r?\n})\r?\nasync function loadArtifactLedger/)?.[1];
  assert.ok(fn);
  const rows=vm.runInNewContext('('+fn+')');
  const e=(p:string,s:string)=>({type:'dump.new',ts:10,data:{package:p,sessionId:s,kind:'sample',size:17,tag:'owned',path:'unneeded'}});
  const result=rows([e('com.example.a','one'),e('com.example.b','one'),e('com.example.a','other')],'com.example.a',['one']);
  assert.equal(result.length,1);
  assert.equal(result[0].sessionId,'one');
  assert.equal(result[0].size,17);
  assert.equal(result[0].path,undefined);
});

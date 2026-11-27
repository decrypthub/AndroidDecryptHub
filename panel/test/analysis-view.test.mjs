import test from 'node:test';
import assert from 'node:assert/strict';
import {Vue,viewModel,setupComponent} from './support/setup-harness.mjs';

const cap = (id, algo='SHA-256', extra={}) => ({id,ts:1000+id,category:'crypto',package:'com.adh.sandbox',algo,inl:4,hex:'61626364',...extra});
function capture(kind='crypto', items=[cap(1),cap(2,'AES-CBC')]) {
  const store = Vue.reactive({chosenPkg:'com.adh.sandbox',selectedDeviceKey:'usb:A',capItems:items,capTotal:{crypto:items.length,system:0,net:0},capHasOlder:{crypto:false,system:false,net:false},sessionPkg:new Map(),wsState:'live',capDropped:0,capComplete:true});
  const limit = Vue.ref(300);
  const props = Vue.reactive({kind});
  const vm = setupComponent('CapturePanel.vue',props,{
    ...viewModel(),store,belongsToApp:c=>c.package===store.chosenPkg,capVisible:()=>true,
    capRemoveWhere:fn=>{store.capItems=store.capItems.filter(c=>!fn(c));},
    capDisplayCap:limit,DISPLAY_CAPS:[100,200,300,500,800],panelDisplay:{time:'time'},savePanelDisplay:()=>{},toast:()=>{},
    getCaptures:async()=>({captures:[],hasMore:false}),getExchanges:async()=>({exchanges:[]}),getCaptureDetail:async()=>({}),
    SearchOutline:{},CapDetail:{},ExchangeDetail:{},
  });
  return {...vm,store,props,limit};
}

test('paused capture searches and filters the frozen input rather than freezing the result',async()=>{
  const v=capture();
  try {
    v.filter.paused=true; await Vue.nextTick();
    v.filter.q='#1'; await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[1]);
    v.filter.q='';v.filter.cat=2;await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[2]);
    v.store.capItems.push(cap(3,'AES-CBC'));await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[2]);
    v.filter.paused=false;await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[2,3]);
  } finally {v.dispose();}
});

test('pausing an empty capture list does not start showing new arrivals',async()=>{
  const v=capture('crypto',[]);
  try {
    v.filter.paused=true;await Vue.nextTick();
    v.store.capItems.push(cap(1));await Vue.nextTick();
    assert.deepEqual(v.rows.value,[]);
    v.filter.paused=false;await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[1]);
  } finally {v.dispose();}
});

test('pausing with an existing search still permits a different search over the same snapshot',async()=>{
  const v=capture();
  try {
    v.filter.q='#1';v.filter.paused=true;await Vue.nextTick();
    v.filter.q='#2';await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[2]);
  } finally {v.dispose();}
});

test('network pause freezes exchanges including incomplete responses, while search remains live',async()=>{
  const v=capture('net',[]);
  try {
    v.exchanges.value=[{id:'a',seq:1,label:'GET /first',ts:1000,request:{bodyBytes:1}},{id:'b',seq:2,label:'GET /second',ts:2000,request:{bodyBytes:2}}];
    v.filter.paused=true;await Vue.nextTick();
    v.exchanges.value=[{id:'a',seq:1,label:'GET /first',ts:1000,response:{bodyText:'arrived later'}},{id:'b',seq:2,label:'GET /second',ts:2000},{id:'c',seq:3,label:'GET /third',ts:3000}];
    await Vue.nextTick();
    assert.deepEqual(v.matchedExchangesAll.value.map(e=>e.id),['a','b']);
    assert.equal(v.matchedExchangesAll.value.find(e=>e.id==='a').response,undefined);
    v.filter.q='first';await Vue.nextTick();
    assert.deepEqual(v.matchedExchangesAll.value.map(e=>e.id),['a']);
    v.filter.paused=false;await Vue.nextTick();
    assert.equal(v.matchedExchangesAll.value[0].response.bodyText,'arrived later');
  } finally {v.dispose();}
});

test('same-package device changes discard the prior frozen records and selection',async()=>{
  const v=capture();
  try {
    v.filter.paused=true;v.sel.value=1;await Vue.nextTick();
    v.store.selectedDeviceKey='usb:B';v.store.capItems=[];await Vue.nextTick();
    assert.equal(v.filter.paused,false);
    assert.equal(v.sel.value,null);
    assert.deepEqual(v.rows.value,[]);
  } finally {v.dispose();}
});

test('deleting a record also removes it from the paused snapshot',async()=>{
  const v=capture();
  try {
    v.filter.paused=true;await Vue.nextTick();
    await v.onCapDeleted(1);await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[2]);
  } finally {v.dispose();}
});

test('paused system filters can switch between file and system events in the same snapshot',async()=>{
  const v=capture('system',[cap(1,'',{category:'system',func:'access'}),cap(2,'',{category:'file',func:'open'})]);
  try {
    v.filter.kind='file';v.filter.paused=true;await Vue.nextTick();
    v.filter.kind='system';await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[1]);
  } finally {v.dispose();}
});

test('paused filtering does not invent new arrivals and a full-size buffer still counts new IDs',async()=>{
  const v=capture();
  try {
    v.filter.paused=true;await Vue.nextTick();
    v.filter.q='#1';await Vue.nextTick();
    v.filter.q='';await Vue.nextTick();
    assert.equal(v.newCount.value,0);
    v.store.capItems=[cap(2,'AES-CBC'),cap(3)];await Vue.nextTick();
    assert.equal(v.newCount.value,1);
    assert.deepEqual(v.rows.value.map(c=>c.id),[1,2]);
  } finally {v.dispose();}
});

test('size filters use known captured lengths and do not treat missing metadata as zero',async()=>{
  const v=capture('crypto',[cap(1,'SHA-256',{inl:undefined}),cap(2,'SHA-256',{inl:undefined,hex:undefined,outHex:'aa'})]);
  try {
    v.filter.paused=true;v.filter.min=4;await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[1]);
    v.filter.min=null;v.filter.max=4;await Vue.nextTick();
    assert.deepEqual(v.rows.value.map(c=>c.id),[1]);
  } finally {v.dispose();}
});

test('an empty network snapshot stays empty and does not observe later response mutations',async()=>{
  const v=capture('net',[]);
  try {
    v.filter.paused=true;await Vue.nextTick();
    v.exchanges.value=[{id:'a',seq:1,ts:1000,request:{bodyText:'initial'}}];await Vue.nextTick();
    assert.deepEqual(v.matchedExchangesAll.value,[]);
    v.filter.paused=false;v.filter.paused=true;await Vue.nextTick();
    v.exchanges.value[0].request.bodyText='mutated';await Vue.nextTick();
    assert.equal(v.matchedExchangesAll.value[0].request.bodyText,'initial');
  } finally {v.dispose();}
});

function detail(record) {
  return setupComponent('CapDetail.vue',Vue.reactive({detail:record}),{...viewModel(),store:{chosenPkg:'com.adh.sandbox'},toast:()=>{},deleteCapture:async()=>({ok:true}),CopyOutline:{}});
}
function fact(html,label) {
  const match=html.match(new RegExp(`<dt>${label}</dt>\\s*<dd[^>]*>(.*?)</dd>`,'s'));
  assert.ok(match,`missing ${label}`);
  return match[1].replace(/<[^>]+>/g,'').trim();
}

test('actual rendered event information agrees with captured output even without outl',async()=>{
  const v=detail(cap(1,'AES-CBC',{outHex:'aa'.repeat(32)}));
  try {
    v.infoOpen.value=true;
    assert.match(fact(await v.html(),'输出大小'),/^32 B/);
  } finally {v.dispose();}
});

test('rendered lengths distinguish reported original size from captured truncated bytes',async()=>{
  const v=detail(cap(1,'AES-CBC',{inl:16,hex:'aa'.repeat(8),outl:64,outHex:'bb'.repeat(32)}));
  try {
    v.infoOpen.value=true;
    const html=await v.html();
    assert.match(fact(html,'输入大小'),/16 B.*已捕获 8 B/);
    assert.match(fact(html,'输出大小'),/64 B.*已捕获 32 B/);
    assert.match(viewModel().cryptoView(v.c.value).sizeLabel,/64 B/);
  } finally {v.dispose();}
});

test('unknown, zero and invalid captured lengths are not conflated',async()=>{
  for(const [data,expected] of [[{outl:0},/^0 B/],[{},/^未记录$/],[{outHex:'f'},/^未记录$/]]) {
    const v=detail(cap(1,'AES-CBC',data));
    try {v.infoOpen.value=true;assert.match(fact(await v.html(),'输出大小'),expected);}
    finally {v.dispose();}
  }
});

test('an explicitly captured empty output is not labelled as missing bytes',async()=>{
  const v=detail(cap(1,'AES-CBC',{outl:0,outHex:''}));
  try {
    assert.equal(v.hasOutput.value,true);
    assert.equal(v.formatBlock('auto','').display,'（空字节）');
    assert.equal(v.formatBlock('auto',undefined).display,'（未捕获字节）');
    assert.match(viewModel().cryptoView(v.c.value).sizeLabel,/0 B/);
  } finally {v.dispose();}
});

test('contradictory reported and captured lengths are visible instead of silently discarded',async()=>{
  const v=detail(cap(1,'AES-CBC',{outl:0,outHex:'aabb'}));
  try {
    v.infoOpen.value=true;
    assert.match(fact(await v.html(),'输出大小'),/0 B.*已捕获 2 B.*长度不一致/);
    assert.match(viewModel().cryptoView(v.c.value).sizeLabel,/长度不一致/);
  } finally {v.dispose();}
});

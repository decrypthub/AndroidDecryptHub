import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

interface Observation { family: string; name: string; count: number; latest: number }
const context = vm.createContext({});
vm.runInContext(readFileSync(new URL('../public/algorithm-observations.js', import.meta.url), 'utf8'), context);
const summarize = (records: unknown[]): Observation[] => JSON.parse(JSON.stringify(context.AdhAlgorithmObservations.summarize(records)));

test('typed observations combine spelling variants and keep the most recent occurrence', () => {
  const records = [
    {category:'crypto', algo:'SHA-256', ts:10},
    {category:'crypto', algo:'Sha256', ts:20},
    {category:'crypto', algo:'HmacSHA256', ts:25},
    {category:'crypto', algo:'AES/GCM/NoPadding', ts:30},
    {category:'crypto', algo:'SHA3-256', ts:35},
  ];
  assert.deepEqual(summarize(records), [
    {family:'digest', name:'SHA-3', count:1, latest:35},
    {family:'aead', name:'AES-GCM', count:1, latest:30},
    {family:'mac', name:'HMAC', count:1, latest:25},
    {family:'digest', name:'SHA-256', count:2, latest:20},
  ]);
});

test('derived categories report only observations, ignoring non-algorithm records and payloads', () => {
  const records = [
    {category:'crypto', algo:'HKDF-SHA256', text:'a private sample', ts:10},
    {category:'crypto', algo:'X25519', ts:20},
    {category:'crypto', algo:'SecureRandom', ts:30},
    {category:'net', algo:'TLSv1.3', ts:40},
    {category:'net', algo:'HTTP', ts:50},
    {category:'system', algo:'RSA', ts:60},
    {category:'crypto', algo:'unclassified-input', preview:'another private sample', ts:70},
    {category:'crypto', algo:'unknown', ts:'invalid time'},
  ];
  assert.deepEqual(summarize(records), [
    {family:'other', name:'未识别算法', count:2, latest:70},
    {family:'tls', name:'TLS', count:1, latest:40},
    {family:'random', name:'随机数', count:1, latest:30},
    {family:'agreement', name:'X25519', count:1, latest:20},
    {family:'kdf', name:'HKDF', count:1, latest:10},
  ]);
  assert.deepEqual(summarize([]), []);
});

test('Hook inventory groups only symbolic record metadata and separates equal names by kind and source', () => {
  const api = context.AdhAlgorithmObservations;
  const record = {category:'crypto', source:'java', func:'Fixture.digest', ts:10, text:'not an observation field'};
  const items = JSON.parse(JSON.stringify(api.summarizeHooks([
    record, {...record, ts:20}, {...record, source:'native'}, {...record, category:'system'},
    {category:'file', view:{hook:'Fixture.file'}, ts:40},
    {category:'file', func:'/tmp/not-a-symbol', ts:50},
    {category:'not-a-category', func:'Fixture.digest', ts:60},
    {category:'crypto', preview:'not a hook', ts:70},
  ])));
  const key = api.hookKey(record);
  assert.equal(items.length,4);
  assert.deepEqual(items.find((item:{key:string})=>item.key===key),{
    key,category:'crypto',source:'java',name:'Fixture.digest',count:2,latest:20,
  });
  assert.equal(new Set(items.map((item:{key:string})=>item.key)).size,4);
  assert.ok(items.some((item:{name:string})=>item.name==='Fixture.file'));
  assert.equal(api.hookKey({category:'net',func:'<script>alert(0)</script>'}),undefined);
});

test('Hook display is default-on, persists per package, and resets only the selected package', () => {
  const api = context.AdhAlgorithmObservations;
  const entries = new Map<string,string>();
  const storage = () => ({
    getItem:(key:string)=>entries.get(key) ?? null,
    setItem:(key:string,value:string)=>entries.set(key,value),
    removeItem:(key:string)=>entries.delete(key),
  });
  const alpha='com.example.alpha', beta='com.example.beta';
  const digest=api.hookKey({category:'crypto',source:'java',func:'Fixture.digest'});
  const prefs = api.hookDisplayPreferences(storage);
  assert.equal(prefs.hidden(alpha).size,0);
  assert.equal(prefs.save(alpha,new Set([digest])),true);
  assert.equal(prefs.hidden(beta).has(digest),false);
  assert.equal(prefs.save(beta,new Set(['other'])),true);
  const reopened=api.hookDisplayPreferences(storage);
  assert.deepEqual([...reopened.hidden(alpha)],[digest]);
  assert.deepEqual([...reopened.hidden(beta)],['other']);
  assert.equal(reopened.save(alpha,new Set()),true);
  assert.equal(api.hookDisplayPreferences(storage).hidden(alpha).size,0);
  assert.deepEqual([...api.hookDisplayPreferences(storage).hidden(beta)],['other']);
  assert.equal(reopened.save('',new Set([digest])),false);
});

test('invalid or denied browser storage cannot hide other records or falsely report persistence', () => {
  const api = context.AdhAlgorithmObservations;
  const invalid=api.hookDisplayPreferences(()=>({getItem:()=>'{invalid'}));
  assert.equal(invalid.hidden('com.example.alpha').size,0);
  const denied=api.hookDisplayPreferences(()=>{throw Error('storage unavailable');});
  assert.equal(denied.hidden('com.example.alpha').size,0);
  assert.equal(denied.save('com.example.alpha',new Set(['local-choice'])),false);
  assert.deepEqual([...denied.hidden('com.example.alpha')],['local-choice']);
  assert.equal(denied.hidden('com.example.beta').size,0);
});

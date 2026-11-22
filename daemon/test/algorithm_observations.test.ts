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

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';

const sandbox:any={console,AbortController,setTimeout,clearTimeout,Uint8Array,Headers,URL,crypto:webcrypto};
vm.runInNewContext(readFileSync(new URL('../public/workbench-model.js',import.meta.url),'utf8'),sandbox);
vm.runInNewContext(readFileSync(new URL('../public/operation-client.js',import.meta.url),'utf8'),sandbox);
const M=sandbox.AdhWorkbenchModel,Client=sandbox.AdhOperationClient;
const plain=value=>JSON.parse(JSON.stringify(value));
const baseline=()=>({settings:{ui:{displayCap:300},capture:{enabled:true,fileModule:''}},control:{resource:'host',revision:1,epoch:2,hostEpoch:2}});

test('a config draft submits only changed leaves and preserves unknown configuration',()=>{
  const snapshot=baseline();snapshot.settings['future']={preserve:true};const draft=new M.Draft(snapshot);
  M.set(draft.draft,'ui.displayCap',411);
  assert.deepEqual(plain(draft.patch()),{ui:{displayCap:411}});
  assert.deepEqual(draft.control.revision,1);assert.equal(draft.draft.future.preserve,true);
  snapshot.control.revision=99;assert.equal(draft.control.revision,1,'read snapshots are not a mutable draft token');
});

test('explicit rebase preserves human intent while adopting concurrent changes to untouched fields',()=>{
  const draft=new M.Draft(baseline());M.set(draft.draft,'ui.displayCap',411);
  const latest=baseline();latest.control.revision=5;latest.settings.capture.fileModule='from-ai.so';latest.settings.ui.displayCap=377;
  const rows=plain(draft.compare(latest));assert.ok(rows.find(row=>row.path==='capture.fileModule'&&!row.local));
  assert.equal(draft.control.revision,1,'comparison must not silently freshen a write');
  draft.rebase(latest);
  assert.equal(draft.draft.capture.fileModule,'from-ai.so');assert.equal(draft.draft.ui.displayCap,411);
  assert.deepEqual(plain(draft.patch()),{ui:{displayCap:411}});assert.equal(draft.control.revision,5);
});

test('invalid imports cannot become silently ignored settings or pollute prototypes',()=>{
  for(const value of [{ui:{displayCap:2}},{startup:{module:''}},{startup:{packages:['bad package']}},{capture:{families:{unknown:true}}},JSON.parse('{"__proto__":{"polluted":true}}')])assert.throws(()=>M.validatePatch(value));
  assert.equal({}['polluted'],undefined);
  assert.doesNotThrow(()=>M.validatePatch({capture:{enabled:false},startup:{extraTargets:['access']}}));
});

test('panel submission preserves the observed versions and intent key across a stale response',async()=>{
  const calls:any[]=[],client=new Client(async(path,init)=>{calls.push({path,body:JSON.parse(init.body)});return new Response(JSON.stringify({ok:false,code:'STALE_CONTROL',error:'changed'}),{status:409});},webcrypto);
  client.key='synthetic-key';const observed=baseline().control;
  await assert.rejects(()=>client.submitSettings({ui:{displayCap:411}},observed,'one-intent'),(e:any)=>e.code==='STALE_CONTROL');
  assert.equal(calls.length,1);assert.deepEqual(plain(calls[0].body._operation),{expectedRevision:1,controlEpoch:2,hostEpoch:2,idempotencyKey:'one-intent'});
});

test('transport failure remains unconfirmed and never automatically retries a write',async()=>{
  let calls=0;const client=new Client(async()=>{calls++;throw new TypeError('synthetic disconnect');},webcrypto);client.key='synthetic-key';
  await assert.rejects(()=>client.submitSettings({ui:{displayCap:411}},baseline().control,'pending-intent'),(e:any)=>e.transport===true&&e.code==='TRANSPORT_UNCONFIRMED');
  assert.equal(calls,1);
});

test('checking one algorithm for a specified app or unpacking does not require an operator key',async()=>{
  const calls:any[]=[];
  const client=new Client(async(path,init)=>{
    calls.push(path);
    if(path==='/api/operations/prepare'){
      return new Response(JSON.stringify({ok:true,spec:{mode:'write',name:'settings',global:true},resource:'host',revision:1,epoch:1,hostEpoch:1}),{status:200});
    }
    return new Response(JSON.stringify({ok:true}),{status:200,headers:{'x-adh-control':JSON.stringify({resource:'host',revision:2,epoch:1,hostEpoch:1})}});
  },webcrypto);
  const page:any={location:{href:'http://127.0.0.1:8088/',origin:'http://127.0.0.1:8088'},fetch:null};
  client.installGuard(page);
  await page.fetch('/api/capture/families',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({package:'com.example.app',family:'symmetric',enabled:true})});
  await page.fetch('/api/unpack/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({package:'com.example.app'})});
  await assert.rejects(()=>page.fetch('/api/capture/families',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({family:'symmetric',enabled:true})}),(error:any)=>error.code==='OPERATOR_REQUIRED');
  await assert.rejects(()=>page.fetch('/api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({capture:{families:{symmetric:true}}})}),(error:any)=>error.code==='OPERATOR_REQUIRED');
  await assert.rejects(()=>page.fetch('/api/config',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ui:{displayCap:80}})}),(error:any)=>error.code==='OPERATOR_REQUIRED');
  await assert.rejects(()=>page.fetch('/api/scope',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({package:'com.example.app'})}),(error:any)=>error.code==='OPERATOR_REQUIRED');
  assert.ok(calls.includes('/api/capture/families'));
  assert.ok(!calls.includes('/api/config'));
  assert.ok(calls.includes('/api/unpack/run'));
});

test('config reads require a Host version header; credentials and task revisions stay explicit',async()=>{
  const calls:any[]=[],client=new Client(async(path,init)=>{calls.push({path,init});return new Response(JSON.stringify({ok:true,settings:baseline().settings}),{status:200});},webcrypto);
  await assert.rejects(()=>client.config(),(e:any)=>e.code==='CONTROL_REQUIRED');
  await assert.rejects(()=>client.taskAction({id:'task',revision:7},'pause'),(e:any)=>e.code==='OPERATOR_REQUIRED');
  client.key='synthetic-key';await client.taskAction({id:'task',revision:7},'pause');
  assert.equal(JSON.parse(calls.at(-1).init.body)._operation.expectedTaskRevision,7);client.disconnect();assert.equal(client.operator,false);
  client.key='synthetic-key';await assert.rejects(()=>client.taskAction({id:'legacy-task'},'pause'),(e:any)=>e.code==='TASK_VERSION_REQUIRED');
});

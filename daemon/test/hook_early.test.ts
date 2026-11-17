import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {startDeviceFixture,FakeAdb,jvmManifest} from './device_fixture.ts';
import {Devices} from '../src/devices.ts';
import {AdbDeviceTransport} from '../src/transport/adb_device.ts';
import {Operations} from '../src/operations.ts';
import {describeTool} from '../src/operation_registry.ts';
import {digest,canonical,FAMILY_KEYS} from '../src/hook_plans.ts';

const skip=existsSync(jvmManifest)?false:'offline JVM fixture not built; no real device fallback';
test('production device cache stages bound Kotlin wire, rejects stale intent, and restores exact legacy bytes',{skip},async t=>{
  const jvm=await startDeviceFixture(),adb=new FakeAdb();adb.add('fixture-usb','1',jvm);
  const root=mkdtempSync(join(tmpdir(),'adh-p5-early-')),engine=new Operations(join(root,'operations'));
  const devices=new Devices(join(root,'devices.json'),new AdbDeviceTransport(adb.run));
  const ai={role:'ai' as const,id:'early-fixture',source:'test'};
  async function execute(args:any){const spec=describeTool('devices',args),c=engine.snapshot(engine.resource(spec));const op=await engine.execute(spec,args,ai,{expectedRevision:c.revision,controlEpoch:c.epoch,hostEpoch:c.hostEpoch},()=>args.action==='connect'?devices.connect(args.serial,args.transportId):devices.call(args));return {...op,body:engine.getOperation(op.id,true).result};}
  try{
    const connected=await execute({action:'connect',serial:'fixture-usb',transportId:'1'}),peer=connected.body;
    const read=async(method:string,params:any={})=>(await devices.call({deviceId:peer.deviceId,connectionId:peer.connectionId,method,params})).result;
    const write=async(method:string,params:any)=>{const state=await read('device.state');return execute({action:'call',deviceId:peer.deviceId,connectionId:peer.connectionId,bootId:peer.bootId,daemonInstanceId:peer.daemonInstanceId,expectedDeviceRevision:state.stateRevision,method,params});};
    const raw='{\n "version":19,"mode":"allowlist","packages":["com.fixture.app"],"policy":{"com.fixture.app":{"c":{"d":false,"future":7},"unknown":[1,2]}},"future":{"exact":true}\n}\n';writeFileSync(join(jvm.root,'scope.json'),raw);
    const p={schemaVersion:1,id:'early',title:'Early fixture',package:'com.fixture.app',families:Object.fromEntries(FAMILY_KEYS.map(k=>[k,k==='hmac'])),steps:[{id:'got',tool:'native_hook',arguments:{action:'hook',mode:'got',module:'libfixture.so',symbol:'read'}},{id:'capture',tool:'capture_start',arguments:{cryptoModule:'libfixture.so',fileModule:'',sysModule:''}}]};
    const withMetadata:any=p;withMetadata.metadata={unicode:'中文 </x> \u2028',fraction:0.0000001};
    const hash=digest(p),preview=await read('hooks.migration.preview',{package:p.package});assert.equal(preview.scopeRaw,raw);
    const migration=await write('hooks.migration.apply',{package:p.package,scopeRevision:preview.scopeRevision,planDigest:hash});assert.equal(migration.state,'succeeded');assert.equal(migration.body.result.result.applied,false);
    const prepared=await read('early.prepare',{package:p.package});assert.equal(prepared.supported,true);
    const params={plan:p,canonicalPlan:canonical(p),digest:hash,binding:prepared.binding,expiresAt:Math.floor(Date.now()/1000)+3600,offline:'keep-until-expiry',expectedCacheRevision:prepared.cacheRevision};
    const staged=await write('early.stage',params);assert.equal(staged.state,'succeeded');const status=staged.body.result.result;assert.equal(status.entry.state,'validated-cache');assert.equal(status.applied,null);
    const eligible=async(uid=prepared.binding.uid)=>(await read('module.status',{package:p.package,uid})).earlyEligible;
    assert.equal(await eligible(),true);assert.equal(await eligible(99),false);writeFileSync(join(jvm.root,'hook-binding.json'),JSON.stringify({...prepared.binding,versionCode:'changed'}));assert.equal(await eligible(),false);writeFileSync(join(jvm.root,'hook-binding.json'),JSON.stringify(prepared.binding));assert.equal(await eligible(),true);
    const stale=await write('early.stage',params);assert.equal(stale.state,'failed');assert.equal(stale.body?.result?.code||stale.error?.code,'STALE_EARLY_CACHE');
    const bad={...params,expectedCacheRevision:status.cacheRevision,binding:{...prepared.binding,uid:99}};const changed=await write('early.stage',bad);assert.equal(changed.state,'failed');assert.equal(changed.body.result.code,'TARGET_CHANGED');
    const unsupported=structuredClone(p);unsupported.steps[0].arguments.mode='inline';const refused=await write('early.stage',{...params,expectedCacheRevision:status.cacheRevision,plan:unsupported,canonicalPlan:canonical(unsupported),digest:digest(unsupported)});assert.equal(refused.state,'failed');assert.equal(refused.body?.result?.code||refused.error?.code,'UNSUPPORTED_EARLY_PLAN');
    // Native production parser and executor consume the exact bytes emitted by Kotlin.
    const compiler=process.env.ADH_CXX||(process.platform==='win32'?'C:/Strawberry/c/bin/g++.exe':'g++');
    await t.test('Kotlin encoder → native validator/receipts, tamper/UID/agent/expiry rejection and SHA oracle', {skip:process.platform==='win32'&&!existsSync(compiler)?'portable C++ compiler unavailable':false},()=>{
      const binary=join(root,'early-wire.exe'),compiled=spawnSync(compiler,['-std=c++17','-O2',resolve('test/fixtures/early_wire.cpp'),'-o',binary],{encoding:'utf8',windowsHide:true});assert.equal(compiled.status,0,compiled.stderr);
      const wire=Buffer.from(status.entry.wire,'base64'),file=join(root,'wire.bin');writeFileSync(file,wire);const now=Math.floor(Date.now()/1000);
      const consume=(uid=prepared.binding.uid,agent=prepared.binding.agentSha256,time=now,confirmed=16)=>spawnSync(binary,[file,p.package,String(uid),agent,String(time),String(confirmed),'fixture'],{encoding:'utf8',windowsHide:true}).stdout.trim();
      assert.equal(consume(),`applied 2 2 ${hash}`);assert.equal(consume(undefined,undefined,undefined,1),`partial-or-failed 2 1 ${hash}`);assert.equal(consume(99),'rejected');assert.equal(consume(undefined,'0'.repeat(64)),'rejected');assert.equal(consume(undefined,undefined,params.expiresAt),'rejected');
      wire[wire.length-1]^=1;writeFileSync(file,wire);assert.equal(consume(),'rejected');
      for(const size of [0,1,55,56,63,64,65,128,1025]){const bytes=Buffer.alloc(size,97);writeFileSync(file,bytes);assert.equal(spawnSync(binary,['sha',file],{encoding:'utf8',windowsHide:true}).stdout.trim(),createHash('sha256').update(bytes).digest('hex'));}
    });
    // A normal scope edit retains the full old policy; rollback refuses to erase it.
    const scope=await read('scope.get'),migratedRaw=readFileSync(join(jvm.root,'scope.json'),'utf8');const edited=await write('scope.patch',{scopeRevision:scope.scopeRevision,add:['com.fixture.other']});assert.equal(edited.state,'succeeded');
    assert.deepEqual((await read('scope.get')).document.policy,JSON.parse(raw).policy);
    const conflict=await write('hooks.migration.rollback',{migrationId:migration.body.result.result.migrationId,scopeRevision:migration.body.result.result.scopeRevision});assert.equal(conflict.state,'failed');assert.equal(conflict.body.result.code,'STALE_SCOPE');
    // Restore only the fixture's exact migrated document, then exercise exact rollback.
    const stored=JSON.parse(readFileSync(join(jvm.root,'hook-cache.json'),'utf8'));writeFileSync(join(jvm.root,'scope.json'),migratedRaw);
    const rolled=await write('hooks.migration.rollback',{migrationId:migration.body.result.result.migrationId,scopeRevision:migration.body.result.result.scopeRevision});assert.equal(rolled.state,'succeeded');assert.equal(readFileSync(join(jvm.root,'scope.json'),'utf8'),raw);assert.equal((await read('early.status',{package:p.package})).entry.state,'revoked');
    assert.equal(stored.entries[p.package].digest,hash);assert.ok(adb.commands.every(c=>!c.includes('reverse')&&!c.includes('install')&&!c.includes('kill-server')));
  }finally{devices.close();engine.close();await adb.close();await jvm.close();rmSync(root,{recursive:true,force:true});}
});

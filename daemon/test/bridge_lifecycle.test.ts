import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {join,resolve,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const executable=(name:string)=>process.platform==='win32'?name+'.exe':name;
const homes=[process.env.JAVA_HOME,process.platform==='win32'?'C:/Program Files/Android/Android Studio/jbr':undefined].filter(Boolean) as string[];
const pick=(name:string)=>homes.map(home=>join(home,'bin',executable(name))).find(existsSync)||executable(name);
const javac=pick('javac'),java=pick('java');
const probe=spawnSync(javac,['-version'],{encoding:'utf8',windowsHide:true,timeout:10000});
const available=probe.status===0&&spawnSync(java,['-version'],{encoding:'utf8',windowsHide:true,timeout:10000}).status===0;
const root=resolve(tmpdir());
const dir=available?mkdtempSync(join(root,'adh-bridge-life-')):null;
const source=process.env.ADH_BRIDGE_SOURCE||fileURLToPath(new URL('../../agent/java/com/adh/agent/AdhJavaHookBridge.java',import.meta.url));
const fixture=fileURLToPath(new URL('./fixtures/HookBridgeLifecycleFixture.java',import.meta.url));
const header=process.env.ADH_BRIDGE_HEADER||fileURLToPath(new URL('../../agent/src/hook/adh_java_hook_bridge_dex.h',import.meta.url));
const dex=process.env.ADH_BRIDGE_DEX||fileURLToPath(new URL('../../agent/src/hook/adh_java_hook_bridge.dex',import.meta.url));
const compilation=dir?spawnSync(javac,['-source','8','-target','8','-Xlint:-options','-d',dir,source,fixture],{encoding:'utf8',windowsHide:true,timeout:30000}):null;
after(()=>{
  if(!dir)return;
  const absolute=resolve(dir);
  assert.ok(absolute.startsWith(root+sep)&&absolute.split(sep).at(-1)!.startsWith('adh-bridge-life-'));
  rmSync(absolute,{recursive:true,force:true});
});

test('embedded Java bridge DEX bytes equal the generated header',()=>{
  const embedded=Buffer.from([...readFileSync(header,'utf8').matchAll(/0x([a-f\d]{2})\b/gi)].map(m=>parseInt(m[1],16)));
  assert.ok(embedded.equals(readFileSync(dex)),'embedded bridge differs from the generated DEX');
});
test('embedded Java bridge declares the exact source hash, preventing forgotten regeneration',()=>{
  const declared=readFileSync(header,'utf8').match(/^\/\/ Source SHA-256: ([a-f\d]{64})$/m)?.[1];
  const expected=createHash('sha256').update(readFileSync(source)).digest('hex');
  assert.equal(declared,expected,'Java bridge changed without regenerating DEX/header');
});

for(const name of ['inactive-static','inactive-crypto','inactive-nonsilent','inactive-instance','inactive-constructor','inactive-exception','inactive-void','inactive-null-args','inactive-not-ready','inactive-argument-observation','inactive-return-observation','deactivate-during-return','deactivate-during-exception','active-positive-control','active-crypto-positive-control','active-argument-rewrite','active-return-override','reactivate-positive-control']) {
  test(`real compiled Java bridge: ${name}`,{skip:available?false:'JDK unavailable; this compiled-source regression requires javac and java'},()=>{
    assert.equal(compilation!.status,0,`javac failed: ${compilation!.stderr}`);
    const result=spawnSync(java,['-cp',dir!,'HookBridgeLifecycleFixture',name],{encoding:'utf8',windowsHide:true,timeout:10000});
    assert.equal(result.status,0,`${name}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
    assert.equal(result.stdout.trim(),`PASS ${name}`);
  });
}

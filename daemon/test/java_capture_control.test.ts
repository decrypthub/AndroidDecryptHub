import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve,join,sep} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
const root=process.env.ADH_JAVA_CONTROL_ROOT||fileURLToPath(new URL('../../',import.meta.url));
const crypto=readFileSync(join(root,'agent/src/hook/java_crypto.cpp'),'utf8').replaceAll('\r\n','\n');
const owner=readFileSync(join(root,'agent/src/hook/java_lsplant.cpp'),'utf8').replaceAll('\r\n','\n');
const cmds=readFileSync(join(root,'agent/src/bootstrap/agent_cmds.c'),'utf8');
const has=existsSync(join(root,'agent/src/hook/java_crypto_registry.h'));
function block(s:string,start:string,end:string){const a=s.indexOf(start),b=s.indexOf(end,a+start.length);assert.ok(a>=0&&b>a,`${start} -> ${end}`);return s.slice(a,b);}
const compiler=process.env.CXX||(process.platform==='win32'&&existsSync('C:/Strawberry/c/bin/g++.exe')?'C:/Strawberry/c/bin/g++.exe':'c++');
const available=spawnSync(compiler,['--version'],{encoding:'utf8',windowsHide:true,timeout:10000}).status===0;
const temp=resolve(tmpdir()),dir=available?mkdtempSync(join(temp,'adh-java-control-')):null;
let compiled:ReturnType<typeof spawnSync>|undefined;
if(dir){
 const fixture=readFileSync(new URL('./fixtures/java_capture_control_fixture.cpp',import.meta.url),'utf8');
 const ownerFunctions=has?block(owner,'static int set_bridge_enabled(','static std::string jstring_to_utf')+
   block(owner,'extern "C" int adh_javahook_set_enabled(','// Hook every method of a class in one call'):
   '';
 const unhook=block(owner,'extern "C" int adh_javahook_unhook_id(','// Defined at the end of the vendored');
 const mode=block(owner,'extern "C" int adh_javahook_set_crypto_mode(','extern "C" int adh_javahook_unhook_id(');
 const core=has?block(crypto,'static std::string quote(','static void discover(')+block(crypto,'static uint64_t reconcile(','static bool kick_locked(void);')+
   block(crypto,'static void *worker(','static bool kick_locked(void) {')+
   block(crypto,'extern "C" void adh_java_crypto_arm(','extern "C" void adh_java_crypto_set_families(')+
   crypto.slice(crypto.indexOf('extern "C" int adh_java_crypto_stop(')):
   crypto.slice(crypto.indexOf('extern "C" void adh_java_crypto_arm('));
 const gate=crypto.includes("static std::atomic<bool> g_observing")?"#include <atomic>\n"+block(crypto,"static std::atomic<bool> g_observing","static bool g_started")+block(crypto,'extern "C" int adh_java_crypto_running(','extern "C" int adh_java_crypto_started('):"";
 const program=`${gate}\n#define ADH_HAS_REGISTRY ${has?1:0}\n${has?'#include "java_crypto_registry.h"':''}\n#define ADH_FIXTURE_PRELUDE\n${fixture}\n#undef ADH_FIXTURE_PRELUDE\n${ownerFunctions}\n${unhook}\n${mode}\n${core}\n${fixture}`;
 writeFileSync(join(dir,'shipping_control.cpp'),program,'utf8');
 compiled=spawnSync(compiler,['-std=c++20','-O0','-I',resolve(root,'agent/src/hook'),join(dir,'shipping_control.cpp'),'-o',join(dir,process.platform==='win32'?'fixture.exe':'fixture')],{encoding:'utf8',windowsHide:true,timeout:30000});
}
after(()=>{if(!dir)return;assert.ok(resolve(dir).startsWith(temp+sep)&&dir.split(sep).at(-1)!.startsWith('adh-java-control-'));rmSync(dir,{recursive:true,force:true});});
test('Java capture command and owner/inactive-first bootstrap are wired in shipping source',()=>{
 assert.match(cmds,/"java_capture"/);assert.match(cmds,/strcmp\(op, "java_capture"\) == 0/);
 assert.match(owner,/old\.owner != owner/);assert.match(owner,/ctx\.owner = owner/);assert.match(owner,/ctx\.active = 0/);
 assert.match(owner,/owner == ADH_JAVA_OWNER_CAPTURE \? env->FindClass/);
});
for(const name of ['producer-gate','arm-again','generic-unhook-ownership','catalog','cipher-dependencies','signature-dependencies','shared-family','missing-dependency','revision','bounded-40','owned-toggle','worker-id-reuse','worker-stop-race','worker-family-race','worker-retry','worker-control-retry','worker-wrong-owner','stop-memo','stop-no-jni','worker-exit-wakeup','status-json']){
 test(`compiled production Java control: ${name}`,{skip:available?false:'C++ compiler unavailable; production registry/reconcile/owner fixture requires c++'},()=>{
   assert.equal(compiled!.status,0,`fixture compile:\n${compiled!.stdout}\n${compiled!.stderr}`);
   const r=spawnSync(join(dir!,process.platform==='win32'?'fixture.exe':'fixture'),[name],{encoding:'utf8',windowsHide:true,timeout:15000});
   assert.equal(r.status,0,`${r.stdout}\n${r.stderr}`);assert.match(String(r.stdout),new RegExp(`PASS ${name}\\s*$`));
   if(name==='status-json'){const s=JSON.parse(String(r.stdout).split('\n')[0]);assert.equal(s.id,'quote"id');assert.equal(s.methods.length,10);assert.equal(s.on,false);assert.equal(s.settling,false);assert.ok(s.methods.every((x:any)=>x.patched&&!x.active&&x.owner==='capture'));}
 });
}

import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root=process.env.ADH_CAPTURE_SOURCE_ROOT||fileURLToPath(new URL('../../',import.meta.url));
const capture=readFileSync(join(root,'agent/src/capture/capture.c'),'utf8').replaceAll('\r\n','\n');
const cmds=readFileSync(join(root,'agent/src/bootstrap/agent_cmds.c'),'utf8');
const header=join(root,'agent/src/capture/capture_methods.h');
const hasMethods=existsSync(header);
const hasSlots=existsSync(join(root,'agent/src/hook/capture_slots.h'));
const fixture=readFileSync(new URL('./fixtures/capture_methods_fixture.c',import.meta.url),'utf8');
const compiler=process.env.CC||(process.platform==='win32'&&existsSync('C:/Strawberry/c/bin/gcc.exe')?'C:/Strawberry/c/bin/gcc.exe':'cc');
const available=spawnSync(compiler,['--version'],{encoding:'utf8',windowsHide:true,timeout:10000}).status===0;
const temp=resolve(tmpdir()),dir=available?mkdtempSync(join(temp,'adh-capture-methods-')):null;
const between=(a:string,b:string)=>{const start=capture.indexOf(a);assert.ok(start>=0,a);const end=capture.indexOf(b,start);assert.ok(end>start,b);return capture.slice(start,end);};
const source=[between('static char g_file_mod','// crypto/TLS caller module'),
  between('static char g_crypto_mod','static void copy_jstring'),
  between('static void skip_add','// There is deliberately NO self-arm'),
  hasMethods?between('static void capture_native_restore','void adh_cmd_capture_start'):'',
  between('void adh_cmd_capture_start','// Uninstall the persistent capture hooks'),
  between('void adh_cmd_capture_stop','// Drain (pop)')].join('\n');
const types=[...new Set([...source.matchAll(/\(([A-Za-z_][A-Za-z_0-9]*_t)\)/g)].map(m=>m[1]))].filter(x=>!['size_t','uint32_t'].includes(x));
const globals=[...new Set([...source.matchAll(/\bg_(?:orig_[A-Za-z_0-9]+|evp_[A-Za-z_0-9]+|cipher_(?:key|iv)_len|ecdsa_[A-Za-z_0-9]+|pkey_[A-Za-z_0-9]+|aead_[A-Za-z_0-9]+)\b/g)].map(m=>m[0]))];
const wrappers=[...new Set([...source.matchAll(/\bmy_[A-Za-z_0-9]+\b/g)].map(m=>m[0]))];
let compiled:ReturnType<typeof spawnSync>|undefined;
if(dir){
 const program=`#define ADH_HAS_SLOTS ${hasSlots?1:0}\n${hasSlots?'#include "../hook/capture_slots.h"':''}\n#define ADH_FIXTURE_PRELUDE\n${fixture}\n#undef ADH_FIXTURE_PRELUDE\n#define ADH_HAS_METHODS ${hasMethods?1:0}\n${hasMethods?'#include "capture_methods.h"':''}\n${types.map(x=>`typedef void *${x};`).join('\n')}\n${globals.map(x=>`static void *${x};`).join('\n')}\n${wrappers.map(x=>`static void ${x}(void) {}`).join('\n')}\n${source}\n${fixture}`;
 writeFileSync(join(dir,'shipping_capture_fixture.c'),program,'utf8');
 compiled=spawnSync(compiler,['-std=c11','-O0','-Werror=implicit-function-declaration','-Werror=return-type','-I',resolve(root,'agent/src/capture'),join(dir,'shipping_capture_fixture.c'),'-o',join(dir,process.platform==='win32'?'fixture.exe':'fixture')],{encoding:'utf8',windowsHide:true,timeout:30000});
}
after(()=>{if(!dir)return;assert.ok(resolve(dir).startsWith(temp+sep)&&dir.split(sep).at(-1)!.startsWith('adh-capture-methods-'));rmSync(dir,{recursive:true,force:true});});

test('persistent method command is actually advertised and dispatched',()=>{
 assert.match(cmds,/"capture_methods"/);
 assert.match(cmds,/strcmp\(op, "capture_methods"\) == 0\) \{\s*adh_cmd_capture_methods\(fd, id, line\)/);
});
test('shipping capture installers and stop are wired to the exact-prior ownership ledger',()=>{
 const got=readFileSync(join(root,'agent/src/hook/got.c'),'utf8');
 assert.match(capture,/adh_capture_got_replace_by_name_ex/);assert.match(capture,/adh_capture_got_restore/);
 assert.doesNotMatch(capture,/\badh_got_replace(?:_by_name(?:_ex)?)?\(/);
 assert.match(got,/capture_owned \? adh_capture_slot_publish/);
 assert.match(got,/adh_capture_slot_restore\(&g_capture_slots/);
});
for(const name of ['defaults','none','single-tls','java-only-crypto','family-off','repeat-retarget','stop-ownership','revision','active-reject','catalog-status','malformed','exact-prior','multi-prior','unreadable-stop','capacity','publish-failure','live-ownership','java-stop','java-family-policy',...Array.from({length:14},(_,i)=>`method-${i}`)]) {
 test(`compiled shipping Native policy/start/stop: ${name}`,{skip:available?false:'C compiler absent; deterministic mocked-GOT fixture requires cc'},()=>{
   assert.equal(compiled!.status,0,`fixture C compile failed:\n${compiled!.stdout}\n${compiled!.stderr}`);
   const r=spawnSync(join(dir!,process.platform==='win32'?'fixture.exe':'fixture'),[name],{encoding:'utf8',windowsHide:true,timeout:10000});
   assert.equal(r.status,0,`${r.stdout}\n${r.stderr}`);assert.match(String(r.stdout),new RegExp(`PASS ${name}\\s*$`));
   if(name==='catalog-status') {
     const status=JSON.parse(String(r.stdout).split('\n')[0]);assert.equal(status.methods.length,14);
     assert.equal(new Set(status.methods.map((x:any)=>x.id )).size,14);assert.equal(status.ok,true);
     assert.equal(status.methods.filter((x:any)=>x.requested).length,1);assert.equal(status.methods.filter((x:any)=>x.effective).length,1);
     assert.equal(status.methods.filter((x:any)=>x.dependency).length,0);
   }
 });
}

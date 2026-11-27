import test,{after}from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import os from'node:os';import path from'node:path';import{spawnSync}from'node:child_process';import{fileURLToPath}from'node:url';
const root=process.env.ADH_COLD_ROOT||fileURLToPath(new URL('../../',import.meta.url)),source=fs.readFileSync(path.join(root,'agent/src/capture/capture.c'),'utf8').replaceAll('\r\n','\n'),owner=fs.readFileSync(path.join(root,'agent/src/hook/java_lsplant.cpp'),'utf8');
const compiler=process.env.CC||(process.platform==='win32'&&fs.existsSync('C:/Strawberry/c/bin/gcc.exe')?'C:/Strawberry/c/bin/gcc.exe':'cc'),available=spawnSync(compiler,['--version'],{encoding:'utf8',windowsHide:true}).status===0,base=path.resolve(os.tmpdir()),dir=available?fs.mkdtempSync(path.join(base,'adh-rich-origin-')):null;
const block=(s:string,a:string,b:string)=>{const i=s.indexOf(a),j=s.indexOf(b,i+a.length);assert.ok(i>=0&&j>i,a+' -> '+b);return s.slice(i,j);};
let compiled:any=null;
if(dir){
 const util=fs.readFileSync(path.join(root,'agent/src/bootstrap/util.c'),'utf8');
 const prelude=`#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdint.h>\n#include <stddef.h>\n#include <assert.h>
typedef int jsize;typedef signed char jbyte;typedef const char *jstring;typedef void *jclass;
typedef struct {int n;unsigned char bytes[4096];} *jbyteArray;
struct JNITable;typedef const struct JNITable *JNIEnv;
struct JNITable {jsize(*GetArrayLength)(JNIEnv*,jbyteArray);void(*GetByteArrayRegion)(JNIEnv*,jbyteArray,int,int,jbyte*);const char*(*GetStringUTFChars)(JNIEnv*,jstring,void*);void(*ReleaseStringUTFChars)(JNIEnv*,jstring,const char*);};
static jsize alen(JNIEnv*e,jbyteArray a){(void)e;return a->n;}static void region(JNIEnv*e,jbyteArray a,int o,int n,jbyte*d){(void)e;assert(o+n<=a->n);memcpy(d,a->bytes+o,n);}static const char*chars(JNIEnv*e,jstring s,void*x){(void)e;(void)x;return s;}static void release(JNIEnv*e,jstring s,const char*p){(void)e;(void)s;(void)p;}
static long long now_ns(void){return 123;}static int fixture_tid(void){return 7;}\n#define gettid fixture_tid
static int locked=0,g_cap_lock,g_cap_cond;static int pthread_mutex_trylock(int*x){(void)x;return locked?1:0;}static void pthread_mutex_unlock(int*x){(void)x;}static void pthread_cond_signal(int*x){(void)x;}
`;
 const code=prelude+block(source,'#define JCAP_MAX','static struct JCapRec g_jcaps')+`
static struct JCapRec g_jcaps[JCAP_MAX];static int g_jcap_head,g_jcap_tail,g_njcaps;static unsigned long long g_jcap_dropped;static volatile int g_java_active;
`+block(util,'void json_escape(','// Minimal JSON')+block(source,'static size_t emit_hex(','static size_t emit_caprec(')+block(source,'static size_t emit_jcaprec(','// ---- symmetric key/IV join')+block(source,'static int copy_jba(','// Register adh_nreport_impl')+`
int main(int argc,char**argv){assert(argc==2);const struct JNITable f={alen,region,chars,release};JNIEnv env=&f;struct {int n;unsigned char bytes[4096];} input={2048,{0}},output={3072,{0}},empty={0,{0}},key={100,{0}},iv={70,{0}};memset(input.bytes,0x61,sizeof(input.bytes));memset(output.bytes,0x62,sizeof(output.bytes));
const char*target="java.security.MessageDigest.digest([B)";
if(!strcmp(argv[1],"legacy"))adh_nreport_impl(&env,0,"SHA-256","digest",0,0,(jbyteArray)&input,(jbyteArray)&output);
else if(!strcmp(argv[1],"null"))adh_capture_java_origin(&env,"SHA-256","digest",0,0,0,(jbyteArray)&output,target,4,0);
else if(!strcmp(argv[1],"empty"))adh_capture_java_origin(&env,"SHA-256","digest",0,0,(jbyteArray)&empty,(jbyteArray)&output,target,4,0);
else if(!strcmp(argv[1],"bounds")){char origin[800];memset(origin,'"',799);origin[799]=0;adh_capture_java_origin(&env,"SHA-256","digest",(jbyteArray)&key,(jbyteArray)&iv,(jbyteArray)&input,(jbyteArray)&output,origin,4,0);}
else if(!strcmp(argv[1],"drop")){locked=1;adh_capture_java_origin(&env,"SHA-256","digest",0,0,0,0,target,4,0);assert(g_njcaps==0&&g_jcap_dropped==1);locked=0;g_njcaps=JCAP_MAX;adh_capture_java_origin(&env,"SHA-256","digest",0,0,0,0,target,4,0);assert(g_njcaps==JCAP_MAX&&g_jcap_dropped==2);puts("PASS drop");return 0;}
else adh_capture_java_origin(&env,"SHA-256","digest",(jbyteArray)&key,(jbyteArray)&iv,(jbyteArray)&input,(jbyteArray)&output,target,4,0);
assert(g_njcaps==1);struct {char out[JCAP_RECORD_RESERVE];char guard[16];} buffer;memset(&buffer,0,sizeof(buffer));memset(buffer.guard,'X',16);size_t n=emit_jcaprec(buffer.out,0,sizeof(buffer.out),&g_jcaps[0],1);assert(n<sizeof(buffer.out)&&strlen(buffer.out)==n);for(int i=0;i<16;i++)assert(buffer.guard[i]=='X');puts(buffer.out);return 0;}
`;
 fs.writeFileSync(path.join(dir,'shipping-rich.c'),code);compiled=spawnSync(compiler,['-std=c11','-O0',path.join(dir,'shipping-rich.c'),'-o',path.join(dir,'fixture.exe')],{encoding:'utf8',windowsHide:true,timeout:30000});
}
after(()=>{if(dir){assert.ok(path.resolve(dir).startsWith(base+path.sep));fs.rmSync(dir,{recursive:true,force:true});}});
for(const mode of ['origin','legacy','null','empty','bounds','drop'])test('compiled shipping rich-capture producer/serializer: '+mode,{skip:available?false:'C compiler unavailable; native producer fixture requires cc'},()=>{assert.equal(compiled.status,0,compiled.stderr);const r=spawnSync(path.join(dir!,'fixture.exe'),[mode],{encoding:'utf8',windowsHide:true,timeout:10000});assert.equal(r.status,0,r.stderr);if(mode==='drop'){assert.equal(r.stdout.trim(),'PASS drop');return;}const c=JSON.parse(r.stdout);assert.equal(c.recordSchema,'java-rich/2');assert.equal(c.outl,3072);assert.equal(c.out.length/2,1024);if(mode==='legacy'){assert.equal(c.javaTarget,undefined);assert.equal(c.inputBytesPresent,undefined);}else{assert.equal(c.inputScope,'call-argument-snapshot-after-return');assert.equal(c.inputBytesPresent,mode!=='null');assert.equal(c.javaHookId,4);if(mode==='bounds'){assert.equal(c.javaTarget.length,255);assert.equal(c.javaTargetTruncated,true);}else{assert.equal(c.javaTarget,'java.security.MessageDigest.digest([B)');assert.equal(c.javaTargetTruncated,false);}}if(['origin','legacy','bounds'].includes(mode)){assert.equal(c.inl,2048);assert.equal(c.in.length/2,1024);}else{assert.equal(c.inl,0);assert.equal(c.in,'');}});
test('shipping old target reporter ABI stays six arguments; bridge ABI includes explicit slot and target',()=>{assert.match(source,/\(Ljava\/lang\/String;Ljava\/lang\/String;\[B\[B\[B\[B\)V/);assert.match(owner,/\(ILjava\/lang\/String;Ljava\/lang\/String;Ljava\/lang\/String;\[B\[B\[B\[B\)V/);assert.equal((source.match(/len \+ JCAP_RECORD_RESERVE > cap/g)||[]).length,2);assert.match(source,/offsetof\(struct JCapRec, in\)/);});

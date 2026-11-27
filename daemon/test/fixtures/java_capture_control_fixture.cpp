// Production registry, reconcile/stop/command and native owner-control functions are inserted
// between these sections. JNI, ART installation, threads and transport are explicit adapters.
#ifdef ADH_FIXTURE_PRELUDE
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>
#include <algorithm>
#define JNI_TRUE 1
#define JNI_FALSE 0
#define LOGI(...) ((void)0)
#define ADH_JAVA_OWNER_MANUAL 0
#define ADH_JAVA_OWNER_CAPTURE 1
#define ADH_JAVA_MAX_HOOKS 64
#define pthread_mutex_t int
#define pthread_mutex_lock fixture_lock
#define pthread_mutex_unlock fixture_unlock
#define pthread_t int
#define pthread_create fixture_thread
#define pthread_detach fixture_detach
#define usleep fixture_sleep
static int lock_depth;
static void fixture_lock(int*) {lock_depth++;}
static void fixture_unlock(int*) {lock_depth--;}
static int fixture_sleep(unsigned) {return 0;}
static int kicks, installs, enables, clears;
static bool env_available=true, env_exception=false, control_failure=false, fail_install=false, stop_during_install=false, family_during_install=false, exit_race=false;
struct MockBridge { bool active=false;int epoch=0,mode=0; };
using jobject=MockBridge*;using jclass=void*;
static int g_bridge_active=1,g_bridge_crypto=2,g_bridge_set_enabled=3,g_bridge_clear_crypto=4;
static jclass g_bridge_class=(void*)1;
struct JNIEnv {
 int GetBooleanField(jobject b,int) {return b->active;}
 void SetBooleanField(jobject b,int,int value) {b->active=value;}
 void SetIntField(jobject b,int,int value) {b->mode=value;}
 void CallVoidMethod(jobject b,int,int value) {if(control_failure){env_exception=true;control_failure=false;return;}b->active=false;b->epoch++;b->active=value;if(value)enables++;}
 void CallStaticVoidMethod(jclass,int) {clears++;}
};
static JNIEnv fake_env;
struct JavaHookContext {int id=0,owner=0,active=0,used=0,patched=0;MockBridge*bridge=nullptr;};
static JavaHookContext g_java_hooks[64];static int g_java_hooks_lock;
static int adh_jni_exception_check(JNIEnv*) {return env_exception;}
static void adh_jni_exception_clear(JNIEnv*) {env_exception=false;}
static JNIEnv *adh_jni_attach(int *attached) {*attached=0;return env_available?&fake_env:nullptr;}
static void adh_jni_detach(int) {}
static jobject adh_jni_app_class_loader(JNIEnv*) {static MockBridge loader;return &loader;}
static void adh_javahook_install_lock(void) {}
static void adh_javahook_install_unlock(void);
static void set_error(char*out,size_t cap,const char*fmt,...) {va_list ap;va_start(ap,fmt);std::vsnprintf(out,cap,fmt,ap);va_end(ap);}
static std::string wire;
extern "C" int send_line(int,const char*s) {wire=s;return 0;}
extern "C" int adh_javahook_set_enabled(JNIEnv*,int,int,int);
extern "C" int adh_javahook_get_enabled(JNIEnv*,int,int);
extern "C" int adh_javahook_clear_crypto(JNIEnv*);
extern "C" int adh_javahook_set_crypto_mode(JNIEnv*,int,int);
#if ADH_HAS_REGISTRY
static AdhCryptoRegistry g_registry;
static int g_crypto_lock;
static bool g_started=false,g_worker_running=false;
static std::string g_missing_classes;
static bool kick_locked() {if(g_worker_running)return true;g_worker_running=true;g_started=true;kicks++;return true;}
static void discover(JNIEnv*) {}
static int next_id=1;
extern "C" int adh_javahook_hook_method_owned(JNIEnv*,int owner,const char*,const char*,const char*,int,const char*,int,const char*,int,int,int*out,char*error,size_t cap) {
 if(lock_depth)std::abort();installs++;
 if(fail_install){*out=0;std::snprintf(error,cap,"fixture install refused");return 0;}
 int id=next_id++;if(id>64)std::abort();auto &h=g_java_hooks[id-1];h.id=id;h.owner=owner;h.active=0;h.used=h.patched=1;h.bridge=new MockBridge;*out=id;
 if(stop_during_install){stop_during_install=false;g_registry.set_running(false);}
 if(family_during_install){family_during_install=false;g_registry.set_families(0);}
 return 1;
}
static void adh_javahook_install_unlock(void) {if(exit_race){exit_race=false;g_registry.set_running(true);}}
#else
static int g_started=0,g_finished=0;
static void *worker(void*) {return nullptr;}
static int fixture_thread(int*,void*,void*(*)(void*),void*) {kicks++;return 0;}
static int fixture_detach(int) {return 0;}
#endif
#else
static void fail(const char*s){std::fprintf(stderr,"FAIL %s\n",s);std::exit(1);}
#define CHECK(v) do{if(!(v))fail(#v);}while(0)
#if ADH_HAS_REGISTRY
static AdhCryptoMethod method(const char*cls,const char*name,const char*params,int mode,unsigned family) {
 AdhCryptoMethod m;m.cls=cls;m.method=name;m.params=params;m.mode=mode;m.families=family;return m;
}
static std::vector<AdhCryptoMethod> sample() {return {
 method("javax.crypto.Cipher","init","int,java.security.Key",1,ADH_CF_SYMMETRIC|ADH_CF_AEAD),
 method("javax.crypto.Cipher","init","int,java.security.Key,java.security.spec.AlgorithmParameterSpec",1,ADH_CF_SYMMETRIC|ADH_CF_AEAD),
 method("javax.crypto.Cipher","doFinal","[B",2,ADH_CF_SYMMETRIC|ADH_CF_AEAD),
 method("javax.crypto.Mac","init","java.security.Key",3,ADH_CF_HMAC),method("javax.crypto.Mac","doFinal","[B",4,ADH_CF_HMAC),
 method("java.security.MessageDigest","digest","[B",5,ADH_CF_DIGEST),
 method("java.security.Signature","initSign","java.security.PrivateKey",7,ADH_CF_ASYMMETRIC),
 method("java.security.Signature","initVerify","java.security.PublicKey",7,ADH_CF_ASYMMETRIC),
 method("java.security.Signature","sign","",8,ADH_CF_ASYMMETRIC),method("java.security.Signature","verify","[B",8,ADH_CF_ASYMMETRIC)};}
static size_t find(const char*cls,const char*name,const char*params=nullptr) {for(size_t i=0;i<g_registry.methods.size();i++){auto&m=g_registry.methods[i];if(m.cls==cls&&m.method==name&&(!params||m.params==params))return i;}fail("method missing");return 0;}
static void choose(uint64_t wanted) {std::string bits(g_registry.methods.size(),'0');for(size_t i=0;i<bits.size();i++)if(wanted&(UINT64_C(1)<<i))bits[i]='1';CHECK(!g_registry.select(g_registry.catalog.c_str(),std::to_string(g_registry.revision).c_str(),bits.c_str(),false));}
static int active_count() {int n=0;for(auto&h:g_java_hooks)if(h.bridge&&h.bridge->active)n++;return n;}
#endif
int main(int argc,char**argv) {
 CHECK(argc==2);std::string name=argv[1];char error[256];
 if(name=="producer-gate") {
   CHECK(!adh_java_crypto_running());adh_java_crypto_arm();CHECK(adh_java_crypto_running());
   CHECK(!adh_java_crypto_stop());CHECK(!adh_java_crypto_running());
   adh_java_crypto_arm();CHECK(adh_java_crypto_running());
 } else if(name=="arm-again") {
   adh_java_crypto_arm();
#if ADH_HAS_REGISTRY
   g_worker_running=false;
#else
   g_finished=1;
#endif
   adh_java_crypto_arm();CHECK(kicks==2);
 } else if(name=="generic-unhook-ownership") {
   MockBridge manual,capture;manual.active=capture.active=true;
   g_java_hooks[0]={11,0,1,1,1,&manual};g_java_hooks[1]={12,1,1,1,1,&capture};
   CHECK(adh_javahook_unhook_id(&fake_env,0,error,sizeof(error)));CHECK(!manual.active);CHECK(capture.active&&g_java_hooks[1].id==12);
   CHECK(!adh_javahook_unhook_id(&fake_env,12,error,sizeof(error)));CHECK(capture.active);
 } else {
#if ADH_HAS_REGISTRY
   CHECK(!g_registry.publish(sample(),false));
   if(name=="catalog") {
     AdhCryptoRegistry other;auto rows=sample();std::reverse(rows.begin(),rows.end());rows.push_back(rows[0]);CHECK(!other.publish(rows,false));CHECK(other.catalog==g_registry.catalog);CHECK(other.methods.size()==10);
     CHECK(g_registry.publish(sample(),false));CHECK(g_registry.catalog.rfind("java-crypto/1:",0)==0);
   } else if(name=="cipher-dependencies"||name=="signature-dependencies"||name=="shared-family") {
     size_t i=find("javax.crypto.Cipher","doFinal");if(name=="signature-dependencies")i=find("java.security.Signature","sign");
     choose(UINT64_C(1)<<i);uint64_t effective=g_registry.effective();CHECK((effective&(UINT64_C(1)<<i))!=0);
     CHECK(__builtin_popcountll(effective)==(name=="signature-dependencies"?2:3));
     if(name=="signature-dependencies")CHECK(!(effective&(UINT64_C(1)<<find("java.security.Signature","initVerify"))));
     if(name=="shared-family"){g_registry.set_families(ADH_CF_AEAD);CHECK(g_registry.effective()==effective);g_registry.set_families(ADH_CF_SYMMETRIC);CHECK(g_registry.effective()==effective);g_registry.set_families(0);CHECK(!g_registry.effective());}
   } else if(name=="missing-dependency") {
     AdhCryptoRegistry r;auto m=method("javax.crypto.Cipher","doFinal","[B",2,ADH_CF_SYMMETRIC);CHECK(!r.publish({m},false));CHECK(r.methods[0].dependencyUnavailable);CHECK(!r.effective());
   } else if(name=="revision") {
     auto revision=g_registry.revision;choose(0);CHECK(g_registry.revision==revision+1);choose(0);CHECK(g_registry.revision==revision+1);
     std::string bits(g_registry.methods.size(),'1');CHECK(std::string(g_registry.select("bad","1",bits.c_str(),false))=="CATALOG_MISMATCH");
     CHECK(std::string(g_registry.select(g_registry.catalog.c_str(),"1",bits.c_str(),false))=="REVISION_CONFLICT");
     const char*bad[]={"4294967296","01","1x","-1"};for(auto p:bad)CHECK(std::string(g_registry.select(g_registry.catalog.c_str(),p,bits.c_str(),false))=="INVALID_REVISION");
     auto rev=std::to_string(g_registry.revision);CHECK(std::string(g_registry.select(g_registry.catalog.c_str(),rev.c_str(),"bad",false))=="INVALID_SELECTION");
     g_registry.set_running(true);CHECK(std::string(g_registry.select(g_registry.catalog.c_str(),rev.c_str(),bits.c_str(),false))=="CAPTURE_ACTIVE");g_registry.set_running(false);
     CHECK(std::string(g_registry.select(g_registry.catalog.c_str(),rev.c_str(),bits.c_str(),true))=="JAVA_SETTLING");
   } else if(name=="bounded-40") {
     AdhCryptoRegistry r;std::vector<AdhCryptoMethod> rows;for(int i=0;i<41;i++)rows.push_back(method("java.security.MessageDigest",("digest"+std::to_string(i)).c_str(),"[B",5,ADH_CF_DIGEST));
     CHECK(!r.publish(rows,false));CHECK(r.methods.size()==40&&r.truncated);r.set_running(true);CHECK(r.effective()==((UINT64_C(1)<<40)-1));
   } else if(name=="owned-toggle") {
     MockBridge capture;g_java_hooks[0]={22,1,1,1,1,&capture};capture.active=true;
     CHECK(!adh_javahook_set_enabled(&fake_env,22,0,0));CHECK(capture.active);
     CHECK(adh_javahook_set_enabled(&fake_env,22,1,0));CHECK(!capture.active&&g_java_hooks[0].id==22);CHECK(capture.epoch==1);
     CHECK(adh_javahook_set_enabled(&fake_env,22,1,1));CHECK(capture.active&&capture.epoch==2);
     capture.active=false;CHECK(adh_javahook_set_enabled(&fake_env,22,1,1));CHECK(capture.active&&capture.epoch==3);
   } else if(name=="worker-id-reuse"||name=="worker-stop-race"||name=="worker-family-race"||name=="worker-retry"||name=="worker-control-retry"||name=="stop-memo"||name=="stop-no-jni"||name=="worker-wrong-owner") {
     if(name=="worker-stop-race")stop_during_install=true;
     if(name=="worker-family-race")family_during_install=true;
     if(name=="worker-retry")fail_install=true;
     if(name=="worker-control-retry")control_failure=true;
     g_registry.set_running(true);reconcile(&fake_env);
     if(name=="worker-stop-race"||name=="worker-family-race") {CHECK(active_count()==0&&enables==0);}
     else if(name=="worker-retry"){CHECK(!active_count());fail_install=false;reconcile(&fake_env);CHECK(active_count()==10);}
     else if(name=="worker-control-retry"){reconcile(&fake_env);CHECK(active_count()==10);CHECK(installs==10);}
     else {
       CHECK(active_count()==10);int initial=installs;std::vector<int> ids;for(auto&m:g_registry.methods)ids.push_back(m.hookId);
       if(name=="worker-id-reuse")for(int n=0;n<100;n++){CHECK(!adh_java_crypto_stop());CHECK(!active_count());g_registry.set_running(true);reconcile(&fake_env);CHECK(active_count()==10);CHECK(installs==initial);for(size_t i=0;i<ids.size();i++)CHECK(g_registry.methods[i].hookId==ids[i]);}
       else if(name=="worker-wrong-owner"){g_java_hooks[0].owner=0;g_java_hooks[0].bridge->active=false;reconcile(&fake_env);CHECK(!g_java_hooks[0].bridge->active);CHECK(g_registry.methods[0].active==-1);}
       else if(name=="stop-no-jni"){env_available=false;CHECK(adh_java_crypto_stop()>0);env_available=true;CHECK(!adh_java_crypto_stop());CHECK(!active_count());}
       else {CHECK(!adh_java_crypto_stop());CHECK(!active_count()&&clears==1);}
     }
   } else if(name=="worker-exit-wakeup") {
     g_registry.set_running(false);g_worker_running=true;exit_race=true;worker(nullptr);CHECK(kicks==1&&g_worker_running&&g_registry.running);
   } else if(name=="status-json") {
     g_registry.set_running(true);reconcile(&fake_env);CHECK(!adh_java_crypto_stop());adh_cmd_java_capture(-1,"quote\"id","{\"action\":\"status\"}");std::puts(wire.c_str());
   } else fail("unknown case");
#else
   fail("capture-owned registry/control unavailable in baseline");
#endif
 }
 CHECK(lock_depth==0);std::printf("PASS %s\n",name.c_str());return 0;
}
#endif

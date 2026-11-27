#include "java_crypto.h"
#include "java_crypto_registry.h"
#include "java_lsplant.h"
#include "../runtime/jni.h"
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>
#include <atomic>
extern "C" int send_line(int fd, const char *line);
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "rt.agent", __VA_ARGS__)

static pthread_mutex_t g_crypto_lock = PTHREAD_MUTEX_INITIALIZER;
static AdhCryptoRegistry g_registry;
// Reporter callbacks run on target crypto threads; never take the controller mutex here.
static std::atomic<bool> g_observing{false};
static bool g_started = false, g_worker_running = false;
static std::string g_missing_classes;

struct Target { const char *cls, *method; int mode; uint32_t families; };
static const Target kTargets[] = {
 {"javax.crypto.Cipher","init",1,ADH_CF_SYMMETRIC|ADH_CF_AEAD},
 {"javax.crypto.Cipher","doFinal",2,ADH_CF_SYMMETRIC|ADH_CF_AEAD},
 {"javax.crypto.Mac","init",3,ADH_CF_HMAC},
 {"javax.crypto.Mac","doFinal",4,ADH_CF_HMAC},
 {"java.security.MessageDigest","digest",5,ADH_CF_DIGEST},
 {"java.security.Signature","initSign",7,ADH_CF_ASYMMETRIC},
 {"java.security.Signature","initVerify",7,ADH_CF_ASYMMETRIC},
 {"java.security.Signature","sign",8,ADH_CF_ASYMMETRIC},
 {"java.security.Signature","verify",8,ADH_CF_ASYMMETRIC},
};

static std::string jstr(JNIEnv *env, jstring value) {
    if (!value) return "";
    const char *chars = env->GetStringUTFChars(value, nullptr);
    std::string out = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return out;
}

static jclass load_named(JNIEnv *env, const char *dot) {
    jobject loader = nullptr;
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID for_name = class_class ? env->GetStaticMethodID(
        class_class, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;") : nullptr;
    jstring name = env->NewStringUTF(dot);
    jclass found = nullptr;
    if (for_name && name && loader) {
        found = (jclass)env->CallStaticObjectMethod(class_class, for_name, name, JNI_FALSE, loader);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!found && for_name && name) {
        found = (jclass)env->CallStaticObjectMethod(class_class, for_name, name, JNI_FALSE, nullptr);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (name) env->DeleteLocalRef(name);
    if (class_class) env->DeleteLocalRef(class_class);
    return found;
}


static void collect_overloads(JNIEnv *env, jclass cls, const Target &target, std::vector<AdhCryptoMethod> *jobs, bool *truncated) {
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared = env->GetMethodID(class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID get_params = env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID class_get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    if (!get_declared || !get_name || !get_params || !class_get_name) {
        if (class_class) env->DeleteLocalRef(class_class);
        if (method_class) env->DeleteLocalRef(method_class);
        return;
    }
    jobjectArray methods = (jobjectArray)env->CallObjectMethod(cls, get_declared);
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (!methods) {
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(method_class);
        return;
    }
    jsize count = env->GetArrayLength(methods);
    for (jsize i = 0; i < count; i++) {
        jobject method = env->GetObjectArrayElement(methods, i);
        if (!method) continue;
        jstring jname = (jstring)env->CallObjectMethod(method, get_name);
        std::string name = jstr(env, jname);
        if (jname) env->DeleteLocalRef(jname);
        if (name != target.method) { env->DeleteLocalRef(method); continue; }
        if (jobs->size() >= AdhCryptoRegistry::limit) { *truncated = true; env->DeleteLocalRef(method); continue; }
        std::string params;
        jobjectArray types = (jobjectArray)env->CallObjectMethod(method, get_params);
        jsize nparams = types ? env->GetArrayLength(types) : 0;
        for (jsize p = 0; p < nparams; p++) {
            jclass pt = (jclass)env->GetObjectArrayElement(types, p);
            jstring pn = pt ? (jstring)env->CallObjectMethod(pt, class_get_name) : nullptr;
            if (p) params += ",";
            params += jstr(env, pn);
            if (pn) env->DeleteLocalRef(pn);
            if (pt) env->DeleteLocalRef(pt);
        }
        if (types) env->DeleteLocalRef(types);
        env->DeleteLocalRef(method);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (params.size() > 512) { *truncated = true; continue; }
        AdhCryptoMethod job;
        job.cls = target.cls;
        job.method = target.method;
        job.params = params;
        job.mode = target.mode;
        job.families = target.families;
        jobs->push_back(job);
    }
    env->DeleteLocalRef(methods);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(method_class);
}


static std::string quote(const std::string &s) {
    std::string out="\"";
    for(unsigned char c:s) {
        if(c=='"'||c=='\\'){out+='\\';out+=(char)c;}
        else if(c<32){char b[7];std::snprintf(b,sizeof(b),"\\u%04x",c);out+=b;}
        else out+=(char)c;
    }
    return out+"\"";
}

static void discover(JNIEnv *env) {
    std::vector<AdhCryptoMethod> found; bool truncated=false;
    std::string missing;
    for(const Target &target:kTargets) {
        jclass cls=load_named(env,target.cls);
        if(!cls){if(missing.find(target.cls)==std::string::npos){if(!missing.empty())missing+=",";missing+=target.cls;}continue;}
        collect_overloads(env,cls,target,&found,&truncated);env->DeleteLocalRef(cls);
    }
    pthread_mutex_lock(&g_crypto_lock);
    if(!g_registry.discovered){const char *e=g_registry.publish(std::move(found),truncated);if(e)g_registry.error=e;}
    g_missing_classes=missing;
    pthread_mutex_unlock(&g_crypto_lock);
}

static uint64_t reconcile(JNIEnv *env) {
    // Install inactive first. Only a generation-current commit may enable the bridge;
    // stop never races a new installation into an observing state.
    for(int pass=0;pass<8;pass++) {
        pthread_mutex_lock(&g_crypto_lock);
        uint64_t generation=g_registry.generation;size_t count=g_registry.methods.size();
        pthread_mutex_unlock(&g_crypto_lock);
        for(size_t i=0;i<count;i++) {
            pthread_mutex_lock(&g_crypto_lock);
            bool install=g_registry.want(i)&&!g_registry.methods[i].hookId;
            AdhCryptoMethod target=g_registry.methods[i];
            pthread_mutex_unlock(&g_crypto_lock);
            int hook_id=target.hookId;char error[256]="";
            if(install) {
                int ok=adh_javahook_hook_method_owned(env,ADH_JAVA_OWNER_CAPTURE,target.cls.c_str(),target.method.c_str(),
                    target.params.c_str(),0,"",-1,"",0,1,&hook_id,error,sizeof(error));
                if(!ok&&error[0]==0)std::snprintf(error,sizeof(error),"JAVA_INSTALL_FAILED");
                if(hook_id>0&&!adh_javahook_set_crypto_mode(env,hook_id,target.mode))
                    std::snprintf(error,sizeof(error),"CRYPTO_MODE_FAILED");
            }
            pthread_mutex_lock(&g_crypto_lock);
            AdhCryptoMethod &job=g_registry.methods[i];
            if(install){job.hookId=hook_id;job.error=error;}
            if(job.hookId>0) {
                bool owned=adh_javahook_get_enabled(env,job.hookId,ADH_JAVA_OWNER_CAPTURE)>=0;
                bool mode_ok=owned&&adh_javahook_set_crypto_mode(env,job.hookId,job.mode);
                if(mode_ok)job.error.clear();else job.error=owned?"CRYPTO_MODE_FAILED":"OWNERSHIP_UNKNOWN";
                bool enabled=g_registry.want(i)&&mode_ok;
                if(!adh_javahook_set_enabled(env,job.hookId,ADH_JAVA_OWNER_CAPTURE,enabled))job.error="JAVA_CONTROL_FAILED";
                job.active=adh_javahook_get_enabled(env,job.hookId,ADH_JAVA_OWNER_CAPTURE);
            }
            pthread_mutex_unlock(&g_crypto_lock);
        }
        pthread_mutex_lock(&g_crypto_lock);bool settled=g_registry.generation==generation;pthread_mutex_unlock(&g_crypto_lock);
        if(settled)return generation;
    }
    pthread_mutex_lock(&g_crypto_lock);g_registry.error="POLICY_CHURN: reconcile again after writes settle";pthread_mutex_unlock(&g_crypto_lock);
    return 0;
}

static bool kick_locked(void);
static void *worker(void *) {
    bool ready=false;uint64_t reconciled=0;
    for(int attempt=0;attempt<40;attempt++) {
        int attached=0;JNIEnv *env=adh_jni_attach(&attached);
        jobject loader=env?adh_jni_app_class_loader(env):nullptr;
        if(env&&loader) {
            adh_javahook_install_lock();
            pthread_mutex_lock(&g_crypto_lock);bool known=g_registry.discovered;pthread_mutex_unlock(&g_crypto_lock);
            if(!known)discover(env);
            reconciled=reconcile(env);
            adh_javahook_install_unlock();ready=true;
            if(attached)adh_jni_detach(attached);break;
        }
        if(attached)adh_jni_detach(attached);usleep(250*1000);
    }
    pthread_mutex_lock(&g_crypto_lock);
    if(!ready)g_registry.error="NO_APP_CLASS_LOADER";
    g_worker_running=false;
    // Close the final-check/worker-exit lost-wakeup window under the same policy lock.
    if(ready&&reconciled!=g_registry.generation&&g_registry.discovered)kick_locked();
    pthread_mutex_unlock(&g_crypto_lock);
    return nullptr;
}
static bool kick_locked(void) {
    if(g_worker_running)return true;
    g_worker_running=true;g_started=true;g_registry.error.clear();
    pthread_t thread;
    if(pthread_create(&thread,nullptr,worker,nullptr)==0){pthread_detach(thread);return true;}
    g_worker_running=false;g_registry.error="JAVA_WORKER_FAILED";return false;
}

extern "C" int adh_java_crypto_running(void) {return g_observing.load(std::memory_order_acquire);}
extern "C" int adh_java_crypto_started(void) {pthread_mutex_lock(&g_crypto_lock);int value=g_started;pthread_mutex_unlock(&g_crypto_lock);return value;}
extern "C" int adh_java_crypto_finished(void) {pthread_mutex_lock(&g_crypto_lock);int value=!g_worker_running;pthread_mutex_unlock(&g_crypto_lock);return value;}
extern "C" void adh_java_crypto_arm(void) {pthread_mutex_lock(&g_crypto_lock);g_registry.set_running(true);g_observing.store(true,std::memory_order_release);kick_locked();pthread_mutex_unlock(&g_crypto_lock);}
extern "C" void adh_java_crypto_set_families(unsigned families) {
    pthread_mutex_lock(&g_crypto_lock);g_registry.set_families(families);if(g_registry.running)kick_locked();pthread_mutex_unlock(&g_crypto_lock);
}
extern "C" int adh_java_crypto_stop(void) {
    g_observing.store(false,std::memory_order_release);
    int attached=0;JNIEnv *env=adh_jni_attach(&attached);int pending=0;
    pthread_mutex_lock(&g_crypto_lock);g_registry.set_running(false);
    bool retained_hooks=false;
    for(auto &job:g_registry.methods)if(job.hookId>0) {
        retained_hooks=true;
        if(!env||!adh_javahook_set_enabled(env,job.hookId,ADH_JAVA_OWNER_CAPTURE,0)){pending++;job.error="JAVA_STOP_PENDING";}
        else job.active=0;
    }
    // With no published owned hook there can be no capture memo yet. Avoid reading
    // bridge loader globals while the first inactive installation is still in flight.
    if(retained_hooks&&!adh_javahook_clear_crypto(env))pending++;
    pthread_mutex_unlock(&g_crypto_lock);
    if(attached)adh_jni_detach(attached);return pending;
}

extern "C" void adh_cmd_java_capture(int fd,const char *id,const char *request) {
    char action[16]="",version[64]="",revision[16]="",selection[AdhCryptoRegistry::limit+2]="";
    std::string failure;
    if(!adh_capture_string_field(request,"action",action,sizeof(action)))failure="INVALID_REQUEST";
    if(failure.empty()&&!std::strcmp(action,"stop")){if(adh_java_crypto_stop())failure="JAVA_STOP_PENDING";}
    pthread_mutex_lock(&g_crypto_lock);
    if(failure.empty()) {
        if(!std::strcmp(action,"discover")){if(!kick_locked())failure=g_registry.error;}
        else if(!std::strcmp(action,"start")){g_registry.set_running(true);g_observing.store(true,std::memory_order_release);if(!kick_locked())failure=g_registry.error;}
        else if(!std::strcmp(action,"set")) {
            if(!adh_capture_string_field(request,"catalog",version,sizeof(version))||!adh_capture_string_field(request,"revision",revision,sizeof(revision))||
               !adh_capture_string_field(request,"selection",selection,sizeof(selection)))failure="INVALID_REQUEST";
            else {const char *e=g_registry.select(version,revision,selection,g_worker_running);if(e)failure=e;}
        } else if(std::strcmp(action,"status")&&std::strcmp(action,"stop"))failure="INVALID_ACTION";
    }
    pthread_mutex_unlock(&g_crypto_lock);
    int attached=0;JNIEnv *env=adh_jni_attach(&attached);
    pthread_mutex_lock(&g_crypto_lock);
    uint64_t effective=g_registry.effective();
    std::string out="{\"t\":\"cmdResult\",\"id\":"+quote(id?id:"")+",\"op\":\"java_capture\",\"ok\":"+(failure.empty()?"true":"false")+
        ",\"error\":"+(failure.empty()?"null":quote(failure))+",\"catalog\":"+quote(g_registry.catalog)+",\"revision\":"+quote(std::to_string(g_registry.revision))+
        ",\"on\":"+(g_registry.running?"true":"false")+",\"settling\":"+(g_worker_running?"true":"false")+",\"discovered\":"+(g_registry.discovered?"true":"false")+
        ",\"truncated\":"+(g_registry.truncated?"true":"false")+",\"missingClasses\":"+quote(g_missing_classes)+",\"lastError\":"+quote(g_registry.error)+",\"methods\":[";
    for(size_t i=0;i<g_registry.methods.size();i++) {
        auto &m=g_registry.methods[i];
        if(m.hookId>0)m.active=adh_javahook_get_enabled(env,m.hookId,ADH_JAVA_OWNER_CAPTURE);
        const char *state=m.active<0?"ownership-unknown":m.active?"observing":m.hookId>0?"soft-disabled":m.dependencyUnavailable?"dependency-unavailable":!m.error.empty()?"install-failed":"not-installed";
        out+=(i?",":"")+std::string("{\"id\":")+quote(m.id)+",\"class\":"+quote(m.cls)+",\"method\":"+quote(m.method)+",\"params\":"+quote(m.params)+
            ",\"families\":"+std::to_string(m.families)+",\"hookId\":"+std::to_string(m.hookId)+",\"owner\":\"capture\",\"requested\":"+(m.selected?"true":"false")+
            ",\"effective\":"+((effective&(UINT64_C(1)<<i))?"true":"false")+",\"dependency\":"+((!m.selected&&(effective&(UINT64_C(1)<<i)))?"true":"false")+
            ",\"active\":"+(m.active>0?"true":"false")+",\"patched\":"+(m.hookId>0?"true":"false")+",\"state\":"+quote(state)+",\"error\":"+quote(m.error)+",\"requires\":[";
        bool first=true;for(size_t j=0;j<g_registry.methods.size();j++)if(m.dependencies&(UINT64_C(1)<<j)){if(!first)out+=",";out+=quote(g_registry.methods[j].id);first=false;}
        out+="]}";
    }
    out+="]}";pthread_mutex_unlock(&g_crypto_lock);if(attached)adh_jni_detach(attached);
    if(out.size()>131072)out="{\"t\":\"cmdResult\",\"id\":"+quote(id?id:"")+",\"op\":\"java_capture\",\"ok\":false,\"error\":\"CATALOG_TOO_LARGE\"}";
    send_line(fd,out.c_str());
}

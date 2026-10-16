#include "java_crypto.h"

#include "java_lsplant.h"
#include "../capture/capture.h"
#include "../runtime/jni.h"

#include <android/log.h>
#include <pthread.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <vector>

#define TAG "rt.agent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int g_finished = 0;

struct Target {
    const char *cls;
    const char *method;
    int mode;
    int family;   // 0 digest, 1 hmac, 2 symmetric or aead, 3 asymmetric
};

static const Target kTargets[] = {
    {"javax.crypto.Cipher", "init", 1, 2},
    {"javax.crypto.Cipher", "doFinal", 2, 2},
    {"javax.crypto.Mac", "init", 3, 1},
    {"javax.crypto.Mac", "doFinal", 4, 1},
    {"java.security.MessageDigest", "digest", 5, 0},
    {"java.security.Signature", "initSign", 7, 3},
    {"java.security.Signature", "initVerify", 7, 3},
    {"java.security.Signature", "sign", 8, 3},
    {"java.security.Signature", "verify", 8, 3},
};

static int want_family(int family, int digest, int hmac, int symmetric, int asymmetric, int aead) {
    if (family == 0) return digest;
    if (family == 1) return hmac;
    if (family == 2) return symmetric || aead;
    if (family == 3) return asymmetric;
    return 0;
}

static std::string jstr(JNIEnv *env, jstring value) {
    if (!value) return "";
    const char *chars = env->GetStringUTFChars(value, nullptr);
    std::string out = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    return out;
}

static jclass load_named(JNIEnv *env, const char *dot) {
    jobject loader = adh_jni_app_class_loader(env);
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID for_name = class_class ? env->GetStaticMethodID(
        class_class, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;") : nullptr;
    jstring name = env->NewStringUTF(dot);
    jclass found = nullptr;
    if (for_name && name && loader) {
        found = (jclass)env->CallStaticObjectMethod(class_class, for_name, name, JNI_TRUE, loader);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (!found && for_name && name) {
        found = (jclass)env->CallStaticObjectMethod(class_class, for_name, name, JNI_TRUE, nullptr);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    if (name) env->DeleteLocalRef(name);
    if (class_class) env->DeleteLocalRef(class_class);
    return found;
}

struct Job {
    std::string cls;
    std::string method;
    std::string params;
    int mode = 0;
    int installed = 0;
    int finished = 0;
};

static void *run_job(void *arg) {
    Job *job = static_cast<Job *>(arg);
    int attached = 0;
    JNIEnv *env = adh_jni_attach(&attached);
    if (!env) return nullptr;
    char error[256] = "";
    int hook_id = 0;
    int ok = adh_javahook_hook_method(env, job->cls.c_str(), job->method.c_str(), job->params.c_str(),
                                      0, "", -1, "", 0, 1, &hook_id, error, sizeof(error));
    if (!ok) LOGI("java crypto miss %s#%s: %s", job->cls.c_str(), job->method.c_str(), error);
    else if (!adh_javahook_set_crypto_mode(env, hook_id, job->mode))
        LOGI("java crypto mode failed id=%d %s#%s", hook_id, job->cls.c_str(), job->method.c_str());
    else job->installed = 1;
    if (attached) adh_jni_detach(attached);
    __atomic_store_n(&job->finished, 1, __ATOMIC_RELEASE);
    return nullptr;
}

static void collect_overloads(JNIEnv *env, jclass cls, const Target &target, std::vector<Job> *jobs) {
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
    for (jsize i = 0; i < count && jobs->size() < 40; i++) {
        jobject method = env->GetObjectArrayElement(methods, i);
        if (!method) continue;
        jstring jname = (jstring)env->CallObjectMethod(method, get_name);
        std::string name = jstr(env, jname);
        if (jname) env->DeleteLocalRef(jname);
        if (name != target.method) { env->DeleteLocalRef(method); continue; }
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
        Job job;
        job.cls = target.cls;
        job.method = target.method;
        job.params = params;
        job.mode = target.mode;
        jobs->push_back(job);
    }
    env->DeleteLocalRef(methods);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(method_class);
}

static int install_all(JNIEnv *env) {
    int digest = 1, hmac = 1, symmetric = 1, asymmetric = 1, tls = 1, aead = 1;
    adh_capture_get_families(&digest, &hmac, &symmetric, &asymmetric, &tls, &aead);
    std::vector<Job> jobs;
    const char *failed = nullptr;
    for (const Target &target : kTargets) {
        if (jobs.size() >= 40) break;
        if (!want_family(target.family, digest, hmac, symmetric, asymmetric, aead)) continue;
        if (failed && strcmp(failed, target.cls) == 0) continue;
        jclass cls = load_named(env, target.cls);
        if (!cls) { failed = target.cls; continue; }
        failed = nullptr;
        collect_overloads(env, cls, target, &jobs);
        env->DeleteLocalRef(cls);
    }
    // One thread per method. A fault inside LSPlant kills that thread only; the
    // rest of the overloads still get installed.
    int installed = 0;
    for (Job &job : jobs) {
        if (installed >= 40) break;
        // Heap copy: a stuck installer thread may still write the job after we move on.
        Job *owned = new Job(job);
        pthread_t thread;
        if (pthread_create(&thread, nullptr, run_job, owned) != 0) {
            delete owned;
            continue;
        }
        for (int spin = 0; spin < 20 && !__atomic_load_n(&owned->finished, __ATOMIC_ACQUIRE); spin++)
            usleep(50 * 1000);
        if (!__atomic_load_n(&owned->finished, __ATOMIC_ACQUIRE)) {
            LOGI("java crypto stuck %s#%s(%s)", owned->cls.c_str(), owned->method.c_str(), owned->params.c_str());
            pthread_detach(thread);
            continue;
        }
        pthread_join(thread, nullptr);
        if (owned->installed) installed++;
        delete owned;
    }
    LOGI("java crypto on %d", installed);
    return installed;
}

static void *worker(void *) {
    for (int attempt = 0; attempt < 40; attempt++) {
        int attached = 0;
        JNIEnv *env = adh_jni_attach(&attached);
        jobject loader = env ? adh_jni_app_class_loader(env) : nullptr;
        if (env && loader) {
            install_all(env);
            if (attached) adh_jni_detach(attached);
            __atomic_store_n(&g_finished, 1, __ATOMIC_RELEASE);
            return nullptr;
        }
        if (attached) adh_jni_detach(attached);
        usleep(250 * 1000);
    }
    LOGI("java crypto gave up: no app ClassLoader");
    __atomic_store_n(&g_finished, 1, __ATOMIC_RELEASE);
    return nullptr;
}

extern "C" int adh_java_crypto_finished(void) {
    return __atomic_load_n(&g_finished, __ATOMIC_ACQUIRE);
}

extern "C" void adh_java_crypto_arm(void) {
    pthread_t thread;
    if (pthread_create(&thread, nullptr, worker, nullptr) == 0) pthread_detach(thread);
    else LOGI("java crypto thread failed");
}

#include "ssl_bypass.h"

#include "java_crypto.h"
#include "java_lsplant.h"
#include "../runtime/jni.h"

#include <android/log.h>
#include <pthread.h>
#include <unistd.h>

#include <cstring>
#include <string>

#define TAG "rt.agent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int g_enabled = 1;
static int g_finished = 0;

struct Scan {
    const char *cls;
    const char *method;
    int kind;   // 0 = choose from the return type, 1 = SSLContext.init replaces the trust managers
};

// Concrete classes only. Hooking an interface does not reach the implementation.
// Every handshake on this stack asks TrustManagerImpl / Platform, including clients created
// before SSLContext.init was replaced. RegisterNative is not hooked on API 31+; that hook,
// not these methods, is what killed the process inside JNI_OnLoad.
static const Scan kScans[] = {
    {"com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", 0},
    {"com.android.org.conscrypt.TrustManagerImpl", "getTrustedChainForServer", 0},
    {"com.android.org.conscrypt.TrustManagerImpl", "checkTrusted", 0},
    {"com.android.org.conscrypt.TrustManagerImpl", "verifyChain", 0},
    {"com.android.org.conscrypt.Platform", "checkServerTrusted", 0},
    {"com.android.org.conscrypt.Platform", "checkTrusted", 0},
    {"com.android.org.conscrypt.ConscryptEngine", "verifyCertificateChain", 0},
    {"javax.net.ssl.SSLContext", "init", 1},
    {"javax.net.ssl.TrustManagerFactory", "getTrustManagers", 0},
    {"okhttp3.CertificatePinner", "check", 0},
    {"com.squareup.okhttp.CertificatePinner", "check", 0},
    {"okhttp3.internal.tls.OkHostnameVerifier", "verify", 0},
    {"com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", 0},
};

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
    return found;
}

// skip < 0 means "do not install": the return type is something a blind null would crash.
static void choose_override(const std::string &ret, int kind, const std::string &params,
                            int *skip, const char **over, int *arg_index, const char **arg_value) {
    *skip = 1;
    *over = "";
    *arg_index = -1;
    *arg_value = "";
    if (kind == 1) {
        int index = 0;
        int found = -1;
        size_t start = 0;
        while (start <= params.size()) {
            size_t comma = params.find(',', start);
            std::string one = params.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (one.find("TrustManager") != std::string::npos) found = index;
            if (comma == std::string::npos) break;
            start = comma + 1;
            index++;
        }
        if (found < 0) { *skip = -1; return; }
        *skip = 0;
        *arg_index = found;
        *arg_value = "@trust";
        return;
    }
    if (ret == "void") return;
    if (ret == "boolean") { *over = "true"; return; }
    if (ret == "java.util.List") { *over = "@chain"; return; }
    if (ret == "[Ljavax.net.ssl.TrustManager;") { *over = "@trust"; return; }
    if (!ret.empty() && ret[0] == '[' && ret.find("Certificate") != std::string::npos) { *over = "@chain"; return; }
    *skip = -1;
}

static int install_overloads(JNIEnv *env, jclass cls, const Scan &scan, int *installed) {
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared = env->GetMethodID(class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID get_params = env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID get_return = env->GetMethodID(method_class, "getReturnType", "()Ljava/lang/Class;");
    jmethodID class_get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    if (!get_declared || !get_name || !get_params || !get_return || !class_get_name) return 0;

    jobjectArray methods = (jobjectArray)env->CallObjectMethod(cls, get_declared);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return 0; }
    if (!methods) return 0;
    int matched = 0;
    jsize count = env->GetArrayLength(methods);
    for (jsize i = 0; i < count && *installed < 48; i++) {
        jobject method = env->GetObjectArrayElement(methods, i);
        if (!method) continue;
        jstring jname = (jstring)env->CallObjectMethod(method, get_name);
        std::string name = jstr(env, jname);
        if (jname) env->DeleteLocalRef(jname);
        if (name != scan.method) { env->DeleteLocalRef(method); continue; }

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
        jclass ret_class = (jclass)env->CallObjectMethod(method, get_return);
        jstring ret_name = ret_class ? (jstring)env->CallObjectMethod(ret_class, class_get_name) : nullptr;
        std::string ret = jstr(env, ret_name);
        if (ret_name) env->DeleteLocalRef(ret_name);
        if (ret_class) env->DeleteLocalRef(ret_class);
        env->DeleteLocalRef(method);
        if (env->ExceptionCheck()) env->ExceptionClear();

        int skip = 0, arg_index = -1;
        const char *over = "";
        const char *arg_value = "";
        choose_override(ret, scan.kind, params, &skip, &over, &arg_index, &arg_value);
        if (skip < 0) continue;
        matched++;
        char error[256] = "";
        int hook_id = 0;
        int ok = adh_javahook_hook_method(env, scan.cls, scan.method, params.c_str(),
                                          skip, over, arg_index, arg_value, 0, 1,
                                          &hook_id, error, sizeof(error));
        if (ok) (*installed)++;
        else LOGI("ssl bypass miss %s#%s: %s", scan.cls, scan.method, error);
    }
    env->DeleteLocalRef(methods);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(method_class);
    return matched;
}

static int install_all(JNIEnv *env) {
    int installed = 0;
    std::string missing;
    const char *failed_class = nullptr;
    for (const Scan &scan : kScans) {
        if (installed >= 48) break;
        if (failed_class && strcmp(failed_class, scan.cls) == 0) continue;
        jclass cls = load_named(env, scan.cls);
        if (!cls) {
            failed_class = scan.cls;
            if (!missing.empty()) missing += ",";
            const char *leaf = strrchr(scan.cls, '.');
            missing += leaf ? leaf + 1 : scan.cls;
            continue;
        }
        failed_class = nullptr;
        int matched = install_overloads(env, cls, scan, &installed);
        env->DeleteLocalRef(cls);
        if (matched == 0) LOGI("ssl bypass no overload %s#%s", scan.cls, scan.method);
    }
    LOGI("ssl bypass on %d miss:%s", installed, missing.c_str());
    return installed;
}

static void *worker(void *) {
    // LSPlant is not safe from two threads. Algorithm hooks run first; this installer
    // starts only after that one has returned.
    for (int wait = 0; wait < 120 && !adh_java_crypto_finished(); wait++) usleep(100 * 1000);
    if (!g_enabled) {
        LOGI("ssl bypass off");
        __atomic_store_n(&g_finished, 1, __ATOMIC_RELEASE);
        return nullptr;
    }
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
    LOGI("ssl bypass gave up: no app ClassLoader");
    __atomic_store_n(&g_finished, 1, __ATOMIC_RELEASE);
    return nullptr;
}

extern "C" int adh_ssl_bypass_finished(void) {
    return __atomic_load_n(&g_finished, __ATOMIC_ACQUIRE);
}

extern "C" void adh_ssl_bypass_set_enabled(int on) {
    g_enabled = on ? 1 : 0;
}

extern "C" void adh_ssl_bypass_arm(void) {
    pthread_t thread;
    if (pthread_create(&thread, nullptr, worker, nullptr) == 0) pthread_detach(thread);
    else LOGI("ssl bypass thread failed");
}

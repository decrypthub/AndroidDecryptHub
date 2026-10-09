// LSPlant (ART Java-method hook) integration — C++ side.
//
// LSPlant v6.4 is compiled directly into libadh_agent.so. The inline-hook backend is the
// existing statically linked Dobby implementation, exposed through native_inline.h. ART
// symbol resolution reuses the agent's in-memory .dynsym resolver from got.h.
//
// The fixed hooker class is embedded as a tiny DEX (adh_java_hook_bridge_dex.h). It contains
// no target knowledge: the native side resolves the requested Java method, installs its
// backup Method into one bridge instance, and LSPlant routes calls through that instance.
#include "java_lsplant.h"
#include "adh_java_hook_bridge_dex.h"
#include "got.h"
#include "lsplant.hpp"
#include "native_inline.h"
#include "../runtime/jni.h"
#include "../runtime/jni_env_hooks.h"
#include "../capture/capture.h"

#include <android/api-level.h>
#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#define LTAG "rt.java"
#define LLOGI(...) __android_log_print(ANDROID_LOG_INFO,  LTAG, __VA_ARGS__)
#define LLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LTAG, __VA_ARGS__)

// ---- small helpers --------------------------------------------------------------------

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
}

static bool jni_failed(JNIEnv *env, const char *stage, std::string &error) {
    if (!env || !adh_jni_exception_check(env)) return false;
    env->ExceptionDescribe();
    adh_jni_exception_clear(env);
    error = stage;
    return true;
}

static std::string trim_ascii(const std::string &value) {
    size_t begin = 0;
    while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t' ||
                                    value[begin] == '\r' || value[begin] == '\n')) begin++;
    size_t end = value.size();
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' ||
                           value[end - 1] == '\r' || value[end - 1] == '\n')) end--;
    return value.substr(begin, end - begin);
}

static std::string json_escape(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 8);
    static const char hex[] = "0123456789abcdef";
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0x0f]);
                    out.push_back(hex[c & 0x0f]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

static std::string normalize_type(std::string type) {
    type = trim_ascii(type);
    for (char &c : type) if (c == '/') c = '.';
    if (type.empty()) return type;
    if (type == "void" || type == "boolean" || type == "byte" || type == "char" ||
        type == "short" || type == "int" || type == "long" || type == "float" ||
        type == "double") {
        return type;
    }

    size_t dimensions = 0;
    while (type.size() >= 2 && type.compare(type.size() - 2, 2, "[]") == 0) {
        dimensions++;
        type.resize(type.size() - 2);
    }
    if (!dimensions) return type;

    std::string out;
    for (size_t i = 0; i < dimensions; i++) out.push_back('[');
    if (type == "boolean") out.push_back('Z');
    else if (type == "byte") out.push_back('B');
    else if (type == "char") out.push_back('C');
    else if (type == "short") out.push_back('S');
    else if (type == "int") out.push_back('I');
    else if (type == "long") out.push_back('J');
    else if (type == "float") out.push_back('F');
    else if (type == "double") out.push_back('D');
    else out += "L" + type + ";";
    return out;
}

static std::vector<std::string> split_params(const std::string &params) {
    std::vector<std::string> out;
    std::string current;
    for (char c : params) {
        if (c == ',') {
            std::string item = trim_ascii(current);
            if (!item.empty()) out.push_back(normalize_type(item));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    std::string item = trim_ascii(current);
    if (!item.empty()) out.push_back(normalize_type(item));
    return out;
}

static std::string get_string_field(JNIEnv *env, jobject object, jfieldID field) {
    if (!env || !object || !field) return "";
    jstring value = (jstring)env->GetObjectField(object, field);
    if (!value) return "";
    const char *chars = env->GetStringUTFChars(value, nullptr);
    std::string out = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    env->DeleteLocalRef(value);
    if (adh_jni_exception_check(env)) {
        adh_jni_exception_clear(env);
        return "";
    }
    return out;
}


// ---- Dobby adapter (LSPlant inline_hooker/unhooker contract) -------------------------
static void *dobby_hooker(void *target, void *hooker) {
    void *origin = nullptr;
    if (!adh_inline_hook(target, hooker, &origin)) {
        LLOGE("inline hook failed target=%p", target);
        return nullptr;
    }
    return origin;                       // LSPlant wants the backup/original callable
}

static bool dobby_unhooker(void *func) {
    return adh_inline_unhook(func) != 0;
}

// ---- one-time LSPlant init -------------------------------------------------------------
static int g_init_ok = 0;
static char g_init_error[256] = "";
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static JNIEnv *g_init_env = nullptr;

static void set_init_error(const char *message) {
    if (!message) message = "unknown LSPlant initialization failure";
    std::strncpy(g_init_error, message, sizeof(g_init_error) - 1);
    g_init_error[sizeof(g_init_error) - 1] = 0;
}

static void do_init(void) {
    if (!g_init_env) {
        set_init_error("no JavaVM/JNIEnv available");
        return;
    }

    lsplant::InitInfo info{
        .inline_hooker = dobby_hooker,
        .inline_unhooker = dobby_unhooker,
        .art_symbol_resolver = [](std::string_view s) -> void * {
            std::string name(s);
            return adh_resolve_sym("libart.so", name.c_str());
        },
        .art_symbol_prefix_resolver = [](std::string_view p) -> void * {
            std::string prefix(p);
            return adh_resolve_sym_prefix("libart.so", prefix.c_str());
        },
        .generated_class_name = "com.android.internal.util.NativeBridge_",
        .generated_source_name = "NativeBridge",
        .generated_field_name = "handler",
        .generated_method_name = "{target}",
    };

    try {
        g_init_ok = lsplant::Init(g_init_env, info) ? 1 : 0;
    } catch (...) {
        g_init_ok = 0;
        set_init_error("java hook backend init threw a C++ exception");
    }

    if (g_init_ok) {
        g_init_error[0] = 0;
        LLOGI("java hook backend init -> ok");
    } else {
        if (!g_init_error[0]) set_init_error("java hook backend init returned false (check logcat tag rt.java)");
        LLOGE("java hook backend init -> FAIL: %s", g_init_error);
    }
}

extern "C" int adh_javahook_available(void) {
    return 1;
}

extern "C" int adh_javahook_init(JNIEnv *env) {
    if (!env) {
        set_init_error("no JavaVM/JNIEnv available");
        return 0;
    }
    g_init_env = env;
    pthread_once(&g_init_once, do_init);
    return g_init_ok;
}

extern "C" const char *adh_javahook_last_error(void) {
    return g_init_error;
}

extern "C" jobject adh_javahook_hook(JNIEnv *env, jobject target_method,
                                     jobject hooker_object, jobject callback_method) {
    if (!g_init_ok || !env || !target_method || !hooker_object || !callback_method) return nullptr;
    return lsplant::Hook(env, target_method, hooker_object, callback_method);
}

extern "C" int adh_javahook_unhook(JNIEnv *env, jobject target_method) {
    if (!g_init_ok || !env || !target_method) return 0;
    return lsplant::UnHook(env, target_method) ? 1 : 0;
}

extern "C" int adh_javahook_is_hooked(JNIEnv *env, jobject method) {
    if (!env || !method) return 0;
    return lsplant::IsHooked(env, method) ? 1 : 0;
}

// Compute a Dalvik method shorty (return-type char + param-type chars) from a reflected
// Method/Constructor via JNI. Used when the ROM's libart.so does not export
// art::GetMethodShorty (ColorOS/Android 15+ strips that internal-linkage symbol) — LSPlant's
// patched art_method.hpp calls this fallback. Shorty chars: V/Z/B/C/S/I/J/F/D for primitives,
// L for any reference/array. Returns a pointer valid until the next call on the same thread.
static char adh_shorty_char(JNIEnv *env, jclass cls) {
    jclass cClass = env->FindClass("java/lang/Class");
    jmethodID isPrim = env->GetMethodID(cClass, "isPrimitive", "()Z");
    char r = 'L';
    if (env->CallBooleanMethod(cls, isPrim)) {
        jmethodID getName = env->GetMethodID(cClass, "getName", "()Ljava/lang/String;");
        jstring nm = (jstring)env->CallObjectMethod(cls, getName);
        const char *s = nm ? env->GetStringUTFChars(nm, nullptr) : nullptr;
        if (s) {
            if (!strcmp(s, "int")) r = 'I';        else if (!strcmp(s, "boolean")) r = 'Z';
            else if (!strcmp(s, "byte")) r = 'B';  else if (!strcmp(s, "char")) r = 'C';
            else if (!strcmp(s, "short")) r = 'S'; else if (!strcmp(s, "long")) r = 'J';
            else if (!strcmp(s, "float")) r = 'F'; else if (!strcmp(s, "double")) r = 'D';
            else if (!strcmp(s, "void")) r = 'V';
            env->ReleaseStringUTFChars(nm, s);
        }
        if (nm) env->DeleteLocalRef(nm);
    }
    env->DeleteLocalRef(cClass);
    return r;
}

extern "C" const char *adh_compute_shorty(JNIEnv *env, jobject method) {
    static thread_local std::string shorty;
    shorty.clear();
    jclass cMethod = env->FindClass("java/lang/reflect/Method");
    jclass cExec = env->FindClass("java/lang/reflect/Executable");
    char rc = 'V';                                   // constructors: void return
    if (env->IsInstanceOf(method, cMethod)) {
        jmethodID getRet = env->GetMethodID(cMethod, "getReturnType", "()Ljava/lang/Class;");
        jobject rt = env->CallObjectMethod(method, getRet);
        if (rt) {
            rc = adh_shorty_char(env, (jclass)rt);
            env->DeleteLocalRef(rt);
        }
    }
    shorty.push_back(rc);
    jmethodID getParams = env->GetMethodID(cExec, "getParameterTypes", "()[Ljava/lang/Class;");
    jobjectArray params = (jobjectArray)env->CallObjectMethod(method, getParams);
    jsize n = params ? env->GetArrayLength(params) : 0;
    for (jsize i = 0; i < n; i++) {
        jobject p = env->GetObjectArrayElement(params, i);
        if (p) {
            shorty.push_back(adh_shorty_char(env, (jclass)p));
            env->DeleteLocalRef(p);
        }
    }
    if (params) env->DeleteLocalRef(params);
    env->DeleteLocalRef(cMethod);
    env->DeleteLocalRef(cExec);
    LLOGI("computed shorty via reflection: \"%s\"", shorty.c_str());
    return shorty.c_str();
}

// ---- embedded bridge dex loader + multi-hook registry ---------------------------------
#define ADH_JAVA_MAX_HOOKS ADH_JAVA_HOOK_MAX   // shared with agent_main.c through the header

struct JavaHookContext {
    int id;
    int active;                 // 0 free, 1 active, 2 reserved
    int used;                   // retired slots are never reused
    int patched;                // LSPlant hook remains installed (soft unhook / reuse)
    jobject target_method;      // global ref to java.lang.reflect.Method
    jobject backup_method;      // global ref returned by LSPlant
    jobject bridge;             // global ref to AdhJavaHookBridge
    bool is_static;
    bool is_ctor;                 // constructor hook (args[0] is the new object)
    std::string target_name;
};

static JavaHookContext g_java_hooks[ADH_JAVA_MAX_HOOKS];
static pthread_mutex_t g_java_hooks_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_next_java_hook_id = 1;

static jclass g_bridge_class = nullptr;
static jobject g_bridge_loader = nullptr;
static void *g_bridge_dex_mem = nullptr;
static jfieldID g_bridge_backup = nullptr;
static jfieldID g_bridge_is_static = nullptr;
static jfieldID g_bridge_is_ctor = nullptr;
static jfieldID g_bridge_capture_stack = nullptr;
static jfieldID g_bridge_last_stack = nullptr;
static jfieldID g_bridge_hook_id = nullptr;
static jfieldID g_bridge_hits = nullptr;
static jfieldID g_bridge_last_arg = nullptr;
static jfieldID g_bridge_last_return = nullptr;
static jfieldID g_bridge_last_error = nullptr;
static jfieldID g_bridge_target = nullptr;
static jfieldID g_bridge_skip_original = nullptr;
static jfieldID g_bridge_override_return = nullptr;
static jfieldID g_bridge_ready = nullptr;
static jfieldID g_bridge_active = nullptr;static jfieldID g_bridge_arg_index = nullptr;
static jfieldID g_bridge_arg_value = nullptr;

static std::string jstring_to_utf(JNIEnv *env, jstring value) {
    if (!env || !value) return "";
    const char *chars = env->GetStringUTFChars(value, nullptr);
    std::string out = chars ? chars : "";
    if (chars) env->ReleaseStringUTFChars(value, chars);
    if (adh_jni_exception_check(env)) {
        adh_jni_exception_clear(env);
        return "";
    }
    return out;
}

static void JNICALL adh_java_hook_native_report(JNIEnv *env, jclass, jint hook_id,
                                                jstring target, jstring arg,
                                                jstring result, jstring error,
                                                jstring stack) {
    std::string target_s = json_escape(jstring_to_utf(env, target));
    std::string arg_s = json_escape(jstring_to_utf(env, arg));
    std::string result_s = json_escape(jstring_to_utf(env, result));
    std::string error_s = json_escape(jstring_to_utf(env, error));
    std::string stack_raw = jstring_to_utf(env, stack);
    // The Java side already bounds the chain; cap again so one long class name cannot bloat the
    // capture ring, and only emit the field when there IS a chain (opt-in per hook).
    if (stack_raw.size() > 700) stack_raw = stack_raw.substr(0, 700) + "...";
    std::string stack_s = json_escape(stack_raw);
    std::string json = "{\"hookId\":" + std::to_string((int)hook_id) +
                       ",\"target\":\"" + target_s + "\"" +
                       ",\"arg\":\"" + arg_s + "\"" +
                       ",\"ret\":\"" + result_s + "\"" +
                       ",\"error\":\"" + error_s + "\"";
    if (!stack_s.empty()) json += ",\"stack\":\"" + stack_s + "\"";
    json += "}";
    adh_capture_push_text("JAVA_HOOK", json.c_str());
}

static std::string pending_exception_text(JNIEnv *env) {
    if (!env || !adh_jni_exception_check(env)) return "";
    jthrowable throwable = env->ExceptionOccurred();
    adh_jni_exception_clear(env);
    if (!throwable) return "unknown Java exception";
    jclass throwable_class = env->FindClass("java/lang/Throwable");
    jmethodID to_string = throwable_class ? env->GetMethodID(throwable_class, "toString", "()Ljava/lang/String;") : nullptr;
    jstring text = to_string ? (jstring)env->CallObjectMethod(throwable, to_string) : nullptr;
    std::string result = text ? jstring_to_utf(env, text) : std::string();
    if (text) env->DeleteLocalRef(text);
    env->DeleteLocalRef(throwable);
    return result.empty() ? "unknown Java exception" : result;
}
static jclass load_bridge_class(JNIEnv *env, std::string &error) {
    if (g_bridge_class) return g_bridge_class;

    jobject app_loader = adh_jni_app_class_loader(env);
    if (!app_loader) {
        error = "no app ClassLoader available for Java hook bridge";
        return nullptr;
    }

    // A real DexClassLoader with a persistent dex path is visible to LSPlant's generated
    // child loader. Anonymous in-memory DexFile classes were not resolvable by name in the
    // generated class on ColorOS, so materialize the tiny bridge dex in the app code cache.
    jclass activity_thread_class = env->FindClass("android/app/ActivityThread");
    jmethodID current_application = activity_thread_class ? env->GetStaticMethodID(
        activity_thread_class, "currentApplication", "()Landroid/app/Application;") : nullptr;
    jobject app = current_application ? env->CallStaticObjectMethod(activity_thread_class, current_application) : nullptr;
    jclass context_class = env->FindClass("android/content/Context");
    jmethodID get_code_cache_dir = context_class ? env->GetMethodID(
        context_class, "getCodeCacheDir", "()Ljava/io/File;") : nullptr;
    jobject code_cache_dir = (app && get_code_cache_dir) ? env->CallObjectMethod(app, get_code_cache_dir) : nullptr;
    jclass file_class = env->FindClass("java/io/File");
    jmethodID get_absolute_path = file_class ? env->GetMethodID(file_class, "getAbsolutePath", "()Ljava/lang/String;") : nullptr;
    jstring dir_path_j = (code_cache_dir && get_absolute_path) ? (jstring)env->CallObjectMethod(code_cache_dir, get_absolute_path) : nullptr;
    std::string code_cache_dir_path = jstring_to_utf(env, dir_path_j);
    if (code_cache_dir_path.empty()) {
        std::string detail = pending_exception_text(env);
        error = "cannot resolve app code cache directory" + (detail.empty() ? std::string() : ": " + detail);
        return nullptr;
    }
    std::string bridge_dex_path = code_cache_dir_path + "/adh_bridge.dex";
    int dex_fd = open(bridge_dex_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (dex_fd < 0) {
        // A previous run deliberately made this file read-only for Android 14+ dex loading.
        chmod(bridge_dex_path.c_str(), 0600);
        dex_fd = open(bridge_dex_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    }
    if (dex_fd < 0 ||
        write(dex_fd, ADH_JAVA_HOOK_BRIDGE_DEX, ADH_JAVA_HOOK_BRIDGE_DEX_SIZE) != (ssize_t)ADH_JAVA_HOOK_BRIDGE_DEX_SIZE) {
        if (dex_fd >= 0) close(dex_fd);
        error = "failed to write embedded bridge dex to app code cache";
        return nullptr;
    }
    // Since Android 14, DexClassLoader rejects writable dex paths. Materialize read-only,
    // then flip back to writable first if this code path runs again in a later process.
    if (fchmod(dex_fd, 0400) != 0) {
        close(dex_fd);
        error = "failed to mark bridge dex read-only";
        return nullptr;
    }
    close(dex_fd);

    jclass dex_loader_class = env->FindClass("dalvik/system/DexClassLoader");
    if (!dex_loader_class) {
        error = "cannot find dalvik.system.DexClassLoader: " + pending_exception_text(env);
        return nullptr;
    }
    jmethodID dex_loader_ctor = env->GetMethodID(
        dex_loader_class, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    if (!dex_loader_ctor) {
        error = "cannot find DexClassLoader constructor: " + pending_exception_text(env);
        return nullptr;
    }
    jstring bridge_dex_path_j = env->NewStringUTF(bridge_dex_path.c_str());
    jstring code_cache_dir_path_j = env->NewStringUTF(code_cache_dir_path.c_str());
    jobject bridge_loader = env->NewObject(
        dex_loader_class, dex_loader_ctor,
        bridge_dex_path_j, code_cache_dir_path_j, nullptr, app_loader);
    if (adh_jni_exception_check(env)) {
        error = "failed to create bridge DexClassLoader: " + pending_exception_text(env);
        return nullptr;
    }
    if (!bridge_loader) {
        error = "failed to create bridge DexClassLoader: unknown failure";
        return nullptr;
    }
    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID load_class = class_loader_class ? env->GetMethodID(
        class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
    jstring class_name = env->NewStringUTF("com.adh.agent.AdhJavaHookBridge");
    jclass bridge_class = load_class ? (jclass)env->CallObjectMethod(bridge_loader, load_class, class_name) : nullptr;
    if (!bridge_class) {
        std::string detail = pending_exception_text(env);
        error = "failed to load AdhJavaHookBridge from code-cache dex" + (detail.empty() ? std::string() : ": " + detail);
        return nullptr;
    }
    {
        jclass class_class = env->FindClass("java/lang/Class");
        jmethodID get_loader = env->GetMethodID(class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
        jobject actual_loader = get_loader ? env->CallObjectMethod(bridge_class, get_loader) : nullptr;
        jclass object_class = env->FindClass("java/lang/Object");
        jmethodID to_string = env->GetMethodID(object_class, "toString", "()Ljava/lang/String;");
        jstring loader_text = (actual_loader && to_string) ? (jstring)env->CallObjectMethod(actual_loader, to_string) : nullptr;
        const char *loader_chars = loader_text ? env->GetStringUTFChars(loader_text, nullptr) : nullptr;
        LLOGI("bridge classloader=%s", loader_chars ? loader_chars : "(none)");
        if (loader_chars) env->ReleaseStringUTFChars(loader_text, loader_chars);
        if (loader_text) env->DeleteLocalRef(loader_text);
        if (actual_loader) {
            jclass loader_class = env->FindClass("java/lang/ClassLoader");
            jmethodID load_class = env->GetMethodID(loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
            jstring bridge_name = env->NewStringUTF("com.adh.agent.AdhJavaHookBridge");
            jobject found = load_class ? env->CallObjectMethod(actual_loader, load_class, bridge_name) : nullptr;
            LLOGI("bridge self-resolve=%s", found ? "ok" : "FAIL");
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            if (found) env->DeleteLocalRef(found);
            env->DeleteLocalRef(bridge_name);
        }
    }

    JNINativeMethod report = {
        const_cast<char *>("nativeReport"),
        const_cast<char *>("(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"),
        reinterpret_cast<void *>(adh_java_hook_native_report),
    };
    if (env->RegisterNatives(bridge_class, &report, 1) != JNI_OK) {
        error = "failed to register AdhJavaHookBridge.nativeReport";
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return nullptr;
    }

    g_bridge_backup = env->GetFieldID(bridge_class, "backup", "Ljava/lang/reflect/Method;");
    g_bridge_is_static = env->GetFieldID(bridge_class, "isStatic", "Z");
    g_bridge_is_ctor = env->GetFieldID(bridge_class, "isConstructor", "Z");
    g_bridge_hook_id = env->GetFieldID(bridge_class, "hookId", "I");
    g_bridge_hits = env->GetFieldID(bridge_class, "hits", "I");
    g_bridge_last_arg = env->GetFieldID(bridge_class, "lastArg", "Ljava/lang/String;");
    g_bridge_last_return = env->GetFieldID(bridge_class, "lastReturn", "Ljava/lang/String;");
    g_bridge_last_error = env->GetFieldID(bridge_class, "lastError", "Ljava/lang/String;");
    g_bridge_capture_stack = env->GetFieldID(bridge_class, "captureStack", "Z");
    g_bridge_last_stack = env->GetFieldID(bridge_class, "lastStack", "Ljava/lang/String;");
    g_bridge_target = env->GetFieldID(bridge_class, "target", "Ljava/lang/String;");
    g_bridge_skip_original = env->GetFieldID(bridge_class, "skipOriginal", "Z");
    g_bridge_override_return = env->GetFieldID(bridge_class, "overrideReturn", "Ljava/lang/String;");
    g_bridge_ready = env->GetFieldID(bridge_class, "ready", "Z");
    g_bridge_active = env->GetFieldID(bridge_class, "active", "Z");    g_bridge_arg_index = env->GetFieldID(bridge_class, "argIndex", "I");
    g_bridge_arg_value = env->GetFieldID(bridge_class, "argValue", "Ljava/lang/String;");
    g_bridge_class = (jclass)env->NewGlobalRef(bridge_class);
    g_bridge_loader = env->NewGlobalRef(bridge_loader);

    if (!g_bridge_class || !g_bridge_backup || !g_bridge_is_static || !g_bridge_is_ctor || !g_bridge_hook_id ||
        !g_bridge_hits || !g_bridge_last_arg || !g_bridge_last_return || !g_bridge_last_error ||
        !g_bridge_capture_stack || !g_bridge_last_stack ||
        !g_bridge_target || !g_bridge_skip_original || !g_bridge_override_return || !g_bridge_arg_index || !g_bridge_arg_value || !g_bridge_ready || !g_bridge_active) {
        error = "AdhJavaHookBridge fields are missing";
        return nullptr;
    }
    LLOGI("loaded embedded AdhJavaHookBridge with native event reporting");
    return g_bridge_class;
}

static jobject create_bridge_object(JNIEnv *env, int hook_id, std::string &error) {
    jclass bridge_class = load_bridge_class(env, error);
    if (!bridge_class) return nullptr;
    jmethodID ctor = env->GetMethodID(bridge_class, "<init>", "()V");
    jobject local = ctor ? env->NewObject(bridge_class, ctor) : nullptr;
    if (!local) {
        error = "failed to create AdhJavaHookBridge instance";
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return nullptr;
    }
    env->SetIntField(local, g_bridge_hook_id, hook_id);
    jobject global = env->NewGlobalRef(local);
    env->DeleteLocalRef(local);
    if (!global) {
        error = "failed to retain AdhJavaHookBridge instance";
        return nullptr;
    }
    return global;
}

// ---- target lookup / multi-hook state --------------------------------------------------
static jclass load_app_class(JNIEnv *env, const std::string &class_name, std::string &error) {
    jobject loader = adh_jni_app_class_loader(env);
    if (!loader) {
        error = "no app ClassLoader available";
        return nullptr;
    }
    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID load_class = env->GetMethodID(class_loader_class, "loadClass",
                                            "(Ljava/lang/String;)Ljava/lang/Class;");
    std::string dot_name = class_name;
    for (char &c : dot_name) if (c == '/') c = '.';
    jstring name = env->NewStringUTF(dot_name.c_str());
    jclass target_class = load_class ? (jclass)env->CallObjectMethod(loader, load_class, name) : nullptr;
    if (!target_class) {
        error = "target class not found: " + dot_name;
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return nullptr;
    }
    return target_class;
}

static bool method_is_static(JNIEnv *env, jobject method, bool &is_static, std::string &error) {
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jclass modifier_class = env->FindClass("java/lang/reflect/Modifier");
    jmethodID get_modifiers = env->GetMethodID(method_class, "getModifiers", "()I");
    jmethodID is_static_method = env->GetStaticMethodID(modifier_class, "isStatic", "(I)Z");
    if (!get_modifiers || !is_static_method) {
        error = "failed to inspect target method modifiers";
        return false;
    }
    jint modifiers = env->CallIntMethod(method, get_modifiers);
    is_static = env->CallStaticBooleanMethod(modifier_class, is_static_method, modifiers) == JNI_TRUE;
    return true;
}

// Scan one class's declared members for an exact (name, parameter-types) match. `member_get_name`
// is null for constructors (their "name" is the class and cannot distinguish overloads), and
// `wanted_name` is the requested method name. The name check is mandatory: matching on parameter
// types alone would happily hook a same-arity sibling method.
static jobject scan_declared_members(JNIEnv *env, jclass cls, jmethodID collect, jmethodID get_params,
                                     jmethodID member_get_name, const char *wanted_name,
                                     jmethodID class_get_name, jmethodID set_accessible,
                                     const std::vector<std::string> &wanted, int *matches) {
    jobjectArray members = (jobjectArray)env->CallObjectMethod(cls, collect);
    if (!members) { if (adh_jni_exception_check(env)) adh_jni_exception_clear(env); return nullptr; }
    jobject found = nullptr;
    jsize count = env->GetArrayLength(members);
    for (jsize i = 0; i < count; i++) {
        jobject member = env->GetObjectArrayElement(members, i);
        if (!member) continue;
        if (member_get_name) {
            jstring jname = (jstring)env->CallObjectMethod(member, member_get_name);
            const char *chars = jname ? env->GetStringUTFChars(jname, nullptr) : nullptr;
            bool name_ok = chars && wanted_name && strcmp(chars, wanted_name) == 0;
            if (chars) env->ReleaseStringUTFChars(jname, chars);
            if (jname) env->DeleteLocalRef(jname);
            if (!name_ok) { env->DeleteLocalRef(member); continue; }
        }
        jobjectArray parameter_types = (jobjectArray)env->CallObjectMethod(member, get_params);
        jsize parameter_count = parameter_types ? env->GetArrayLength(parameter_types) : 0;
        bool params_ok = parameter_count == (jsize)wanted.size();
        for (jsize j = 0; params_ok && j < parameter_count; j++) {
            jclass parameter_class = (jclass)env->GetObjectArrayElement(parameter_types, j);
            jstring parameter_name = parameter_class ? (jstring)env->CallObjectMethod(parameter_class, class_get_name) : nullptr;
            const char *parameter_chars = parameter_name ? env->GetStringUTFChars(parameter_name, nullptr) : nullptr;
            std::string actual = parameter_chars ? parameter_chars : "";
            if (parameter_chars) env->ReleaseStringUTFChars(parameter_name, parameter_chars);
            if (parameter_name) env->DeleteLocalRef(parameter_name);
            if (parameter_class) env->DeleteLocalRef(parameter_class);
            if (normalize_type(actual) != wanted[(size_t)j]) params_ok = false;
        }
        if (parameter_types) env->DeleteLocalRef(parameter_types);
        if (params_ok) {
            if (set_accessible) env->CallVoidMethod(member, set_accessible, JNI_TRUE);
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            if (!found) found = (jobject)env->NewLocalRef(member);
            (*matches)++;
        }
        env->DeleteLocalRef(member);
    }
    env->DeleteLocalRef(members);
    return found;
}
static jobject find_target_method(JNIEnv *env, jclass target_class, const std::string &class_name,
                                  const std::string &method_name, const std::string &params,
                                  std::string &signature, std::string &error) {
    std::vector<std::string> wanted = split_params(params);
    const bool want_ctor = method_name == "<init>" || method_name == "constructor";
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared_methods = env->GetMethodID(class_class, "getDeclaredMethods",
                                                      "()[Ljava/lang/reflect/Method;");
    jmethodID get_declared_ctors = env->GetMethodID(class_class, "getDeclaredConstructors",
                                                    "()[Ljava/lang/reflect/Constructor;");
    jmethodID get_super = env->GetMethodID(class_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID method_get_params = env->GetMethodID(method_class, "getParameterTypes",
                                                   "()[Ljava/lang/Class;");
    jmethodID method_get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID method_set_accessible = env->GetMethodID(method_class, "setAccessible", "(Z)V");
    jclass ctor_class = env->FindClass("java/lang/reflect/Constructor");
    jmethodID ctor_get_params = env->GetMethodID(ctor_class, "getParameterTypes",
                                                 "()[Ljava/lang/Class;");
    jmethodID ctor_set_accessible = env->GetMethodID(ctor_class, "setAccessible", "(Z)V");
    if (!get_declared_methods || !get_declared_ctors || !get_super || !get_name ||
        !method_get_params || !method_get_name || !ctor_get_params) {
        error = "reflection methods unavailable";
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return nullptr;
    }

    jobject found = nullptr;
    int matches = 0;
    std::string declaring = class_name;
    if (want_ctor) {
        found = scan_declared_members(env, target_class, get_declared_ctors, ctor_get_params,
                                      nullptr, nullptr, get_name, ctor_set_accessible, wanted, &matches);
    } else {
        jclass cursor = (jclass)env->NewLocalRef(target_class);
        for (int depth = 0; cursor && depth < 10 && !found; depth++) {
            found = scan_declared_members(env, cursor, get_declared_methods, method_get_params,
                                          method_get_name, method_name.c_str(), get_name,
                                          method_set_accessible, wanted, &matches);
            if (found) {
                jstring jname = (jstring)env->CallObjectMethod(cursor, get_name);
                const char *chars = jname ? env->GetStringUTFChars(jname, nullptr) : nullptr;
                if (chars) { declaring = chars; env->ReleaseStringUTFChars(jname, chars); }
                if (jname) env->DeleteLocalRef(jname);
                break;
            }
            jclass parent = (jclass)env->CallObjectMethod(cursor, get_super);
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            env->DeleteLocalRef(cursor);
            cursor = parent;
        }
        if (cursor && !found) env->DeleteLocalRef(cursor);
    }

    if (!found) {
        error = std::string(want_ctor ? "target constructor not found: " : "target method not found: ") +
                class_name + "." + method_name + "(" + params + ")";
        return nullptr;
    }
    if (matches > 1) {
        env->DeleteLocalRef(found);
        error = "ambiguous target (multiple overloads): " + class_name + "." + method_name;
        return nullptr;
    }
    signature = declaring + "." + (want_ctor ? std::string("<init>") : method_name) + "(" + params + ")";
    return found;
}
// Collect EVERY method of the class (declared + superclass chain) that matches an optional name and an
// optional exact parameter list. "*" or an empty list means "any". Used by hook-all, where the point
// is to stop hand-enumerating overloads before installing - the Frida `overloads.forEach(hook)`
// workflow. Slots are bounded by the caller; the local-ref count stays well under the 512 limit.
// Hard ceiling for COLLECTION (a JNI local-ref budget, not the install limit): the install limit is
// applied later and must never shrink the reported match count - a caller asking for limit=3 out of
// 30 matches has to see matched=30, otherwise the truncation is invisible.
#define ADH_JAVA_COLLECT_MAX 64
static int collect_target_methods(JNIEnv *env, jclass target_class, const std::string &method_name,
                                  const std::string &params, int cap, std::vector<jobject> &out,
                                  std::string &error) {
    const bool any_name = method_name.empty();
    const bool want_ctor = method_name == "<init>" || method_name == "constructor";
    const bool any_params = params.empty() || params == "*";
    std::vector<std::string> wanted = any_params ? std::vector<std::string>() : split_params(params);

    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared_methods = env->GetMethodID(class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    jmethodID get_declared_ctors = env->GetMethodID(class_class, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;");
    jmethodID get_super = env->GetMethodID(class_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    jclass member_class = env->FindClass(want_ctor ? "java/lang/reflect/Constructor" : "java/lang/reflect/Method");
    jmethodID member_get_params = member_class ? env->GetMethodID(member_class, "getParameterTypes", "()[Ljava/lang/Class;") : nullptr;
    jmethodID member_get_name = want_ctor || !member_class ? nullptr : env->GetMethodID(member_class, "getName", "()Ljava/lang/String;");
    jmethodID member_set_accessible = member_class ? env->GetMethodID(member_class, "setAccessible", "(Z)V") : nullptr;
    if (!get_declared_methods || !get_declared_ctors || !get_super || !get_name || !member_get_params || !member_set_accessible) {
        error = "reflection methods unavailable";
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return 0;
    }

    std::vector<std::string> seen;
    jclass cursor = (jclass)env->NewLocalRef(target_class);
    for (int depth = 0; cursor && depth < 10 && (int)out.size() < cap; depth++) {
        jobjectArray members = (jobjectArray)env->CallObjectMethod(cursor, want_ctor ? get_declared_ctors : get_declared_methods);
        if (members) {
            jsize count = env->GetArrayLength(members);
            for (jsize i = 0; i < count && (int)out.size() < cap; i++) {
                jobject member = env->GetObjectArrayElement(members, i);
                if (!member) continue;
                bool keep = true;
                std::string member_name = want_ctor ? "<init>" : "";
                if (!want_ctor && member_get_name) {
                    jstring jname = (jstring)env->CallObjectMethod(member, member_get_name);
                    member_name = jstring_to_utf(env, jname);
                    if (jname) env->DeleteLocalRef(jname);
                    if (!any_name) keep = method_name == member_name;
                }
                jobjectArray parameter_types = keep ? (jobjectArray)env->CallObjectMethod(member, member_get_params) : nullptr;
                jsize parameter_count = parameter_types ? env->GetArrayLength(parameter_types) : 0;
                std::string signature_key;
                bool params_ok = keep && (any_params || parameter_count == (jsize)wanted.size());
                for (jsize j = 0; params_ok && j < parameter_count; j++) {
                    jclass parameter_class = (jclass)env->GetObjectArrayElement(parameter_types, j);
                    jstring parameter_name = parameter_class ? (jstring)env->CallObjectMethod(parameter_class, get_name) : nullptr;
                    const char *parameter_chars = parameter_name ? env->GetStringUTFChars(parameter_name, nullptr) : nullptr;
                    std::string actual = parameter_chars ? parameter_chars : "";
                    if (parameter_chars) env->ReleaseStringUTFChars(parameter_name, parameter_chars);
                    if (parameter_name) env->DeleteLocalRef(parameter_name);
                    if (parameter_class) env->DeleteLocalRef(parameter_class);
                    if (!any_params && normalize_type(actual) != wanted[(size_t)j]) params_ok = false;
                    if (params_ok) { if (!signature_key.empty()) signature_key += ","; signature_key += actual; }
                }
                if (parameter_types) env->DeleteLocalRef(parameter_types);
                if (params_ok) {
                    // Key on (name, params): a class-wide scan sees foo(int) and bar(int), which must
                    // both be collected - keying on params alone silently dropped one of them.
                    std::string dedupe_key = member_name + "(" + signature_key + ")";
                    bool duplicate = false;
                    for (const std::string &s : seen) if (s == dedupe_key) { duplicate = true; break; }
                    if (!duplicate) {
                        env->CallVoidMethod(member, member_set_accessible, JNI_TRUE);
                        if (adh_jni_exception_check(env)) {
                            // Not fatal (the install path may still succeed for public members), but it
                            // must be visible: silently clearing it turned a permission problem into a
                            // mysterious install failure later.
                            LLOGI("WARN hook_all: setAccessible failed for %s (member kept; install may fail)", dedupe_key.c_str());
                            adh_jni_exception_clear(env);
                        }
                        seen.push_back(dedupe_key);
                        out.push_back((jobject)env->NewLocalRef(member));
                    }
                }
                env->DeleteLocalRef(member);
            }
            env->DeleteLocalRef(members);
        } else if (adh_jni_exception_check(env)) {
            adh_jni_exception_clear(env);
        }
        jclass parent = (jclass)env->CallObjectMethod(cursor, get_super);
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        env->DeleteLocalRef(cursor);
        cursor = parent;
    }
    if (cursor) env->DeleteLocalRef(cursor);
    // Count everything that WOULD match, so matched is honest even when we stop collecting at the
    // local-ref budget; the caller decides how many of them to install.
    return (int)out.size();
}

static int find_free_hook_slot_locked() {
    for (int i = 0; i < ADH_JAVA_MAX_HOOKS; i++) {
        if (g_java_hooks[i].active == 0 && !g_java_hooks[i].used) return i;
    }
    return -1;
}

static int find_hook_slot_locked(int id) {
    for (int i = 0; i < ADH_JAVA_MAX_HOOKS; i++) {
        if (g_java_hooks[i].active == 1 && g_java_hooks[i].id == id) return i;
    }
    return -1;
}

static void reset_hook_slot(JavaHookContext &hook) {
    hook.id = 0;
    hook.active = 0;
    hook.used = 0;
    hook.patched = 0;
    hook.target_method = nullptr;
    hook.backup_method = nullptr;
    hook.bridge = nullptr;
    hook.is_static = false;
    hook.target_name.clear();
}

static void release_hook_slot(JNIEnv *env, JavaHookContext &hook) {
    if (hook.bridge && g_bridge_backup) env->SetObjectField(hook.bridge, g_bridge_backup, nullptr);
    if (hook.backup_method) env->DeleteGlobalRef(hook.backup_method);
    if (hook.target_method) env->DeleteGlobalRef(hook.target_method);
    if (hook.bridge) env->DeleteGlobalRef(hook.bridge);
    reset_hook_slot(hook);
}

extern "C" int adh_javahook_hook_method(JNIEnv *env, const char *class_name, const char *method_name,
                                         const char *params, int skip_original, const char *override_return,
                                         int arg_index, const char *arg_value, int capture_stack,
                                         int *hook_id_out, char *error, size_t error_size) {
    if (hook_id_out) *hook_id_out = 0;
    if (!env || !class_name || !method_name) {
        set_error(error, error_size, "missing class/method");
        return 0;
    }
    if (!adh_javahook_init(env)) {
        set_error(error, error_size, "%s", adh_javahook_last_error());
        return 0;
    }

    std::string problem;
    int slot = -1;
    int hook_id = 0;
    pthread_mutex_lock(&g_java_hooks_lock);
    slot = find_free_hook_slot_locked();
    if (slot >= 0) {
        hook_id = g_next_java_hook_id++;
        if (g_next_java_hook_id <= 0) g_next_java_hook_id = 1;
        g_java_hooks[slot].active = 2;      // reserve while resolving/installing
        g_java_hooks[slot].id = hook_id;
    }
    pthread_mutex_unlock(&g_java_hooks_lock);
    if (slot < 0) {
        set_error(error, error_size, "too many active Java hooks (max %d)", ADH_JAVA_MAX_HOOKS);
        return 0;
    }

    auto fail_hook = [&](const char *message) -> int {
        pthread_mutex_lock(&g_java_hooks_lock);
        if (g_java_hooks[slot].active == 2) reset_hook_slot(g_java_hooks[slot]);
        pthread_mutex_unlock(&g_java_hooks_lock);
        set_error(error, error_size, "%s", message);
        return 0;
    };

    jclass target_class = load_app_class(env, class_name, problem);
    if (!target_class) return fail_hook(problem.c_str());
    std::string signature;
    jobject target = find_target_method(env, target_class, class_name, method_name, params ? params : "", signature, problem);
    env->DeleteLocalRef(target_class);
    if (!target) return fail_hook(problem.c_str());

    const bool is_ctor = strcmp(method_name, "<init>") == 0 || strcmp(method_name, "constructor") == 0;
    if (is_ctor && (skip_original || (override_return && override_return[0]))) {
        env->DeleteLocalRef(target);
        return fail_hook("constructor hooks cannot skip the original or override the return value");
    }
    bool is_static = false;
    if (!is_ctor && !method_is_static(env, target, is_static, problem)) {
        env->DeleteLocalRef(target);
        return fail_hook(problem.c_str());
    }

    // Reactivate an already soft-unhooked LSPlant hook on the same signature instead of
    // calling lsplant::Hook again (which cannot safely re-hook a patched method).
    pthread_mutex_lock(&g_java_hooks_lock);
    for (int i = 0; i < ADH_JAVA_MAX_HOOKS; i++) {
        JavaHookContext &old = g_java_hooks[i];
        if (i == slot || !old.patched || old.active != 0 || !old.bridge ||
            old.target_name != signature) continue;
        jobject old_bridge = old.bridge;
        jstring empty = env->NewStringUTF("");
        env->SetIntField(old_bridge, g_bridge_hook_id, hook_id);
        env->SetIntField(old_bridge, g_bridge_hits, 0);
        env->SetObjectField(old_bridge, g_bridge_last_arg, empty);
        env->SetObjectField(old_bridge, g_bridge_last_return, empty);
        env->SetObjectField(old_bridge, g_bridge_last_error, empty);
        jstring target_string = env->NewStringUTF(signature.c_str());
        env->SetObjectField(old_bridge, g_bridge_target, target_string);
        env->SetBooleanField(old_bridge, g_bridge_is_static, is_static ? JNI_TRUE : JNI_FALSE);
        env->SetBooleanField(old_bridge, g_bridge_is_ctor, is_ctor ? JNI_TRUE : JNI_FALSE);
        env->SetBooleanField(old_bridge, g_bridge_skip_original, skip_original ? JNI_TRUE : JNI_FALSE);
        jstring override_string = env->NewStringUTF(override_return ? override_return : "");
        env->SetObjectField(old_bridge, g_bridge_override_return, override_string);
        env->SetIntField(old_bridge, g_bridge_arg_index, arg_index);
        jstring arg_value_string = env->NewStringUTF(arg_value ? arg_value : "");
        env->SetObjectField(old_bridge, g_bridge_arg_value, arg_value_string);
        env->SetBooleanField(old_bridge, g_bridge_capture_stack, capture_stack ? JNI_TRUE : JNI_FALSE);
        env->SetBooleanField(old_bridge, g_bridge_ready, JNI_TRUE);
        env->SetBooleanField(old_bridge, g_bridge_active, JNI_TRUE);
        if (empty) env->DeleteLocalRef(empty);
        if (target_string) env->DeleteLocalRef(target_string);
        if (override_string) env->DeleteLocalRef(override_string);
        if (arg_value_string) env->DeleteLocalRef(arg_value_string);

        old.id = hook_id;
        old.active = 1;
        old.used = 1;
        old.patched = 1;
        old.is_static = is_static;
        reset_hook_slot(g_java_hooks[slot]);   // release the newly reserved spare slot
        pthread_mutex_unlock(&g_java_hooks_lock);
        if (hook_id_out) *hook_id_out = hook_id;
        LLOGI("java_hook reactivated id=%d target=%s", hook_id, signature.c_str());
        return 1;
    }
    pthread_mutex_unlock(&g_java_hooks_lock);
    jobject bridge = create_bridge_object(env, hook_id, problem);
    if (!bridge) {
        env->DeleteLocalRef(target);
        return fail_hook(problem.c_str());
    }

    jstring empty = env->NewStringUTF("");
    env->SetIntField(bridge, g_bridge_hits, 0);
    env->SetObjectField(bridge, g_bridge_last_arg, empty);
    env->SetObjectField(bridge, g_bridge_last_return, empty);
    env->SetObjectField(bridge, g_bridge_last_error, empty);
    jstring target_string = env->NewStringUTF(signature.c_str());
    env->SetObjectField(bridge, g_bridge_target, target_string);
    env->SetBooleanField(bridge, g_bridge_is_static, is_static ? JNI_TRUE : JNI_FALSE);
    env->SetBooleanField(bridge, g_bridge_is_ctor, is_ctor ? JNI_TRUE : JNI_FALSE);
    env->SetObjectField(bridge, g_bridge_backup, nullptr);
    env->SetBooleanField(bridge, g_bridge_active, JNI_FALSE);
    env->SetBooleanField(bridge, g_bridge_skip_original, skip_original ? JNI_TRUE : JNI_FALSE);
    jstring override_string = env->NewStringUTF(override_return ? override_return : "");
    env->SetObjectField(bridge, g_bridge_override_return, override_string);
    if (override_string) env->DeleteLocalRef(override_string);    env->SetIntField(bridge, g_bridge_arg_index, arg_index);
    jstring arg_value_string = env->NewStringUTF(arg_value ? arg_value : "");
    env->SetObjectField(bridge, g_bridge_arg_value, arg_value_string);
    if (arg_value_string) env->DeleteLocalRef(arg_value_string);
    env->SetBooleanField(bridge, g_bridge_capture_stack, capture_stack ? JNI_TRUE : JNI_FALSE);
    if (empty) env->SetObjectField(bridge, g_bridge_last_stack, empty);

    jmethodID callback_id = env->GetMethodID(g_bridge_class, "callback",
                                             "([Ljava/lang/Object;)Ljava/lang/Object;");
    jobject callback = callback_id ? env->ToReflectedMethod(g_bridge_class, callback_id, JNI_FALSE) : nullptr;
    if (!callback) {
        env->DeleteGlobalRef(bridge);
        env->DeleteLocalRef(target);
        return fail_hook("failed to reflect AdhJavaHookBridge.callback");
    }

    jobject backup = lsplant::Hook(env, target, bridge, callback);
    env->DeleteLocalRef(callback);
    if (!backup) {
        env->DeleteGlobalRef(bridge);
        env->DeleteLocalRef(target);
        return fail_hook("java hook backend hook failed (check logcat tag rt.java)");
    }

    // The Method returned by LSPlant is LSPlant's own global ref; UnHook deletes it. Keep
    // an ADH-owned ref for the bridge so in-flight callbacks never depend on that handle.
    jobject adh_backup = env->NewGlobalRef(backup);
    if (!adh_backup) {
        (void)lsplant::UnHook(env, target);
        env->DeleteLocalRef(target);
        env->DeleteGlobalRef(bridge);
        return fail_hook("failed to retain hook backup global reference");
    }
    env->SetObjectField(bridge, g_bridge_backup, adh_backup);
    env->SetBooleanField(bridge, g_bridge_ready, JNI_TRUE);
    env->SetBooleanField(bridge, g_bridge_active, JNI_TRUE);

    jobject target_global = env->NewGlobalRef(target);
    if (!target_global) {
        (void)lsplant::UnHook(env, target);
        env->DeleteLocalRef(target);
        return fail_hook("failed to retain target method global reference");
    }
    env->DeleteLocalRef(target);

    pthread_mutex_lock(&g_java_hooks_lock);
    JavaHookContext &ctx = g_java_hooks[slot];
    ctx.id = hook_id;
    ctx.active = 1;
    ctx.used = 1;
    ctx.target_method = target_global;
    ctx.backup_method = adh_backup;
    ctx.bridge = bridge;
    ctx.patched = 1;
    ctx.is_static = is_static;
    ctx.is_ctor = is_ctor;
    ctx.target_name = signature;
    pthread_mutex_unlock(&g_java_hooks_lock);

    if (hook_id_out) *hook_id_out = hook_id;
    LLOGI("java_hook installed id=%d target=%s", hook_id, signature.c_str());
    return 1;
}

// Hook every method of a class in one call (Frida's "hook all overloads / hook the whole class"
// workflow). Each collected method is installed through the ordinary single-method path, so all the
// existing rules apply (constructors reject skip/override, slots are bounded, failures roll back per
// method). Installs stop at the slot limit; the caller learns how many methods matched so a truncated
// result is visible instead of silently partial.
extern "C" int adh_javahook_hook_all(JNIEnv *env, const char *class_name, const char *method_name,
                                     const char *params, int skip_original, const char *override_return,
                                     int arg_index, const char *arg_value, int capture_stack,
                                     int max_hooks, int *hook_ids_out, int hook_ids_cap,
                                     int *matched_out, int *collect_capped_out, char *error, size_t error_size) {
    if (matched_out) *matched_out = 0;
    if (!env || !class_name || !class_name[0]) {
        set_error(error, error_size, "hook_all needs className");
        return 0;
    }
    if (!adh_javahook_init(env)) {
        set_error(error, error_size, "%s", adh_javahook_last_error());
        return 0;
    }
    if (matched_out) *matched_out = 0;
    if (collect_capped_out) *collect_capped_out = 0;
    if (hook_ids_cap > ADH_JAVA_MAX_HOOKS) hook_ids_cap = ADH_JAVA_MAX_HOOKS;   // never trust the caller's buffer size
    const int install_cap = max_hooks > 0 ? (max_hooks > ADH_JAVA_MAX_HOOKS ? ADH_JAVA_MAX_HOOKS : max_hooks)
                                          : ADH_JAVA_MAX_HOOKS;
    std::string problem;
    jclass target_class = load_app_class(env, class_name, problem);
    if (!target_class) {
        set_error(error, error_size, "%s", problem.c_str());
        return 0;
    }
    std::vector<jobject> methods;
    std::string collect_error;
    int matched = collect_target_methods(env, target_class, method_name ? method_name : "",
                                         params ? params : "*", ADH_JAVA_COLLECT_MAX, methods, collect_error);
    if (collect_capped_out) *collect_capped_out = matched >= ADH_JAVA_COLLECT_MAX ? 1 : 0;
    // Install at most install_cap of them; `matched` above stays the size of the match set.
    int install_count = matched < install_cap ? matched : install_cap;
    if (matched <= 0) {
        env->DeleteLocalRef(target_class);
        set_error(error, error_size, "%s",
                  collect_error.empty() ? "no method matched (name/params filter too narrow?)" : collect_error.c_str());
        return 0;
    }
    if (matched_out) *matched_out = matched;

    // Constructors are collected as java.lang.reflect.Constructor objects: the install loop must ask
    // the right reflection class for their parameter types (see below).
    const bool want_ctor = method_name && (strcmp(method_name, "<init>") == 0 || strcmp(method_name, "constructor") == 0);
    int installed = 0;
    int failed = 0;
    int first_error_kept = 0;
    char first_error[192] = "";
    for (int i = 0; i < install_count && installed < hook_ids_cap; i++) {
        jobject method = methods[(size_t)i];
        // Build the exact parameter list of THIS overload so the single-method resolver selects it
        // unambiguously, and read the real method name when the caller asked for "any name".
        std::string param_list;
        std::string actual_name = method_name ? method_name : "";
        // Constructors live in java.lang.reflect.Constructor: asking THAT object for Method.getName()
        // throws and the exception would be swallowed, leaving the name to a lucky fallback.
        const bool collecting_ctors_here = want_ctor;
        jclass method_class = env->FindClass(collecting_ctors_here ? "java/lang/reflect/Constructor" : "java/lang/reflect/Method");
        jmethodID get_params = method_class ? env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;") : nullptr;
        jmethodID get_name = (!collecting_ctors_here && method_class) ? env->GetMethodID(method_class, "getName", "()Ljava/lang/String;") : nullptr;
        jclass class_class = env->FindClass("java/lang/Class");
        jmethodID class_get_name = class_class ? env->GetMethodID(class_class, "getName", "()Ljava/lang/String;") : nullptr;
        if (actual_name.empty() && get_name) {
            jstring jname = (jstring)env->CallObjectMethod(method, get_name);
            actual_name = jstring_to_utf(env, jname);
            if (jname) env->DeleteLocalRef(jname);
        }
        jobjectArray parameter_types = get_params ? (jobjectArray)env->CallObjectMethod(method, get_params) : nullptr;
        jsize parameter_count = parameter_types ? env->GetArrayLength(parameter_types) : 0;
        for (jsize j = 0; j < parameter_count; j++) {
            jclass parameter_class = (jclass)env->GetObjectArrayElement(parameter_types, j);
            jstring parameter_name = parameter_class && class_get_name ? (jstring)env->CallObjectMethod(parameter_class, class_get_name) : nullptr;
            std::string actual = jstring_to_utf(env, parameter_name);
            if (parameter_name) env->DeleteLocalRef(parameter_name);
            if (parameter_class) env->DeleteLocalRef(parameter_class);
            if (j) param_list += ",";
            param_list += actual;
        }
        if (parameter_types) env->DeleteLocalRef(parameter_types);

        char hook_error[192] = "";
        int hook_id = 0;
        int ok = adh_javahook_hook_method(env, class_name, actual_name.c_str(), param_list.c_str(),
                                          skip_original, override_return, arg_index, arg_value,
                                          capture_stack, &hook_id, hook_error, sizeof(hook_error));
        if (ok && hook_id > 0) {
            hook_ids_out[installed++] = hook_id;
        } else {
            failed++;
            if (!first_error_kept) {
                first_error_kept = 1;
                snprintf(first_error, sizeof(first_error), "%s", hook_error[0] ? hook_error : "install failed");
            }
        }
    }
    for (jobject m : methods) env->DeleteLocalRef(m);
    env->DeleteLocalRef(target_class);
    if (installed <= 0) {
        set_error(error, error_size, "%s", first_error[0] ? first_error : "no hook could be installed (slot limit?)");
        return 0;
    }
    if (first_error_kept && error && error_size) {
        // Partial failure: the error string says what failed, and the caller also gets a `partial`
        // flag so "ok:true with some methods missing" cannot be read as a complete batch.
        snprintf(error, error_size, "partial (%d of %d failed): %s", failed, install_count, first_error);
    }
    LLOGI("java_hook_all installed=%d matched=%d class=%s", installed, matched, class_name);
    return installed;
}

extern "C" int adh_javahook_unhook_id(JNIEnv *env, int hook_id, char *error, size_t error_size) {
    if (!env) {
        set_error(error, error_size, "no JavaVM/JNIEnv available");
        return 0;
    }
    int removed = 0, failed = 0;
    pthread_mutex_lock(&g_java_hooks_lock);
    for (int i = 0; i < ADH_JAVA_MAX_HOOKS; i++) {
        JavaHookContext &hook = g_java_hooks[i];
        if (hook.active != 1 || (hook_id != 0 && hook.id != hook_id)) continue;
        if (hook.bridge && g_bridge_active) {
            // Soft-unhook: keep the LSPlant hook and all refs installed, but make the bridge
            // forward straight to the backup. This avoids LSPlant UnHook races and lets a
            // later install reactivate the same target without consuming a new slot.
            env->SetBooleanField(hook.bridge, g_bridge_active, JNI_FALSE);
            hook.active = 0;
            hook.id = 0;
            hook.patched = 1;
            removed++;
        } else {
            failed++;
        }
    }
    pthread_mutex_unlock(&g_java_hooks_lock);
    if (removed == 0 && failed == 0) {
        set_error(error, error_size, hook_id ? "no matching active Java hook" : "no active Java hooks");
        return 0;
    }
    if (failed) {
        set_error(error, error_size, "%d Java hook(s) failed to unhook", failed);
        return 0;
    }
    return 1;
}

extern "C" int adh_javahook_status_json(JNIEnv *env, char *out, size_t out_size) {
    if (!out || !out_size) return 0;
    std::string hooks = "[";
    int active_count = 0;
    int patched_count = 0;
    pthread_mutex_lock(&g_java_hooks_lock);
    for (int i = 0; i < ADH_JAVA_MAX_HOOKS; i++) {
        JavaHookContext &hook = g_java_hooks[i];
        if (hook.active != 1) { if (hook.patched) patched_count++; continue; }
        int hits = 0;
        std::string last_arg, last_return, last_error, last_stack;
        bool capture_stack = false;
        if (env && hook.bridge) {
            hits = env->GetIntField(hook.bridge, g_bridge_hits);
            last_arg = get_string_field(env, hook.bridge, g_bridge_last_arg);
            last_return = get_string_field(env, hook.bridge, g_bridge_last_return);
            last_error = get_string_field(env, hook.bridge, g_bridge_last_error);
            last_stack = get_string_field(env, hook.bridge, g_bridge_last_stack);
            capture_stack = env->GetBooleanField(hook.bridge, g_bridge_capture_stack) == JNI_TRUE;
        }
        if (active_count) hooks += ",";
        hooks += "{\"id\":" + std::to_string(hook.id) +
                 ",\"target\":\"" + json_escape(hook.target_name) + "\"" +
                 ",\"hits\":" + std::to_string(hits) +
                 ",\"lastArg\":\"" + json_escape(last_arg) + "\"" +
                 ",\"lastReturn\":\"" + json_escape(last_return) + "\"" +
                 ",\"lastError\":\"" + json_escape(last_error) + "\"" +
                 ",\"stackCapture\":" + std::string(capture_stack ? "true" : "false") +
                 ",\"lastStack\":\"" + json_escape(last_stack) + "\"}";
        active_count++;
    }
    pthread_mutex_unlock(&g_java_hooks_lock);
    hooks += "]";
    std::string json = "{\"available\":true,\"returnOverride\":true,\"argRewrite\":true,\"stackCapture\":true,"
                       "\"maxHooks\":" + std::to_string(ADH_JAVA_MAX_HOOKS) + ",\"initOk\":" + std::string(g_init_ok ? "true" : "false") +
                       ",\"backend\":\"art\",\"version\":\"v6.4\",\"active\":" +
                       std::string(active_count ? "true" : "false") +
                       ",\"count\":" + std::to_string(active_count) +
                       ",\"patched\":" + std::to_string(patched_count) +
                       ",\"hooks\":" + hooks + "}";
    snprintf(out, out_size, "%s", json.c_str());
    out[out_size - 1] = 0;
    return 1;
}
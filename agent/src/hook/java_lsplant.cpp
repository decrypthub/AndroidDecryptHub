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

#include <android/api-level.h>
#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#define LTAG "ADH_LSP"
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
    if (!env || !env->ExceptionCheck()) return false;
    env->ExceptionDescribe();
    env->ExceptionClear();
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
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
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
    };

    try {
        g_init_ok = lsplant::Init(g_init_env, info) ? 1 : 0;
    } catch (...) {
        g_init_ok = 0;
        set_init_error("LSPlant init threw a C++ exception");
    }

    if (g_init_ok) {
        g_init_error[0] = 0;
        LLOGI("lsplant::Init -> ok");
    } else {
        if (!g_init_error[0]) set_init_error("lsplant::Init returned false (check logcat tag ADH_LSP)");
        LLOGE("lsplant::Init -> FAIL: %s", g_init_error);
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

// ---- embedded bridge dex loader --------------------------------------------------------
static jclass g_bridge_class = nullptr;
static jobject g_bridge_object = nullptr;
static jfieldID g_bridge_backup = nullptr;
static jfieldID g_bridge_is_static = nullptr;
static jfieldID g_bridge_hits = nullptr;
static jfieldID g_bridge_last_arg = nullptr;
static jfieldID g_bridge_last_return = nullptr;
static jfieldID g_bridge_last_error = nullptr;
static jfieldID g_bridge_target = nullptr;
static void *g_bridge_dex_mem = nullptr;

static jclass load_bridge_class(JNIEnv *env, std::string &error) {
    if (g_bridge_class) return g_bridge_class;

    if (!g_bridge_dex_mem) {
        void *mem = mmap(nullptr, ADH_JAVA_HOOK_BRIDGE_DEX_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            error = "mmap failed for embedded Java hook bridge dex";
            return nullptr;
        }
        memcpy(mem, ADH_JAVA_HOOK_BRIDGE_DEX, ADH_JAVA_HOOK_BRIDGE_DEX_SIZE);
        if (mprotect(mem, ADH_JAVA_HOOK_BRIDGE_DEX_SIZE, PROT_READ) != 0) {
            error = "mprotect failed for embedded Java hook bridge dex";
            return nullptr;
        }
        g_bridge_dex_mem = mem;
    }

    jobject loader = adh_jni_app_class_loader(env);
    if (!loader) {
        error = "no app ClassLoader available for Java hook bridge";
        return nullptr;
    }

    jobject byte_buffer = env->NewDirectByteBuffer(g_bridge_dex_mem, (jlong)ADH_JAVA_HOOK_BRIDGE_DEX_SIZE);
    jclass dex_file_class = env->FindClass("dalvik/system/DexFile");
    if (!byte_buffer || !dex_file_class) {
        error = "failed to prepare DexFile for Java hook bridge";
        return nullptr;
    }

    jobject dex_file = nullptr;
    int api = android_get_device_api_level();
    if (api >= 29) {
        jclass byte_buffer_class = env->FindClass("java/nio/ByteBuffer");
        jobjectArray buffers = env->NewObjectArray(1, byte_buffer_class, byte_buffer);
        jmethodID ctor = env->GetMethodID(
            dex_file_class, "<init>",
            "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;[Ldalvik/system/DexPathList$Element;)V");
        if (ctor) dex_file = env->NewObject(dex_file_class, ctor, buffers, loader, (jobjectArray)nullptr);
    } else {
        jmethodID ctor = env->GetMethodID(dex_file_class, "<init>", "(Ljava/nio/ByteBuffer;)V");
        if (ctor) dex_file = env->NewObject(dex_file_class, ctor, byte_buffer);
    }
    if (!dex_file) {
        error = "failed to construct in-memory DexFile for Java hook bridge";
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }

    jmethodID load_class = env->GetMethodID(
        dex_file_class, "loadClass", "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;");
    jstring class_name = env->NewStringUTF("com.adh.agent.AdhJavaHookBridge");
    jclass bridge_class = load_class ? (jclass)env->CallObjectMethod(dex_file, load_class, class_name, loader) : nullptr;
    if (!bridge_class) {
        error = "failed to load AdhJavaHookBridge from embedded dex";
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }

    g_bridge_backup = env->GetFieldID(bridge_class, "backup", "Ljava/lang/reflect/Method;");
    g_bridge_is_static = env->GetFieldID(bridge_class, "isStatic", "Z");
    g_bridge_hits = env->GetFieldID(bridge_class, "hits", "I");
    g_bridge_last_arg = env->GetFieldID(bridge_class, "lastArg", "Ljava/lang/String;");
    g_bridge_last_return = env->GetFieldID(bridge_class, "lastReturn", "Ljava/lang/String;");
    g_bridge_last_error = env->GetFieldID(bridge_class, "lastError", "Ljava/lang/String;");
    g_bridge_target = env->GetFieldID(bridge_class, "target", "Ljava/lang/String;");
    g_bridge_class = (jclass)env->NewGlobalRef(bridge_class);
    if (!g_bridge_class || !g_bridge_backup || !g_bridge_is_static || !g_bridge_hits ||
        !g_bridge_last_arg || !g_bridge_last_return || !g_bridge_last_error || !g_bridge_target) {
        error = "AdhJavaHookBridge fields are missing";
        return nullptr;
    }
    LLOGI("loaded embedded AdhJavaHookBridge");
    return g_bridge_class;
}

static jobject get_bridge_object(JNIEnv *env, std::string &error) {
    if (g_bridge_object) return g_bridge_object;
    jclass bridge_class = load_bridge_class(env, error);
    if (!bridge_class) return nullptr;
    jmethodID ctor = env->GetMethodID(bridge_class, "<init>", "()V");
    jobject object = ctor ? env->NewObject(bridge_class, ctor) : nullptr;
    if (!object) {
        error = "failed to create AdhJavaHookBridge instance";
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    g_bridge_object = env->NewGlobalRef(object);
    env->DeleteLocalRef(object);
    if (!g_bridge_object) {
        error = "failed to retain AdhJavaHookBridge instance";
        return nullptr;
    }
    return g_bridge_object;
}

// ---- target lookup / hook state -------------------------------------------------------
static jobject g_target_method = nullptr;   // global ref to java.lang.reflect.Method
static jobject g_backup_method = nullptr;   // global ref returned by LSPlant
static int g_hook_active = 0;
static std::string g_target_name;

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
        if (env->ExceptionCheck()) env->ExceptionClear();
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

static jobject find_target_method(JNIEnv *env, jclass target_class, const std::string &class_name,
                                  const std::string &method_name, const std::string &params,
                                  std::string &signature, std::string &error) {
    std::vector<std::string> wanted = split_params(params);
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_declared_methods = env->GetMethodID(class_class, "getDeclaredMethods",
                                                      "()[Ljava/lang/reflect/Method;");
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID method_get_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID method_get_params = env->GetMethodID(method_class, "getParameterTypes",
                                                   "()[Ljava/lang/Class;");
    jmethodID set_accessible = env->GetMethodID(method_class, "setAccessible", "(Z)V");
    jobjectArray methods = (jobjectArray)env->CallObjectMethod(target_class, get_declared_methods);
    if (!methods) {
        error = "Class.getDeclaredMethods failed";
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }

    jobject found = nullptr;
    int matches = 0;
    jsize count = env->GetArrayLength(methods);
    for (jsize i = 0; i < count; i++) {
        jobject method = env->GetObjectArrayElement(methods, i);
        jstring name = (jstring)env->CallObjectMethod(method, method_get_name);
        const char *name_chars = name ? env->GetStringUTFChars(name, nullptr) : nullptr;
        bool name_ok = name_chars && method_name == name_chars;
        if (name_chars) env->ReleaseStringUTFChars(name, name_chars);
        if (name) env->DeleteLocalRef(name);
        if (!name_ok) {
            env->DeleteLocalRef(method);
            continue;
        }

        jobjectArray parameter_types = (jobjectArray)env->CallObjectMethod(method, method_get_params);
        jsize parameter_count = parameter_types ? env->GetArrayLength(parameter_types) : 0;
        bool params_ok = parameter_count == (jsize)wanted.size();
        for (jsize j = 0; params_ok && j < parameter_count; j++) {
            jclass parameter_class = (jclass)env->GetObjectArrayElement(parameter_types, j);
            jstring parameter_name = (jstring)env->CallObjectMethod(parameter_class, get_name);
            const char *parameter_chars = parameter_name ? env->GetStringUTFChars(parameter_name, nullptr) : nullptr;
            std::string actual = parameter_chars ? parameter_chars : "";
            if (parameter_chars) env->ReleaseStringUTFChars(parameter_name, parameter_chars);
            if (parameter_name) env->DeleteLocalRef(parameter_name);
            env->DeleteLocalRef(parameter_class);
            if (normalize_type(actual) != wanted[(size_t)j]) params_ok = false;
        }
        if (parameter_types) env->DeleteLocalRef(parameter_types);

        if (params_ok) {
            if (set_accessible) env->CallVoidMethod(method, set_accessible, JNI_TRUE);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (!found) found = env->NewLocalRef(method);
            matches++;
        }
        env->DeleteLocalRef(method);
    }
    env->DeleteLocalRef(methods);

    if (!found) {
        error = "target method not found: " + class_name + "." + method_name + "(" + params + ")";
        return nullptr;
    }
    if (matches > 1) {
        env->DeleteLocalRef(found);
        error = "ambiguous target method (multiple overloads): " + class_name + "." + method_name;
        return nullptr;
    }
    signature = class_name + "." + method_name + "(" + params + ")";
    return found;
}

extern "C" int adh_javahook_hook_method(JNIEnv *env, const char *class_name, const char *method_name,
                                         const char *params, char *error, size_t error_size) {
    if (!env || !class_name || !method_name) {
        set_error(error, error_size, "missing class/method");
        return 0;
    }
    if (!adh_javahook_init(env)) {
        set_error(error, error_size, "%s", adh_javahook_last_error());
        return 0;
    }
    if (g_hook_active) {
        set_error(error, error_size, "a Java hook is already active; unhook it first");
        return 0;
    }

    std::string problem;
    jclass target_class = load_app_class(env, class_name, problem);
    if (!target_class) {
        set_error(error, error_size, "%s", problem.c_str());
        return 0;
    }
    std::string signature;
    jobject target = find_target_method(env, target_class, class_name, method_name, params ? params : "", signature, problem);
    env->DeleteLocalRef(target_class);
    if (!target) {
        set_error(error, error_size, "%s", problem.c_str());
        return 0;
    }

    bool is_static = false;
    if (!method_is_static(env, target, is_static, problem)) {
        env->DeleteLocalRef(target);
        set_error(error, error_size, "%s", problem.c_str());
        return 0;
    }

    jobject bridge = get_bridge_object(env, problem);
    if (!bridge) {
        env->DeleteLocalRef(target);
        set_error(error, error_size, "%s", problem.c_str());
        return 0;
    }

    // Reset the fixed bridge before installing the next hook.
    env->SetIntField(bridge, g_bridge_hits, 0);
    jstring empty = env->NewStringUTF("");
    env->SetObjectField(bridge, g_bridge_last_arg, empty);
    env->SetObjectField(bridge, g_bridge_last_return, empty);
    env->SetObjectField(bridge, g_bridge_last_error, empty);
    jstring target_string = env->NewStringUTF(signature.c_str());
    env->SetObjectField(bridge, g_bridge_target, target_string);
    env->SetBooleanField(bridge, g_bridge_is_static, is_static ? JNI_TRUE : JNI_FALSE);
    env->SetObjectField(bridge, g_bridge_backup, nullptr);

    jmethodID callback_id = env->GetMethodID(g_bridge_class, "callback",
                                             "([Ljava/lang/Object;)Ljava/lang/Object;");
    jobject callback = callback_id ? env->ToReflectedMethod(g_bridge_class, callback_id, JNI_FALSE) : nullptr;
    if (!callback) {
        env->DeleteLocalRef(target);
        set_error(error, error_size, "failed to reflect AdhJavaHookBridge.callback");
        if (env->ExceptionCheck()) env->ExceptionClear();
        return 0;
    }

    jobject backup = lsplant::Hook(env, target, bridge, callback);
    env->DeleteLocalRef(callback);
    if (!backup) {
        env->DeleteLocalRef(target);
        set_error(error, error_size, "lsplant::Hook failed (check logcat tag ADH_LSP)");
        return 0;
    }

    env->SetObjectField(bridge, g_bridge_backup, backup);
    g_target_method = env->NewGlobalRef(target);
    g_backup_method = backup;  // LSPlant returns a global reference
    g_hook_active = 1;
    g_target_name = signature;
    env->DeleteLocalRef(target);
    return 1;
}

extern "C" int adh_javahook_unhook_active(JNIEnv *env, char *error, size_t error_size) {
    if (!env || !g_hook_active || !g_target_method) {
        set_error(error, error_size, "no active Java hook");
        return 0;
    }
    if (!lsplant::UnHook(env, g_target_method)) {
        set_error(error, error_size, "lsplant::UnHook failed (check logcat tag ADH_LSP)");
        return 0;
    }
    if (g_bridge_object && g_bridge_backup) env->SetObjectField(g_bridge_object, g_bridge_backup, nullptr);
    if (g_bridge_object && g_bridge_hits) env->SetIntField(g_bridge_object, g_bridge_hits, 0);
    if (g_backup_method) {
        env->DeleteGlobalRef(g_backup_method);
        g_backup_method = nullptr;
    }
    env->DeleteGlobalRef(g_target_method);
    g_target_method = nullptr;
    g_hook_active = 0;
    g_target_name.clear();
    return 1;
}

extern "C" int adh_javahook_status_json(JNIEnv *env, char *out, size_t out_size) {
    if (!out || !out_size) return 0;
    int hits = 0;
    std::string last_arg, last_return, last_error;
    if (env && g_bridge_object) {
        hits = env->GetIntField(g_bridge_object, g_bridge_hits);
        last_arg = get_string_field(env, g_bridge_object, g_bridge_last_arg);
        last_return = get_string_field(env, g_bridge_object, g_bridge_last_return);
        last_error = get_string_field(env, g_bridge_object, g_bridge_last_error);
    }
    std::string json =
        std::string("{\"available\":true,\"initOk\":") + (g_init_ok ? "true" : "false") +
        ",\"backend\":\"lsplant\",\"version\":\"v6.4\",\"active\":" + (g_hook_active ? "true" : "false") +
        ",\"target\":\"" + json_escape(g_target_name) + "\"" +
        ",\"hits\":" + std::to_string(hits) +
        ",\"lastArg\":\"" + json_escape(last_arg) + "\"" +
        ",\"lastReturn\":\"" + json_escape(last_return) + "\"" +
        ",\"lastError\":\"" + json_escape(last_error) + "\"}";
    snprintf(out, out_size, "%s", json.c_str());
    out[out_size - 1] = 0;
    return 1;
}
// Lightweight live-class introspection for MCP: class metadata, constructors, overloaded
// methods and fields. This is reflection-only; heavy analysis and indexing stay on the Host.
#include "java_enum.h"
#include "jni.h"
#include "jni_env_hooks.h"

#include <android/log.h>
#include <pthread.h>
#include <time.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#define TAG "rt.enum"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static std::string jstring_to_utf(JNIEnv *env, jstring value);

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
}

struct LocalFrameGuard {
    JNIEnv *env;
    bool active;
    LocalFrameGuard(JNIEnv *e, jint capacity) : env(e), active(false) {
        if (env && env->PushLocalFrame(capacity) == 0) active = true;
    }
    ~LocalFrameGuard() {
        if (active) {
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            env->PopLocalFrame(nullptr);
        }
    }
};

static std::string throwable_text(JNIEnv *env, jthrowable throwable) {
    if (!env || !throwable) return "";
    jclass throwable_class = env->FindClass("java/lang/Throwable");
    jmethodID to_string = throwable_class ? env->GetMethodID(throwable_class, "toString", "()Ljava/lang/String;") : nullptr;
    jstring text = to_string ? (jstring)env->CallObjectMethod(throwable, to_string) : nullptr;
    std::string result = jstring_to_utf(env, text);
    if (text) env->DeleteLocalRef(text);
    return result;
}

static std::string pending_exception_text(JNIEnv *env) {
    if (!env || !adh_jni_exception_check(env)) return "";
    jthrowable throwable = env->ExceptionOccurred();
    adh_jni_exception_clear(env);
    if (!throwable) return "unknown Java exception";
    std::string result = throwable_text(env, throwable);
    // Reflection wrappers hide the answer. "java.lang.reflect.InvocationTargetException" tells an
    // operator (or an AI) nothing it can act on; the CAUSE carries the real class and message
    // (e.g. "android.system.ErrnoException: Os.access failed: EACCES (Permission denied)"), which is
    // the difference between "the call failed" and "the target refused for THIS reason".
    jclass ite = env->FindClass("java/lang/reflect/InvocationTargetException");
    if (ite && env->IsInstanceOf(throwable, ite)) {
        jmethodID get_cause = env->GetMethodID(ite, "getCause", "()Ljava/lang/Throwable;");
        jthrowable cause = get_cause ? (jthrowable)env->CallObjectMethod(throwable, get_cause) : nullptr;
        if (env->ExceptionCheck()) adh_jni_exception_clear(env);
        if (cause) {
            std::string inner = throwable_text(env, cause);
            if (!inner.empty()) result = inner;
            env->DeleteLocalRef(cause);
        }
        env->DeleteLocalRef(ite);
    }
    env->DeleteLocalRef(throwable);
    return result.empty() ? "unknown Java exception" : result;
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
                } else out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

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

static std::string class_name_of(JNIEnv *env, jclass cls, jmethodID get_name) {
    if (!env || !cls || !get_name) return "";
    jstring name = (jstring)env->CallObjectMethod(cls, get_name);
    std::string out = jstring_to_utf(env, name);
    if (name) env->DeleteLocalRef(name);
    return out;
}

static std::string modifiers_of(JNIEnv *env, jint modifiers, jclass modifier_class, jmethodID to_string) {
    if (!modifier_class || !to_string) return "";
    jstring value = (jstring)env->CallStaticObjectMethod(modifier_class, to_string, modifiers);
    std::string out = jstring_to_utf(env, value);
    if (value) env->DeleteLocalRef(value);
    return out;
}

static void append_class_array(JNIEnv *env, std::string &out, jobjectArray array, jmethodID get_name) {
    out += "[";
    jsize count = array ? env->GetArrayLength(array) : 0;
    for (jsize i = 0; i < count; i++) {
        jclass item = (jclass)env->GetObjectArrayElement(array, i);
        if (i) out += ",";
        out += "\"" + json_escape(class_name_of(env, item, get_name)) + "\"";
        if (item) env->DeleteLocalRef(item);
    }
    out += "]";
}

static void append_params(JNIEnv *env, std::string &out, jobjectArray params, jmethodID get_name) {
    out += "[";
    jsize count = params ? env->GetArrayLength(params) : 0;
    for (jsize i = 0; i < count; i++) {
        jclass item = (jclass)env->GetObjectArrayElement(params, i);
        if (i) out += ",";
        out += "\"" + json_escape(class_name_of(env, item, get_name)) + "\"";
        if (item) env->DeleteLocalRef(item);
    }
    out += "]";
}

extern "C" int adh_java_enum_json(JNIEnv *env, const char *class_name, char **out_json,
                                   char *error, size_t error_size) {
    LocalFrameGuard local_frame(env, 256);
    if (out_json) *out_json = nullptr;
    if (!env || !class_name || !class_name[0] || !out_json) {
        set_error(error, error_size, "need className and JNIEnv");
        return 0;
    }

    jobject loader = adh_jni_app_class_loader(env);
    if (!loader) {
        set_error(error, error_size, "no app ClassLoader available");
        return 0;
    }
    jclass class_loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID load_class = env->GetMethodID(class_loader_class, "loadClass",
                                            "(Ljava/lang/String;)Ljava/lang/Class;");
    std::string dot_name = class_name;
    for (char &c : dot_name) if (c == '/') c = '.';
    jstring requested = env->NewStringUTF(dot_name.c_str());
    jclass target = load_class ? (jclass)env->CallObjectMethod(loader, load_class, requested) : nullptr;
    if (!target) {
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        set_error(error, error_size, "target class not found: %s", dot_name.c_str());
        return 0;
    }

    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    jmethodID get_super = env->GetMethodID(class_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID get_interfaces = env->GetMethodID(class_class, "getInterfaces", "()[Ljava/lang/Class;");
    jmethodID get_loader = env->GetMethodID(class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jmethodID is_interface = env->GetMethodID(class_class, "isInterface", "()Z");
    jmethodID is_enum = env->GetMethodID(class_class, "isEnum", "()Z");
    jmethodID get_methods = env->GetMethodID(class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    jmethodID get_constructors = env->GetMethodID(class_class, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;");
    jmethodID get_fields = env->GetMethodID(class_class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
    jclass modifier_class = env->FindClass("java/lang/reflect/Modifier");
    jmethodID modifier_to_string = env->GetStaticMethodID(modifier_class, "toString", "(I)Ljava/lang/String;");
    if (!get_name || !get_methods || !get_constructors || !get_fields || !modifier_to_string) {
        set_error(error, error_size, "reflection methods unavailable");
        return 0;
    }

    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID method_name = env->GetMethodID(method_class, "getName", "()Ljava/lang/String;");
    jmethodID method_params = env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID method_return = env->GetMethodID(method_class, "getReturnType", "()Ljava/lang/Class;");
    jmethodID method_modifiers = env->GetMethodID(method_class, "getModifiers", "()I");
    jmethodID method_synthetic = env->GetMethodID(method_class, "isSynthetic", "()Z");
    jmethodID method_bridge = env->GetMethodID(method_class, "isBridge", "()Z");

    jclass ctor_class = env->FindClass("java/lang/reflect/Constructor");
    jmethodID ctor_params = env->GetMethodID(ctor_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jmethodID ctor_modifiers = env->GetMethodID(ctor_class, "getModifiers", "()I");
    jmethodID ctor_synthetic = env->GetMethodID(ctor_class, "isSynthetic", "()Z");

    jclass field_class = env->FindClass("java/lang/reflect/Field");
    jmethodID field_name = env->GetMethodID(field_class, "getName", "()Ljava/lang/String;");
    jmethodID field_type = env->GetMethodID(field_class, "getType", "()Ljava/lang/Class;");
    jmethodID field_modifiers = env->GetMethodID(field_class, "getModifiers", "()I");
    jmethodID field_synthetic = env->GetMethodID(field_class, "isSynthetic", "()Z");

    const int MAX_MEMBERS = 500;
    bool truncated = false;
    std::string out = "{\"className\":\"" + json_escape(class_name_of(env, target, get_name)) + "\"";

    jclass super = (jclass)env->CallObjectMethod(target, get_super);
    out += ",\"superclass\":";
    if (super) out += "\"" + json_escape(class_name_of(env, super, get_name)) + "\"";
    else out += "null";
    if (super) env->DeleteLocalRef(super);

    jobjectArray interfaces = (jobjectArray)env->CallObjectMethod(target, get_interfaces);
    out += ",\"interfaces\":";
    append_class_array(env, out, interfaces, get_name);
    if (interfaces) env->DeleteLocalRef(interfaces);

    jobject class_loader = env->CallObjectMethod(target, get_loader);
    out += ",\"classLoader\":";
    if (class_loader) {
        jclass object_class = env->FindClass("java/lang/Object");
        jmethodID to_string = env->GetMethodID(object_class, "toString", "()Ljava/lang/String;");
        jstring loader_name = (jstring)env->CallObjectMethod(class_loader, to_string);
        out += "\"" + json_escape(jstring_to_utf(env, loader_name)) + "\"";
        if (loader_name) env->DeleteLocalRef(loader_name);
        env->DeleteLocalRef(object_class);
        env->DeleteLocalRef(class_loader);
    } else out += "\"bootstrap\"";

    out += ",\"interface\":";
    out += env->CallBooleanMethod(target, is_interface) ? "true" : "false";
    out += ",\"enum\":";
    out += env->CallBooleanMethod(target, is_enum) ? "true" : "false";

    out += ",\"constructors\":[";
    jobjectArray ctors = (jobjectArray)env->CallObjectMethod(target, get_constructors);
    jsize ctor_count = ctors ? env->GetArrayLength(ctors) : 0;
    if (ctor_count > MAX_MEMBERS) { ctor_count = MAX_MEMBERS; truncated = true; }
    for (jsize i = 0; i < ctor_count; i++) {
        jobject ctor = env->GetObjectArrayElement(ctors, i);
        jobjectArray params = (jobjectArray)env->CallObjectMethod(ctor, ctor_params);
        jint modifiers = env->CallIntMethod(ctor, ctor_modifiers);
        if (i) out += ",";
        out += "{\"params\":";
        append_params(env, out, params, get_name);
        out += ",\"modifiers\":\"" + json_escape(modifiers_of(env, modifiers, modifier_class, modifier_to_string)) + "\"";
        out += ",\"synthetic\":";
        out += env->CallBooleanMethod(ctor, ctor_synthetic) ? "true" : "false";
        out += "}";
        if (params) env->DeleteLocalRef(params);
        if (ctor) env->DeleteLocalRef(ctor);
    }
    if (ctors) env->DeleteLocalRef(ctors);
    out += "]";

    out += ",\"methods\":[";
    jobjectArray methods = (jobjectArray)env->CallObjectMethod(target, get_methods);
    jsize method_count = methods ? env->GetArrayLength(methods) : 0;
    if (method_count > MAX_MEMBERS) { method_count = MAX_MEMBERS; truncated = true; }
    for (jsize i = 0; i < method_count; i++) {
        jobject method = env->GetObjectArrayElement(methods, i);
        jstring name = (jstring)env->CallObjectMethod(method, method_name);
        jclass return_class = (jclass)env->CallObjectMethod(method, method_return);
        jobjectArray params = (jobjectArray)env->CallObjectMethod(method, method_params);
        jint modifiers = env->CallIntMethod(method, method_modifiers);
        if (i) out += ",";
        out += "{\"name\":\"" + json_escape(jstring_to_utf(env, name)) + "\"";
        out += ",\"return\":\"" + json_escape(class_name_of(env, return_class, get_name)) + "\"";
        out += ",\"params\":";
        append_params(env, out, params, get_name);
        out += ",\"modifiers\":\"" + json_escape(modifiers_of(env, modifiers, modifier_class, modifier_to_string)) + "\"";
        out += ",\"synthetic\":";
        out += env->CallBooleanMethod(method, method_synthetic) ? "true" : "false";
        out += ",\"bridge\":";
        out += env->CallBooleanMethod(method, method_bridge) ? "true" : "false";
        out += "}";
        if (name) env->DeleteLocalRef(name);
        if (return_class) env->DeleteLocalRef(return_class);
        if (params) env->DeleteLocalRef(params);
        if (method) env->DeleteLocalRef(method);
    }
    if (methods) env->DeleteLocalRef(methods);
    out += "]";

    out += ",\"fields\":[";
    jobjectArray fields = (jobjectArray)env->CallObjectMethod(target, get_fields);
    jsize field_count = fields ? env->GetArrayLength(fields) : 0;
    if (field_count > MAX_MEMBERS) { field_count = MAX_MEMBERS; truncated = true; }
    for (jsize i = 0; i < field_count; i++) {
        jobject field = env->GetObjectArrayElement(fields, i);
        jstring name = (jstring)env->CallObjectMethod(field, field_name);
        jclass type = (jclass)env->CallObjectMethod(field, field_type);
        jint modifiers = env->CallIntMethod(field, field_modifiers);
        if (i) out += ",";
        out += "{\"name\":\"" + json_escape(jstring_to_utf(env, name)) + "\"";
        out += ",\"type\":\"" + json_escape(class_name_of(env, type, get_name)) + "\"";
        out += ",\"modifiers\":\"" + json_escape(modifiers_of(env, modifiers, modifier_class, modifier_to_string)) + "\"";
        out += ",\"synthetic\":";
        out += env->CallBooleanMethod(field, field_synthetic) ? "true" : "false";
        out += "}";
        if (name) env->DeleteLocalRef(name);
        if (type) env->DeleteLocalRef(type);
        if (field) env->DeleteLocalRef(field);
    }
    if (fields) env->DeleteLocalRef(fields);
    out += "]";
    out += ",\"truncated\":";
    out += truncated ? "true" : "false";
    out += "}";

    char *copy = strdup(out.c_str());
    if (!copy) {
        set_error(error, error_size, "out of memory");
        return 0;
    }
    *out_json = copy;
    LOGI("java_enum %s: methods=%d fields=%d ctors=%d truncated=%d", dot_name.c_str(),
         (int)method_count, (int)field_count, (int)ctor_count, truncated ? 1 : 0);
    return 1;
}

extern "C" void adh_java_enum_free(char *json) {
    free(json);
}
// ---- active Java method invocation -----------------------------------------------------
struct CallArg {
    int kind;          // 0 null, 1 string, 2 bool, 3 number, 4 array, 5 bytes
    std::string text;
    std::vector<CallArg> items;   // kind 4 only
    // kind 5 only: text holds the payload, either UTF-8 ({"$bytes":…}) or hex ({"$bytesHex":…}).
    // A JSON array cannot express "this element is a byte[]" — its elements are typed by the
    // declared component (Object), so a dispatcher like Bridge.entry(int, Object[]) would receive a
    // String where native code does GetArrayLength and aborts the VM. The wrapper is that type.
    bool hex_bytes = false;
};

static void skip_ws(const char *&p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
}

static bool parse_json_string(const char *&p, std::string &out, std::string &error) {
    if (*p != '"') { error = "expected JSON string"; return false; }
    p++;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
                case '"': out.push_back('"'); p++; break;
                case '\\': out.push_back('\\'); p++; break;
                case '/': out.push_back('/'); p++; break;
                case 'b': out.push_back('\b'); p++; break;
                case 'f': out.push_back('\f'); p++; break;
                case 'n': out.push_back('\n'); p++; break;
                case 'r': out.push_back('\r'); p++; break;
                case 't': out.push_back('\t'); p++; break;
                case 'u': {
                    p++;
                    unsigned code = 0;
                    for (int i = 0; i < 4 && isxdigit((unsigned char)*p); i++, p++) {
                        char c = *p;
                        code <<= 4;
                        code += (c >= '0' && c <= '9') ? (c - '0') :
                                (c >= 'a' && c <= 'f') ? (c - 'a' + 10) : (c - 'A' + 10);
                    }
                    if (code < 0x80) out.push_back((char)code);
                    else if (code < 0x800) {
                        out.push_back((char)(0xc0 | (code >> 6)));
                        out.push_back((char)(0x80 | (code & 0x3f)));
                    } else out.push_back('?');
                    break;
                }
                default: error = "unsupported JSON escape"; return false;
            }
        } else out.push_back(*p++);
    }
    if (*p != '"') { error = "unterminated JSON string"; return false; }
    p++;
    return true;
}

// One JSON value inside the args array. Arrays are nested, because a target's entry point is very
// often `Object[]` (the JDGuard dispatcher is `main(int, Object[])`): without this, java_call could
// not drive a dispatcher at all, which is exactly the call an oracle for a signer needs.
static bool parse_json_arg(const char *&p, CallArg &arg, std::string &error);

static bool parse_json_args(const char *json, std::vector<CallArg> &args, std::string &error) {
    args.clear();
    if (!json || !*json) return true;
    const char *p = json;
    skip_ws(p);
    if (*p != '[') { error = "args must be a JSON array"; return false; }
    p++;
    for (;;) {
        skip_ws(p);
        if (*p == ']') break;
        CallArg arg{};
        if (!parse_json_arg(p, arg, error)) return false;
        args.push_back(arg);
        skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == ']') break;
        error = "expected ',' or ']' in args";
        return false;
    }
    return true;
}

static bool parse_json_arg(const char *&p, CallArg &arg, std::string &error) {
    skip_ws(p);
    if (*p == '"') {
        arg.kind = 1;
        return parse_json_string(p, arg.text, error);
    }
    if (strncmp(p, "true", 4) == 0) { arg.kind = 2; arg.text = "true"; p += 4; return true; }
    if (strncmp(p, "false", 5) == 0) { arg.kind = 2; arg.text = "false"; p += 5; return true; }
    if (strncmp(p, "null", 4) == 0) { arg.kind = 0; p += 4; return true; }
    if (*p == '{') {
        // {"$bytes":"…"} / {"$bytesHex":"…"} — the only object form an argument may take.
        p++;
        skip_ws(p);
        if (strncmp(p, "\"$bytesHex\"", 11) == 0) { arg.hex_bytes = true; p += 11; }
        else if (strncmp(p, "\"$bytes\"", 8) == 0) { arg.hex_bytes = false; p += 8; }
        else { error = "unsupported JSON object argument (only {\"$bytes\":…} / {\"$bytesHex\":…})"; return false; }
        skip_ws(p);
        if (*p != ':') { error = "expected ':' after $bytes"; return false; }
        p++;
        skip_ws(p);
        arg.kind = 5;
        if (!parse_json_string(p, arg.text, error)) return false;
        skip_ws(p);
        if (*p != '}') { error = "expected '}' after $bytes value"; return false; }
        p++;
        return true;
    }
    if (*p == '[') {
        arg.kind = 4;
        p++;
        for (;;) {
            skip_ws(p);
            if (*p == ']') { p++; return true; }
            CallArg item{};
            if (!parse_json_arg(p, item, error)) return false;
            arg.items.push_back(item);
            skip_ws(p);
            if (*p == ',') { p++; continue; }
            if (*p == ']') { p++; return true; }
            error = "expected ',' or ']' in nested args";
            return false;
        }
    }
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        arg.kind = 3;
        const char *begin = p;
        while (*p && *p != ',' && *p != ']') p++;
        arg.text.assign(begin, p - begin);
        while (!arg.text.empty() && (arg.text.back() == ' ' || arg.text.back() == '\t' ||
                                     arg.text.back() == '\r' || arg.text.back() == '\n')) arg.text.pop_back();
        return true;
    }
    error = "unsupported JSON argument value";
    return false;
}

static std::string normalize_call_type(std::string type) {
    for (char &c : type) if (c == '/') c = '.';
    if (type == "void" || type == "boolean" || type == "byte" || type == "char" ||
        type == "short" || type == "int" || type == "long" || type == "float" ||
        type == "double") return type;
    size_t dims = 0;
    while (type.size() >= 2 && type.compare(type.size() - 2, 2, "[]") == 0) {
        dims++;
        type.resize(type.size() - 2);
    }
    if (!dims) return type;
    std::string out;
    for (size_t i = 0; i < dims; i++) out.push_back('[');
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

static std::vector<std::string> split_call_params(const std::string &params) {
    std::vector<std::string> out;
    std::string current;
    for (char c : params) {
        if (c == ',') {
            std::string item = current;
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.erase(item.begin());
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.pop_back();
            if (!item.empty()) out.push_back(normalize_call_type(item));
            current.clear();
        } else current.push_back(c);
    }
    std::string item = current;
    while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.erase(item.begin());
    while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.pop_back();
    if (!item.empty()) out.push_back(normalize_call_type(item));
    return out;
}

static jclass load_class_by_name(JNIEnv *env, const std::string &class_name, std::string &error) {
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
    jclass target = load_class ? (jclass)env->CallObjectMethod(loader, load_class, name) : nullptr;
    if (!target) {
        error = "target class not found: " + dot_name;
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return nullptr;
    }
    return target;
}

static jobject find_call_method(JNIEnv *env, jclass target_class, const std::string &class_name,
                                const std::string &method_name, const std::string &params,
                                std::string &signature, std::string &error) {
    std::vector<std::string> wanted = split_call_params(params);
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
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        if (!name_ok) { env->DeleteLocalRef(method); continue; }
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
            if (normalize_call_type(actual) != wanted[(size_t)j]) params_ok = false;
        }
        if (parameter_types) env->DeleteLocalRef(parameter_types);
        if (params_ok) {
            if (set_accessible) env->CallVoidMethod(method, set_accessible, JNI_TRUE);
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        error = "ambiguous target method: " + class_name + "." + method_name;
        return nullptr;
    }
    signature = class_name + "." + method_name + "(" + params + ")";
    return found;
}

static jobject make_java_arg_typed(JNIEnv *env, const std::string &type, const CallArg &arg,
                                   std::string &error) {
    // A typed byte payload wins over the declared type: {"$bytes":…} inside an Object[] is the only
    // way to hand a dispatcher (main(int, Object[])) the bytes it expects instead of a String.
    if (arg.kind == 5) {
        std::string raw;
        if (arg.hex_bytes) {
            if (arg.text.size() % 2 != 0) { error = "hex byte payload has an odd number of digits"; return nullptr; }
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            raw.reserve(arg.text.size() / 2);
            for (size_t i = 0; i < arg.text.size(); i += 2) {
                int hi = nib(arg.text[i]), lo = nib(arg.text[i + 1]);
                if (hi < 0 || lo < 0) { error = "invalid hex digit in $bytesHex"; return nullptr; }
                raw.push_back((char)((hi << 4) | lo));
            }
        } else {
            raw = arg.text;
        }
        jbyteArray bytes = env->NewByteArray((jsize)raw.size());
        if (!bytes) { error = "NewByteArray failed"; return nullptr; }
        if (!raw.empty()) {
            env->SetByteArrayRegion(bytes, 0, (jsize)raw.size(), reinterpret_cast<const jbyte *>(raw.data()));
        }
        return bytes;
    }
    // Class.getName() reports an array as the JVM descriptor (`[Ljava.lang.Object;`), while a
    // user-typed params list says `java.lang.Object[]`. Accept both: the dispatcher call that
    // needs this is the whole reason the array marshalling exists.
    bool array = false;
    std::string component;
    if (type.size() > 2 && type.compare(type.size() - 2, 2, "[]") == 0) {
        array = true;
        component = type.substr(0, type.size() - 2);
    } else if (!type.empty() && type[0] == '[' && type.size() > 3 && type[1] == 'L' &&
               type[type.size() - 1] == ';') {
        array = true;
        component = type.substr(2, type.size() - 3);
    } else if (type == "byte[]" || type == "[B") {
        array = true;
        component = "byte";
    }
    if (array && component == "byte") {
        // A real dispatcher takes the request as a byte[] (measured: JDGuard `main(101, ...)` does a
        // GetArrayLength on it, and a String there aborts the VM). A JSON string becomes its UTF-8
        // bytes, which is exact for ASCII input and never silently truncates.
        if (arg.kind == 0) return nullptr;
        if (arg.kind != 1) {
            error = "byte[] argument must be a JSON string (sent as its UTF-8 bytes)";
            return nullptr;
        }
        jbyteArray bytes = env->NewByteArray((jsize)arg.text.size());
        if (!bytes) {
            error = "NewByteArray failed";
            return nullptr;
        }
        env->SetByteArrayRegion(bytes, 0, (jsize)arg.text.size(),
                                reinterpret_cast<const jbyte *>(arg.text.data()));
        return bytes;
    }
    if (arg.kind == 4) {
        if (!array) {
            error = "array value passed to non-array parameter " + type;
            return nullptr;
        }
        if (component == "byte" || component == "boolean" || component == "char" ||
            component == "short" || component == "int" || component == "long" ||
            component == "float" || component == "double") {
            error = "primitive array parameter is not marshalled: " + type;
            return nullptr;
        }
        std::string slash = component;
        for (char &c : slash) if (c == '.') c = '/';
        jclass comp_class = env->FindClass(slash.c_str());
        if (!comp_class) {
            env->ExceptionClear();
            error = "array component class not found: " + component;
            return nullptr;
        }
        jobjectArray arr = env->NewObjectArray((jsize)arg.items.size(), comp_class, nullptr);
        env->DeleteLocalRef(comp_class);
        if (!arr) {
            error = "NewObjectArray failed for " + type;
            return nullptr;
        }
        for (size_t i = 0; i < arg.items.size(); i++) {
            jobject item = make_java_arg_typed(env, component, arg.items[i], error);
            if (!item && arg.items[i].kind != 0) {
                env->DeleteLocalRef(arr);
                return nullptr;
            }
            env->SetObjectArrayElement(arr, (jsize)i, item);
            if (item) env->DeleteLocalRef(item);
        }
        return arr;
    }
    if (arg.kind == 0) {
        if (type == "boolean" || type == "byte" || type == "char" || type == "short" ||
            type == "int" || type == "long" || type == "float" || type == "double") {
            error = "null cannot be passed to primitive " + type;
            return nullptr;
        }
        return nullptr;
    }
    if (arg.kind == 1) {
        if (type == "char" || type == "java.lang.Character") {
            if (arg.text.size() != 1) { error = "char argument must be one character"; return nullptr; }
            jclass cls = env->FindClass("java/lang/Character");
            jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(C)Ljava/lang/Character;");
            return env->CallStaticObjectMethod(cls, value_of, (jchar)arg.text[0]);
        }
        if (type == "java.lang.String" || type == "java.lang.Object" || type == "java.lang.CharSequence" ||
            type == "java.lang.Comparable") return env->NewStringUTF(arg.text.c_str());
        error = "string argument does not match " + type;
        return nullptr;
    }
    if (arg.kind == 2) {
        if (type == "boolean" || type == "java.lang.Boolean" || type == "java.lang.Object") {
            jclass cls = env->FindClass("java/lang/Boolean");
            jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(Z)Ljava/lang/Boolean;");
            return env->CallStaticObjectMethod(cls, value_of, arg.text == "true" ? JNI_TRUE : JNI_FALSE);
        }
        error = "boolean argument does not match " + type;
        return nullptr;
    }
    // number
    char *end = nullptr;
    if (type == "byte" || type == "java.lang.Byte") {
        jclass cls = env->FindClass("java/lang/Byte");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(B)Ljava/lang/Byte;");
        return env->CallStaticObjectMethod(cls, value_of, (jbyte)strtol(arg.text.c_str(), &end, 10));
    }
    if (type == "short" || type == "java.lang.Short") {
        jclass cls = env->FindClass("java/lang/Short");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(S)Ljava/lang/Short;");
        return env->CallStaticObjectMethod(cls, value_of, (jshort)strtol(arg.text.c_str(), &end, 10));
    }
    if (type == "int" || type == "java.lang.Integer") {
        jclass cls = env->FindClass("java/lang/Integer");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(I)Ljava/lang/Integer;");
        return env->CallStaticObjectMethod(cls, value_of, (jint)strtol(arg.text.c_str(), &end, 10));
    }
    if (type == "long" || type == "java.lang.Long" || type == "java.lang.Object" || type == "java.lang.Number") {
        if (type == "java.lang.Object" || type == "java.lang.Number") {
            if (arg.text.find('.') != std::string::npos || arg.text.find('e') != std::string::npos ||
                arg.text.find('E') != std::string::npos) {
                jclass cls = env->FindClass("java/lang/Double");
                jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(D)Ljava/lang/Double;");
                return env->CallStaticObjectMethod(cls, value_of, strtod(arg.text.c_str(), &end));
            }
        }
        jclass cls = env->FindClass("java/lang/Long");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(J)Ljava/lang/Long;");
        return env->CallStaticObjectMethod(cls, value_of, (jlong)strtoll(arg.text.c_str(), &end, 10));
    }
    if (type == "float" || type == "java.lang.Float") {
        jclass cls = env->FindClass("java/lang/Float");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(F)Ljava/lang/Float;");
        return env->CallStaticObjectMethod(cls, value_of, (jfloat)strtod(arg.text.c_str(), &end));
    }
    if (type == "double" || type == "java.lang.Double") {
        jclass cls = env->FindClass("java/lang/Double");
        jmethodID value_of = env->GetStaticMethodID(cls, "valueOf", "(D)Ljava/lang/Double;");
        return env->CallStaticObjectMethod(cls, value_of, strtod(arg.text.c_str(), &end));
    }
    error = "number argument does not match " + type;
    return nullptr;
}

static jobject make_java_arg(JNIEnv *env, jclass param_type, const CallArg &arg, std::string &error) {
    jclass class_class = env->FindClass("java/lang/Class");
    jmethodID get_name = env->GetMethodID(class_class, "getName", "()Ljava/lang/String;");
    std::string type = class_name_of(env, param_type, get_name);
    return make_java_arg_typed(env, type, arg, error);
}

extern "C" int adh_java_call_json(JNIEnv *env, const char *class_name, const char *method_name,
                                   const char *params, const char *field_name, const char *args_json,
                                   char **out_json, char *error, size_t error_size) {
    LocalFrameGuard local_frame(env, 256);
    if (out_json) *out_json = nullptr;
    if (!env || !class_name || !method_name || !out_json) {
        set_error(error, error_size, "need className and method");
        return 0;
    }
    std::string problem;
    jclass target_class = load_class_by_name(env, class_name, problem);
    if (!target_class) return (set_error(error, error_size, "%s", problem.c_str()), 0);
    std::string signature;
    jobject method = find_call_method(env, target_class, class_name, method_name, params ? params : "", signature, problem);
    if (!method) {
        env->DeleteLocalRef(target_class);
        return (set_error(error, error_size, "%s", problem.c_str()), 0);
    }

    jclass method_class = env->FindClass("java/lang/reflect/Method");
    jmethodID get_modifiers = env->GetMethodID(method_class, "getModifiers", "()I");
    jclass modifier_class = env->FindClass("java/lang/reflect/Modifier");
    jmethodID is_static = env->GetStaticMethodID(modifier_class, "isStatic", "(I)Z");
    bool method_is_static = env->CallStaticBooleanMethod(modifier_class, is_static,
                                                         env->CallIntMethod(method, get_modifiers)) == JNI_TRUE;

    jobject receiver = nullptr;
    if (!method_is_static) {
        if (!field_name || !field_name[0]) {
            env->DeleteLocalRef(method);
            env->DeleteLocalRef(target_class);
            return (set_error(error, error_size, "instance method requires field=<static field holding the receiver>"), 0);
        }
        jclass class_class = env->FindClass("java/lang/Class");
        jmethodID get_field = env->GetMethodID(class_class, "getDeclaredField",
                                               "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
        jstring field_j = env->NewStringUTF(field_name);
        jobject field = get_field ? env->CallObjectMethod(target_class, get_field, field_j) : nullptr;
        if (adh_jni_exception_check(env)) {
            std::string reason = pending_exception_text(env);
            env->DeleteLocalRef(method);
            env->DeleteLocalRef(target_class);
            return (set_error(error, error_size, "receiver field lookup failed: %s", reason.c_str()), 0);
        }
        if (field) {
            jclass field_class = env->FindClass("java/lang/reflect/Field");
            jmethodID set_accessible = env->GetMethodID(field_class, "setAccessible", "(Z)V");
            jmethodID get_value = env->GetMethodID(field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
            env->CallVoidMethod(field, set_accessible, JNI_TRUE);
            if (adh_jni_exception_check(env)) {
                std::string reason = pending_exception_text(env);
                env->DeleteLocalRef(method);
                env->DeleteLocalRef(target_class);
                return (set_error(error, error_size, "receiver field access failed: %s", reason.c_str()), 0);
            }
            receiver = env->CallObjectMethod(field, get_value, nullptr);
            if (adh_jni_exception_check(env)) {
                std::string reason = pending_exception_text(env);
                env->DeleteLocalRef(method);
                env->DeleteLocalRef(target_class);
                return (set_error(error, error_size, "receiver field read failed: %s", reason.c_str()), 0);
            }
        }
        if (!receiver) {
            env->DeleteLocalRef(method);
            env->DeleteLocalRef(target_class);
            return (set_error(error, error_size, "receiver field not found or null: %s", field_name), 0);
        }
    }

    std::vector<CallArg> args;
    if (!parse_json_args(args_json, args, problem)) {
        env->DeleteLocalRef(method);
        env->DeleteLocalRef(target_class);
        return (set_error(error, error_size, "%s", problem.c_str()), 0);
    }
    jmethodID get_params = env->GetMethodID(method_class, "getParameterTypes", "()[Ljava/lang/Class;");
    jobjectArray param_types = (jobjectArray)env->CallObjectMethod(method, get_params);
    jsize param_count = param_types ? env->GetArrayLength(param_types) : 0;
    if (param_count != (jsize)args.size()) {
        env->DeleteLocalRef(param_types);
        env->DeleteLocalRef(method);
        env->DeleteLocalRef(target_class);
        return (set_error(error, error_size, "argument count mismatch: expected %d got %d", (int)param_count, (int)args.size()), 0);
    }
    jobjectArray invoke_args = env->NewObjectArray(param_count, env->FindClass("java/lang/Object"), nullptr);
    for (jsize i = 0; i < param_count; i++) {
        jclass parameter_class = (jclass)env->GetObjectArrayElement(param_types, i);
        jobject value = make_java_arg(env, parameter_class, args[(size_t)i], problem);
        env->DeleteLocalRef(parameter_class);
        if (!value && args[(size_t)i].kind != 0) {
            env->DeleteLocalRef(param_types);
            env->DeleteLocalRef(invoke_args);
            env->DeleteLocalRef(method);
            env->DeleteLocalRef(target_class);
            return (set_error(error, error_size, "%s", problem.c_str()), 0);
        }
        env->SetObjectArrayElement(invoke_args, i, value);
    }

    jmethodID invoke = env->GetMethodID(method_class, "invoke",
                                        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jobject result = env->CallObjectMethod(method, invoke, receiver, invoke_args);
    if (adh_jni_exception_check(env)) {
        // Unwrap InvocationTargetException here too (this is the path java_call actually returns
        // through): the wrapper's own toString is "java.lang.reflect.InvocationTargetException",
        // which hides the class and message the caller can act on.
        std::string exception_text = pending_exception_text(env);
        if (exception_text.empty()) exception_text = "invocation threw an exception";
        env->DeleteLocalRef(param_types);
        env->DeleteLocalRef(invoke_args);
        env->DeleteLocalRef(method);
        env->DeleteLocalRef(target_class);
        return (set_error(error, error_size, "%s", exception_text.c_str()), 0);
    }

    jmethodID get_return = env->GetMethodID(method_class, "getReturnType", "()Ljava/lang/Class;");
    jclass return_class = (jclass)env->CallObjectMethod(method, get_return);
    std::string return_type = class_name_of(env, return_class, env->GetMethodID(env->FindClass("java/lang/Class"), "getName", "()Ljava/lang/String;"));
    std::string result_text = "null";
    if (return_type == "void") result_text = "void";
    else if (result) {
        jclass string_class = env->FindClass("java/lang/String");
        jmethodID value_of = env->GetStaticMethodID(string_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
        // A dispatcher returns Object[]/String[] (JDGuard's main hands back the jdgs JSON as a
        // String[]). String.valueOf on an array is the identity string "…@1a2b3c", which is not a
        // result — render the elements instead, the same way the hook bridge renders arguments.
        jclass obj_arr_class = env->FindClass("[Ljava/lang/Object;");
        if (obj_arr_class && env->IsInstanceOf(result, obj_arr_class)) {
            jobjectArray arr = (jobjectArray)result;
            jsize n = env->GetArrayLength(arr);
            std::string joined = "[";
            const jsize cap = 64;   // bounded: a reply is not a dump
            for (jsize i = 0; i < n && i < cap; i++) {
                jobject item = env->GetObjectArrayElement(arr, i);
                if (i) joined += ", ";
                if (!item) { joined += "null"; continue; }
                jstring text = (jstring)env->CallStaticObjectMethod(string_class, value_of, item);
                joined += text ? jstring_to_utf(env, text) : "";
                if (text) env->DeleteLocalRef(text);
                env->DeleteLocalRef(item);
            }
            if (n > cap) joined += ", …(" + std::to_string(n) + " slots)";
            joined += "]";
            result_text = joined;
            env->DeleteLocalRef(obj_arr_class);
        } else {
            jstring text = (jstring)env->CallStaticObjectMethod(string_class, value_of, result);
            result_text = jstring_to_utf(env, text);
            if (text) env->DeleteLocalRef(text);
        }
    }
    std::string out = "{\"className\":\"" + json_escape(class_name) + "\"" +
                      ",\"method\":\"" + json_escape(method_name) + "\"" +
                      ",\"signature\":\"" + json_escape(signature) + "\"" +
                      ",\"static\":" + (method_is_static ? "true" : "false") +
                      ",\"returnType\":\"" + json_escape(return_type) + "\"" +
                      ",\"result\":\"" + json_escape(result_text) + "\"}";
    char *copy = strdup(out.c_str());
    if (!copy) {
        set_error(error, error_size, "out of memory");
        return 0;
    }
    *out_json = copy;
    if (result) env->DeleteLocalRef(result);
    if (return_class) env->DeleteLocalRef(return_class);
    env->DeleteLocalRef(param_types);
    env->DeleteLocalRef(invoke_args);
    env->DeleteLocalRef(method);
    env->DeleteLocalRef(target_class);
    LOGI("java_call %s -> %s", signature.c_str(), result_text.c_str());
    return 1;
}

// ---- detached java_call -------------------------------------------------------------
// A synchronous java_call runs on the command thread, so a target method that blocks — or a
// dispatcher that waits for work on its own thread, which is exactly what a signing entry point
// does — takes the whole command channel with it: the daemon sees a timeout, cannot tell "still
// working" from "dead", and cannot even ask. Measured against JDGuard's `Bridge.entry`: the call
// never returned and the process was killed before the timeout expired.
//
// A detached call runs on its own attached thread and is polled. The contract stays deliberately
// narrow: start returns an id, status returns running/done/failed. A call that never returns stays
// running and costs one parked thread — it does not cost the session.
static long long acall_now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

namespace {
struct AsyncCall {
    int id = 0;
    int state = 0;                  // 0 running, 1 done, 2 failed
    char *result = nullptr;         // owned JSON from adh_java_call_json
    char error[512] = {0};
    long long started_ms = 0, finished_ms = 0;
    std::string cls, method, params, field, args;
};
std::mutex g_acall_mu;
std::map<int, AsyncCall *> g_acalls;
int g_acall_next = 1;
const size_t ACALL_KEEP = 16;       // finished jobs retained for polling
}  // namespace

static void acall_free(AsyncCall *job) {
    if (job->result) free(job->result);
    delete job;
}

static void *acall_worker(void *p) {
    AsyncCall *job = (AsyncCall *)p;
    char error[512] = {0};
    char *json = nullptr;
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    int ok = 0;
    if (!env) {
        snprintf(error, sizeof(error), "no JavaVM");
    } else {
        ok = adh_java_call_json(env, job->cls.c_str(), job->method.c_str(), job->params.c_str(),
                                job->field.c_str(), job->args.c_str(), &json, error, sizeof(error));
        if (did_attach) adh_jni_detach(did_attach);
    }
    std::lock_guard<std::mutex> lk(g_acall_mu);
    job->finished_ms = acall_now_ms();
    if (ok && json) {
        job->state = 1;
        job->result = json;
    } else {
        job->state = 2;
        snprintf(job->error, sizeof(job->error), "%s", error[0] ? error : "call failed");
        if (json) free(json);
    }
    return nullptr;
}

// Caller must hold g_acall_mu.
static void acall_prune_locked() {
    if (g_acalls.size() <= ACALL_KEEP) return;
    for (auto it = g_acalls.begin(); it != g_acalls.end() && g_acalls.size() > ACALL_KEEP;) {
        if (it->second->state == 0) { ++it; continue; }
        acall_free(it->second);
        it = g_acalls.erase(it);
    }
}

extern "C" int adh_java_call_async_start(const char *class_name, const char *method_name,
                                         const char *params, const char *field_name,
                                         const char *args_json, char *error, size_t error_size) {
    AsyncCall *job = new (std::nothrow) AsyncCall();
    if (!job) {
        set_error(error, error_size, "out of memory");
        return -1;
    }
    job->cls = class_name ? class_name : "";
    job->method = method_name ? method_name : "";
    job->params = params ? params : "";
    job->field = field_name ? field_name : "";
    job->args = args_json ? args_json : "[]";
    job->started_ms = acall_now_ms();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, &attr, acall_worker, job);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        delete job;
        set_error(error, error_size, "pthread_create failed: %d", rc);
        return -1;
    }
    std::lock_guard<std::mutex> lk(g_acall_mu);
    job->id = g_acall_next++;
    g_acalls[job->id] = job;
    acall_prune_locked();
    int id = job->id;
    LOGI("java_call detached #%d %s#%s", id, job->cls.c_str(), job->method.c_str());
    return id;
}

static const char *acall_state_name(int state) {
    return state == 1 ? "done" : (state == 2 ? "failed" : "running");
}

// JSON for one job (malloc-backed, free with adh_java_enum_free), or NULL for an unknown id.
// The stored result is copied, not consumed: polling twice is allowed and has to stay safe.
extern "C" char *adh_java_call_async_status(int id) {
    std::lock_guard<std::mutex> lk(g_acall_mu);
    auto it = g_acalls.find(id);
    if (it == g_acalls.end()) return nullptr;
    AsyncCall *job = it->second;
    long long end = job->state == 0 ? acall_now_ms() : job->finished_ms;
    std::string out = "{\"callId\":" + std::to_string(job->id) +
                      ",\"state\":\"" + acall_state_name(job->state) + "\"" +
                      ",\"elapsedMs\":" + std::to_string(end - job->started_ms) +
                      ",\"target\":\"" + json_escape(job->cls + "#" + job->method) + "\"";
    if (job->state == 1 && job->result) out += ",\"result\":" + std::string(job->result);
    if (job->state == 2) out += ",\"error\":\"" + json_escape(job->error) + "\"";
    out += "}";
    return strdup(out.c_str());
}

// Summary of every retained job (no results): the answer to "what happened to my call" when the
// id was lost. Caller frees with adh_java_enum_free.
extern "C" char *adh_java_call_async_list(void) {
    std::lock_guard<std::mutex> lk(g_acall_mu);
    std::string out = "[";
    bool first = true;
    for (auto &kv : g_acalls) {
        AsyncCall *job = kv.second;
        long long end = job->state == 0 ? acall_now_ms() : job->finished_ms;
        out += first ? "" : ",";
        first = false;
        out += "{\"callId\":" + std::to_string(job->id) +
               ",\"state\":\"" + acall_state_name(job->state) + "\"" +
               ",\"elapsedMs\":" + std::to_string(end - job->started_ms) +
               ",\"target\":\"" + json_escape(job->cls + "#" + job->method) + "\"}";
    }
    out += "]";
    return strdup(out.c_str());
}
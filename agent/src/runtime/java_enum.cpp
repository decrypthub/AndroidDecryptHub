// Lightweight live-class introspection for MCP: class metadata, constructors, overloaded
// methods and fields. This is reflection-only; heavy analysis and indexing stay on the Host.
#include "java_enum.h"
#include "jni.h"

#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#define TAG "ADH_JAVA_ENUM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
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
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
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
        if (env->ExceptionCheck()) env->ExceptionClear();
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
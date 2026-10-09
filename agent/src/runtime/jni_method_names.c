// jmethodID -> "<class>#<name><signature>" resolution for the JNIEnv Call* hooks.
//
// JNI has no reverse mapping from a jmethodID, and the ArtMethod/DexFile layout differs per
// API level (and is stripped on some ROMs), so this resolves through reflection instead: walk
// the receiver's class chain, build each member's JNI signature, and compare the jmethodID that
// GetMethodID/GetStaticMethodID returns with the one the target actually passed. First match
// wins, overloads disambiguate by signature.
//
// Cost control (this runs on target threads):
//   * a fixed-size, lock-free, mid-keyed cache makes repeated calls O(1);
//   * reflective scans are capped per process (ADH_METHOD_LOOKUPS); past that we return a
//     partial label ("?#mid") so the caller still emits something correlatable;
//   * callers only ask while they are still under their own event budget.

#include "jni_method_names.h"

#include "../bootstrap/agent_internal.h"
#include "jni.h"
#include "jni_env_hooks.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ADH_METHOD_CACHE 64
#define ADH_METHOD_LOOKUPS 512     // hard cap on reflective scans per process
#define ADH_METHOD_DEPTH 8         // superclass levels walked
#define ADH_METHOD_MEMBERS 192     // members inspected per class

struct MethodCacheEntry {
    void *mid;
    char label[224];
    char sig[192];
};

static struct MethodCacheEntry g_method_cache[ADH_METHOD_CACHE];
static unsigned int g_method_lookups = 0;
static pthread_mutex_t g_method_name_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned int cache_index(void *mid) {
    return (unsigned int)(((uintptr_t)mid >> 4) % ADH_METHOD_CACHE);
}

static void cache_store(void *mid, const char *label, const char *sig) {
    unsigned int i = cache_index(mid);
    struct MethodCacheEntry *e = &g_method_cache[i];
    // Lock-free-ish publish: fill the payload first, then the key. A racing reader either
    // misses (key not yet set) or reads a complete entry.
    __atomic_store_n(&e->mid, NULL, __ATOMIC_RELEASE);
    snprintf(e->label, sizeof(e->label), "%s", label);
    snprintf(e->sig, sizeof(e->sig), "%s", sig);
    __atomic_store_n(&e->mid, mid, __ATOMIC_RELEASE);
}

// Write the JNI type descriptor of one reflected Class ("I", "Ljava/lang/String;", "[B", ...).
static void class_descriptor(JNIEnv *env, jclass cls, char *out, size_t out_size) {
    out[0] = 0;
    if (!cls) { snprintf(out, out_size, "Ljava/lang/Object;"); return; }
    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    jmethodID get_name = class_class
        ? (*env)->GetMethodID(env, class_class, "getName", "()Ljava/lang/String;") : NULL;
    jstring name = get_name ? (jstring)(*env)->CallObjectMethod(env, cls, get_name) : NULL;
    char dotted[160] = "";
    if (name) {
        const char *chars = (*env)->GetStringUTFChars(env, name, NULL);
        if (chars) {
            snprintf(dotted, sizeof(dotted), "%s", chars);
            (*env)->ReleaseStringUTFChars(env, name, chars);
        }
        (*env)->DeleteLocalRef(env, name);
    }
    if (dotted[0] == 0) { snprintf(out, out_size, "Ljava/lang/Object;"); return; }
    static const struct { const char *name; const char *desc; } prims[] = {
        { "void", "V" }, { "boolean", "Z" }, { "byte", "B" }, { "char", "C" }, { "short", "S" },
        { "int", "I" }, { "long", "J" }, { "float", "F" }, { "double", "D" }, { NULL, NULL },
    };
    for (int i = 0; prims[i].name; i++) {
        if (strcmp(dotted, prims[i].name) == 0) { snprintf(out, out_size, "%s", prims[i].desc); return; }
    }
    if (dotted[0] == '[') {   // array: dots become slashes
        size_t w = 0;
        for (size_t i = 0; dotted[i] && w + 1 < out_size; i++) out[w++] = dotted[i] == '.' ? '/' : dotted[i];
        out[w] = 0;
        return;
    }
    size_t w = 0;
    out[w++] = 'L';
    for (size_t i = 0; dotted[i] && w + 2 < out_size; i++) out[w++] = dotted[i] == '.' ? '/' : dotted[i];
    out[w++] = ';';
    out[w] = 0;
}

// Build "(params)return" for the member whose parameter/return types live in a Class[].
static void build_signature(JNIEnv *env, jobjectArray param_types, jclass return_type,
                            char *out, size_t out_size) {
    size_t w = 0;
    out[w++] = '(';
    out[w] = 0;
    jsize n = param_types ? (*env)->GetArrayLength(env, param_types) : 0;
    if (n > 32) n = 32;
    for (jsize i = 0; i < n; i++) {
        jclass pt = (jclass)(*env)->GetObjectArrayElement(env, param_types, i);
        char desc[96];
        class_descriptor(env, pt, desc, sizeof(desc));
        if (pt) (*env)->DeleteLocalRef(env, pt);
        size_t need = strlen(desc);
        if (w + need + 4 >= out_size) break;
        memcpy(out + w, desc, need);
        w += need;
        out[w] = 0;
    }
    char ret[96] = "V";
    if (return_type) class_descriptor(env, return_type, ret, sizeof(ret));
    snprintf(out + w, out_size > w ? out_size - w : 0, ")%s", ret);
}

// One pass over a class's declared methods (or constructors) looking for `mid`. The reflective
// accessors live on the MEMBER class (java.lang.reflect.Method / Constructor), not on
// java.lang.Class - resolving them on the wrong class throws NoSuchMethodError, and continuing
// with that pending exception aborts the process under CheckJNI. Every step therefore clears
// its own exception and bails out instead of running on with one pending.
static int scan_members(JNIEnv *env, jclass cls, int kind, jmethodID mid,
                        char *label, size_t label_size, char *sig_out, size_t sig_size) {
    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    if (!class_class) { adh_jni_exception_clear(env); return 0; }
    const char *member_type = (kind == ADH_MEMBER_CTOR) ? "java/lang/reflect/Constructor"
                                                         : "java/lang/reflect/Method";
    jmethodID get_members = (kind == ADH_MEMBER_CTOR)
        ? (*env)->GetMethodID(env, class_class, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;")
        : (*env)->GetMethodID(env, class_class, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
    if (adh_jni_exception_check(env) || !get_members) { adh_jni_exception_clear(env); return 0; }
    jclass member_class = (*env)->FindClass(env, member_type);
    jmethodID get_param_types = member_class
        ? (*env)->GetMethodID(env, member_class, "getParameterTypes", "()[Ljava/lang/Class;") : NULL;
    jmethodID get_name = (kind != ADH_MEMBER_CTOR && member_class)
        ? (*env)->GetMethodID(env, member_class, "getName", "()Ljava/lang/String;") : NULL;
    jmethodID get_return_type = (kind != ADH_MEMBER_CTOR && member_class)
        ? (*env)->GetMethodID(env, member_class, "getReturnType", "()Ljava/lang/Class;") : NULL;
    jmethodID get_declaring = (kind == ADH_MEMBER_CTOR && member_class)
        ? (*env)->GetMethodID(env, member_class, "getDeclaringClass", "()Ljava/lang/Class;") : NULL;
    if (adh_jni_exception_check(env) || !get_param_types ||
        (kind != ADH_MEMBER_CTOR && (!get_name || !get_return_type)) ||
        (kind == ADH_MEMBER_CTOR && !get_declaring)) {
        adh_jni_exception_clear(env);
        return 0;
    }

    jobjectArray members = (jobjectArray)(*env)->CallObjectMethod(env, cls, get_members);
    if (adh_jni_exception_check(env) || !members) { adh_jni_exception_clear(env); return 0; }
    jsize count = (*env)->GetArrayLength(env, members);
    if (count > ADH_METHOD_MEMBERS) count = ADH_METHOD_MEMBERS;
    int found = 0;
    for (jsize i = 0; i < count && !found; i++) {
        jobject member = (*env)->GetObjectArrayElement(env, members, i);
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); continue; }
        if (!member) continue;
        char name[128] = "<init>";
        if (kind != ADH_MEMBER_CTOR) {
            jstring jname = (jstring)(*env)->CallObjectMethod(env, member, get_name);
            if (adh_jni_exception_check(env)) {
                adh_jni_exception_clear(env);
                (*env)->DeleteLocalRef(env, member);
                continue;
            }
            if (jname) {
                const char *chars = (*env)->GetStringUTFChars(env, jname, NULL);
                if (chars) {
                    snprintf(name, sizeof(name), "%s", chars);
                    (*env)->ReleaseStringUTFChars(env, jname, chars);
                }
                (*env)->DeleteLocalRef(env, jname);
            }
        }
        jobjectArray params = (jobjectArray)(*env)->CallObjectMethod(env, member, get_param_types);
        jclass return_type = NULL;
        if (kind != ADH_MEMBER_CTOR) {
            return_type = (jclass)(*env)->CallObjectMethod(env, member, get_return_type);
        }
        if (adh_jni_exception_check(env)) {
            adh_jni_exception_clear(env);
            if (params) (*env)->DeleteLocalRef(env, params);
            if (return_type) (*env)->DeleteLocalRef(env, return_type);
            (*env)->DeleteLocalRef(env, member);
            continue;
        }
        char sig[192];
        build_signature(env, params, return_type, sig, sizeof(sig));
        if (params) (*env)->DeleteLocalRef(env, params);
        if (return_type) (*env)->DeleteLocalRef(env, return_type);
        if (adh_jni_exception_check(env)) {   // abstract/native oddities: skip this member
            adh_jni_exception_clear(env);
            (*env)->DeleteLocalRef(env, member);
            continue;
        }
        jmethodID candidate = NULL;
        if (kind == ADH_MEMBER_CTOR) {
            jclass declaring = (jclass)(*env)->CallObjectMethod(env, member, get_declaring);
            if (!adh_jni_exception_check(env) && declaring) {
                candidate = (*env)->GetMethodID(env, declaring, "<init>", sig);
            }
            if (declaring) (*env)->DeleteLocalRef(env, declaring);
        } else if (kind == ADH_MEMBER_STATIC) {
            candidate = (*env)->GetStaticMethodID(env, cls, name, sig);
        } else {
            candidate = (*env)->GetMethodID(env, cls, name, sig);
        }
        // A lookup for a member of the other staticness throws; that is expected and must not
        // leak into the next iteration (CheckJNI aborts on JNI calls with a pending exception).
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        if (candidate == mid) {
            char cls_name[192] = "";
            adh_jni_class_name(env, cls, cls_name, sizeof(cls_name));
            snprintf(label, label_size, "%s#%s%s", cls_name[0] ? cls_name : "?", name, sig);
            snprintf(sig_out, sig_size, "%s", sig);
            found = 1;
        }
        (*env)->DeleteLocalRef(env, member);
    }
    (*env)->DeleteLocalRef(env, members);
    return found;
}
struct AdhMethodInfo *adh_jni_method_info(JNIEnv *env, jobject target, int kind, jmethodID mid,
                                          struct AdhMethodInfo *out) {
    if (!out) return NULL;
    out->ok = 0;
    out->label[0] = 0;
    out->sig[0] = 0;
    if (!env || !target || !mid) return out;

    struct MethodCacheEntry *e = &g_method_cache[cache_index(mid)];
    if (__atomic_load_n(&e->mid, __ATOMIC_ACQUIRE) == (void *)mid) {
        snprintf(out->label, sizeof(out->label), "%s", e->label);
        snprintf(out->sig, sizeof(out->sig), "%s", e->sig);
        out->ok = 1;
        return out;
    }
    if (__atomic_load_n(&g_method_lookups, __ATOMIC_RELAXED) >= ADH_METHOD_LOOKUPS) {
        snprintf(out->label, sizeof(out->label), "?#mid=0x%llx", (unsigned long long)(uintptr_t)mid);
        return out;
    }
    if (pthread_mutex_trylock(&g_method_name_lock) != 0) {   // never block a target thread
        snprintf(out->label, sizeof(out->label), "?#mid=0x%llx", (unsigned long long)(uintptr_t)mid);
        return out;
    }
    __atomic_add_fetch(&g_method_lookups, 1, __ATOMIC_RELAXED);
    if ((*env)->PushLocalFrame(env, 64) == 0) {
        jclass cls = (kind == ADH_MEMBER_INSTANCE) ? (*env)->GetObjectClass(env, target) : (jclass)target;
        char label[224] = "", sig[192] = "";
        for (int depth = 0; cls && depth < ADH_METHOD_DEPTH && !label[0]; depth++) {
            if (scan_members(env, cls, kind, mid, label, sizeof(label), sig, sizeof(sig))) break;
            if (kind == ADH_MEMBER_CTOR) break;      // constructors are not inherited
            jclass class_class = (*env)->FindClass(env, "java/lang/Class");
            jmethodID get_super = class_class
                ? (*env)->GetMethodID(env, class_class, "getSuperclass", "()Ljava/lang/Class;") : NULL;
            jclass super = get_super ? (jclass)(*env)->CallObjectMethod(env, cls, get_super) : NULL;
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            cls = super;
        }
        if (label[0]) {
            snprintf(out->label, sizeof(out->label), "%s", label);
            snprintf(out->sig, sizeof(out->sig), "%s", sig);
            out->ok = 1;
            cache_store(mid, label, sig);
        } else {
            snprintf(out->label, sizeof(out->label), "?#mid=0x%llx", (unsigned long long)(uintptr_t)mid);
        }
        (*env)->PopLocalFrame(env, NULL);
    }
    pthread_mutex_unlock(&g_method_name_lock);
    return out;
}
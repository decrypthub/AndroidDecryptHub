#include "inspection.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <pthread.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "jni.h"
#include "jni_env_hooks.h"

// Resolve a live object through a caller-supplied static field and enumerate its
// declared fields without embedding target class knowledge in the agent.
// getDeclaredField only sees the class it is called on, so an INHERITED holder/target field used to
// be reported as "not found" - a usability failure, not a missing feature: the Java-side resolver
// already walks the superclass chain. Walk it here too (Object.getSuperclass() == NULL ends the loop).
static jobject adh_find_field_walk(JNIEnv *env, jmethodID get_declared_field, jmethodID get_superclass,
                                   jclass start, const char *name) {
    jclass cur = start;
    while (cur) {
        jobject f = (*env)->CallObjectMethod(env, cur, get_declared_field, (*env)->NewStringUTF(env, name));
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); f = NULL; }
        if (f) return f;
        cur = (*env)->CallObjectMethod(env, cur, get_superclass);
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); cur = NULL; }
    }
    return NULL;
}

void adh_cmd_object_inspect(int fd, const char *id, const char *class_name,
                            const char *field_name) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = adh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 256);

    size_t cap = 1 << 14; char *out = malloc(cap);
    int ok = 0; char err[128] = ""; char obj_class[160] = ""; int nfields = 0;
    char *recs = malloc(1 << 14); if (recs) recs[0] = 0; size_t rlen = 0, rcap = 1 << 14;   // room for the declaring-class field

    jclass cls_class = (*env)->FindClass(env, "java/lang/Class");
    jclass field_class = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jmethodID get_field = (*env)->GetMethodID(env, cls_class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID get_fields = (*env)->GetMethodID(env, cls_class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
    jmethodID inspect_get_superclass = (*env)->GetMethodID(env, cls_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID get_name = (*env)->GetMethodID(env, cls_class, "getName", "()Ljava/lang/String;");
    jmethodID set_accessible = (*env)->GetMethodID(env, field_class, "setAccessible", "(Z)V");
    jmethodID field_get = (*env)->GetMethodID(env, field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID field_get_name = (*env)->GetMethodID(env, field_class, "getName", "()Ljava/lang/String;");
    jmethodID value_of = (*env)->GetStaticMethodID(env, str_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = adh_jni_load_app_class(env, class_name);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }

    jstring field_name_value = (*env)->NewStringUTF(env, field_name);
    (void)field_name_value;
    jobject field_obj = adh_find_field_walk(env, get_field, inspect_get_superclass, target, field_name);
    if (!field_obj) { strncpy(err, "field not found (searched the superclass chain)", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, field_obj, set_accessible, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, field_obj, field_get, NULL);
    if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); strncpy(err, "field.get failed (not static?)", sizeof(err)-1); goto done; }
    if (!obj) { strncpy(err, "field value is null", sizeof(err)-1); goto done; }

    jclass object_class = (*env)->GetObjectClass(env, obj);
    jstring object_class_name = (jstring)(*env)->CallObjectMethod(env, object_class, get_name);
    if (object_class_name) { const char *s = (*env)->GetStringUTFChars(env, object_class_name, NULL); if (s) { strncpy(obj_class, s, sizeof(obj_class)-1); (*env)->ReleaseStringUTFChars(env, object_class_name, s); } }

    // Walk the runtime class AND its superclasses: an inherited field must show up here, otherwise
    // the read path cannot confirm a write to it. Each record names its declaring class.
    for (jclass walker = object_class; walker && recs; ) {
    jstring walker_name = (jstring)(*env)->CallObjectMethod(env, walker, get_name);
    char walker_buf[160] = "";
    if (walker_name) { const char *c = (*env)->GetStringUTFChars(env, walker_name, NULL); if (c) { strncpy(walker_buf, c, sizeof(walker_buf)-1); (*env)->ReleaseStringUTFChars(env, walker_name, c); } }
    jobjectArray fields = (jobjectArray)(*env)->CallObjectMethod(env, walker, get_fields);
    jsize field_count = fields ? (*env)->GetArrayLength(env, fields) : 0;
    for (jsize i = 0; i < field_count && recs; i++) {
        jobject field = (*env)->GetObjectArrayElement(env, fields, i);
        (*env)->CallVoidMethod(env, field, set_accessible, JNI_TRUE);
        jstring name = (jstring)(*env)->CallObjectMethod(env, field, field_get_name);
        jobject value = (*env)->CallObjectMethod(env, field, field_get, obj);
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        jstring value_string = (jstring)(*env)->CallStaticObjectMethod(env, str_class, value_of, value);
        char name_buf[96] = "", value_buf[300] = "";
        if (name) { const char *s = (*env)->GetStringUTFChars(env, name, NULL); if (s) { strncpy(name_buf, s, sizeof(name_buf)-1); (*env)->ReleaseStringUTFChars(env, name, s); } }
        if (value_string) { const char *s = (*env)->GetStringUTFChars(env, value_string, NULL); if (s) { strncpy(value_buf, s, sizeof(value_buf)-1); (*env)->ReleaseStringUTFChars(env, value_string, s); } }
        char namej[120], valuej[600]; json_escape(name_buf, namej, sizeof(namej)); json_escape(value_buf, valuej, sizeof(valuej));
        char walkerj[200]; json_escape(walker_buf, walkerj, sizeof(walkerj));
        char rec[900]; int written = snprintf(rec, sizeof(rec), "%s{\"name\":\"%s\",\"value\":\"%s\",\"class\":\"%s\"}", nfields ? "," : "", namej, valuej, walkerj);
        if (written > 0 && rlen + (size_t)written + 1 < rcap) { memcpy(recs + rlen, rec, written); rlen += written; recs[rlen] = 0; nfields++; }
        (*env)->DeleteLocalRef(env, field);
    }
    walker = (*env)->CallObjectMethod(env, walker, inspect_get_superclass);
    if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); walker = NULL; }
    }
    ok = 1;

done:
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    (*env)->PopLocalFrame(env, NULL);
    adh_jni_detach(did);
    if (out) {
        char classj[160], errorj[160]; json_escape(obj_class, classj, sizeof(classj)); json_escape(err, errorj, sizeof(errorj));
        if (ok) snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":true,\"objectClass\":\"%s\",\"fieldCount\":%d,\"fields\":[%s]}\n", idj, classj, nfields, recs ? recs : "");
        else snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"%s\"}\n", idj, errorj);
        send_line(fd, out);
        free(out);
    }
    free(recs);
    LOGI("object_inspect: %s.%s -> %s fields=%d ok=%d", class_name, field_name, obj_class, nfields, ok);
}

// Invoke only a caller-selected no-arg method on the object reached through the same
// static-field path. Policy and confirmation stay with the Host ADH Daemon.
void adh_cmd_object_invoke(int fd, const char *id, const char *class_name,
                           const char *field_name, const char *method_name) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = adh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 128);
    int ok = 0; char err[128] = "", result[400] = "";

    jclass cls_class = (*env)->FindClass(env, "java/lang/Class");
    jclass field_class = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass method_class = (*env)->FindClass(env, "java/lang/reflect/Method");
    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jmethodID get_field = (*env)->GetMethodID(env, cls_class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID get_method = (*env)->GetMethodID(env, cls_class, "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    jmethodID invoke_get_superclass = (*env)->GetMethodID(env, cls_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID set_accessible = (*env)->GetMethodID(env, field_class, "setAccessible", "(Z)V");
    jmethodID field_get = (*env)->GetMethodID(env, field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID invoke = (*env)->GetMethodID(env, method_class, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID value_of = (*env)->GetStaticMethodID(env, str_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = adh_jni_load_app_class(env, class_name);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }
    jobject field_obj = adh_find_field_walk(env, get_field, invoke_get_superclass, target, field_name);
    if (!field_obj) { strncpy(err, "field not found (searched the superclass chain)", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, field_obj, set_accessible, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, field_obj, field_get, NULL);
    if (!obj || adh_jni_exception_check(env)) { adh_jni_exception_clear(env); strncpy(err, "field value null", sizeof(err)-1); goto done; }

    jclass object_class = (*env)->GetObjectClass(env, obj);
    jobject method = (*env)->CallObjectMethod(env, object_class, get_method, (*env)->NewStringUTF(env, method_name), NULL);
    if (!method || adh_jni_exception_check(env)) { adh_jni_exception_clear(env); strncpy(err, "method not found (no-arg only)", sizeof(err)-1); goto done; }
    jobject ret = (*env)->CallObjectMethod(env, method, invoke, obj, NULL);
    if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); strncpy(err, "invoke threw", sizeof(err)-1); goto done; }
    jstring value_string = (jstring)(*env)->CallStaticObjectMethod(env, str_class, value_of, ret);
    if (value_string) { const char *s = (*env)->GetStringUTFChars(env, value_string, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, value_string, s); } }
    ok = 1;

done:
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    (*env)->PopLocalFrame(env, NULL);
    adh_jni_detach(did);
    char resultj[500], errorj[160]; json_escape(result, resultj, sizeof(resultj)); json_escape(err, errorj, sizeof(errorj));
    char out[800];
    if (ok) snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":true,\"result\":\"%s\"}\n", idj, resultj);
    else snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"%s\"}\n", idj, errorj);
    send_line(fd, out);
    LOGI("object_invoke: %s.%s.%s() -> %s ok=%d", class_name, field_name, method_name, result, ok);
}

// Write one field of a live object: the write counterpart of object_inspect. `field` names the STATIC
// holder that carries the object (same convention as inspect/invoke), `target_field` is the field on
// that object to patch, and the value is coerced by the FIELD declared type. The reply carries
// before/after so the caller sees the effect and can put it back - flipping a flag on a live object
// (isRooted, debugChecked, a key blob) is the whole point.
// Strict numeric parses: the WHOLE string must be a number (no trailing junk, no ERANGE, finite).
// strtol with a NULL endptr - what the first version used - turns a typo like "abc" into 0 while the
// call still reports ok:true with a convincing before/after. Writing a wrong value into a live target
// silently is exactly what this tool must never do.
static int adh_parse_i64_strict(const char *v, long long *out) {
    if (!v || !v[0]) return 0;
    errno = 0;
    char *end = NULL;
    long long x = strtoll(v, &end, 0);
    if (errno != 0 || end == v || (end && *end != '\0')) return 0;
    *out = x;
    return 1;
}

static int adh_parse_double_strict(const char *v, double *out) {
    if (!v || !v[0]) return 0;
    errno = 0;
    char *end = NULL;
    double x = strtod(v, &end);
    if (errno != 0 || end == v || (end && *end != '\0') || !isfinite(x)) return 0;
    *out = x;
    return 1;
}

static int adh_parse_bool_value(const char *v, int *out) {
    if (!v) return 0;
    if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0) { *out = 1; return 1; }
    if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0) { *out = 0; return 1; }
    return 0;
}

static void adh_object_value_to_str(JNIEnv *env, jclass str_class, jobject value, jmethodID value_of,
                                    char *out, size_t out_size) {
    out[0] = 0;
    if (value_of && str_class) {
        jstring s = (jstring)(*env)->CallStaticObjectMethod(env, str_class, value_of, value);
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); }
        if (s) {
            const char *c = (*env)->GetStringUTFChars(env, s, NULL);
            if (c) { snprintf(out, out_size, "%s", c); (*env)->ReleaseStringUTFChars(env, s, c); }
        }
    }
    if (!out[0]) snprintf(out, out_size, "%s", value ? "<object>" : "null");
}

void adh_cmd_object_set(int fd, const char *id, const char *class_name, const char *holder_field,
                        const char *target_field, const char *value) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = adh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_set\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 128);
    int ok = 0; char err[200] = "", before[300] = "", after[300] = "", type_name[96] = "", obj_class_name[160] = "";

    jclass cls_class = (*env)->FindClass(env, "java/lang/Class");
    jclass field_class = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jmethodID get_declared_field = (*env)->GetMethodID(env, cls_class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID get_superclass = (*env)->GetMethodID(env, cls_class, "getSuperclass", "()Ljava/lang/Class;");
    jmethodID get_name = (*env)->GetMethodID(env, cls_class, "getName", "()Ljava/lang/String;");
    jmethodID field_get_type = (*env)->GetMethodID(env, field_class, "getType", "()Ljava/lang/Class;");
    jmethodID set_accessible = (*env)->GetMethodID(env, field_class, "setAccessible", "(Z)V");
    jmethodID field_get = (*env)->GetMethodID(env, field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID set_boolean = (*env)->GetMethodID(env, field_class, "setBoolean", "(Ljava/lang/Object;Z)V");
    jmethodID set_int = (*env)->GetMethodID(env, field_class, "setInt", "(Ljava/lang/Object;I)V");
    jmethodID set_long = (*env)->GetMethodID(env, field_class, "setLong", "(Ljava/lang/Object;J)V");
    jmethodID set_float = (*env)->GetMethodID(env, field_class, "setFloat", "(Ljava/lang/Object;F)V");
    jmethodID set_double = (*env)->GetMethodID(env, field_class, "setDouble", "(Ljava/lang/Object;D)V");
    jmethodID field_set = (*env)->GetMethodID(env, field_class, "set", "(Ljava/lang/Object;Ljava/lang/Object;)V");
    jmethodID value_of = (*env)->GetStaticMethodID(env, str_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
    jmethodID get_modifiers = (*env)->GetMethodID(env, field_class, "getModifiers", "()I");
    jclass mod_class = (*env)->FindClass(env, "java/lang/reflect/Modifier");
    jmethodID modifier_is_final = (*env)->GetStaticMethodID(env, mod_class, "isFinal", "(I)Z");

    if (!value || !value[0]) { snprintf(err, sizeof(err), "need value"); goto done; }
    jclass target = adh_jni_load_app_class(env, class_name);
    if (!target) { snprintf(err, sizeof(err), "class not found"); goto done; }
    jobject holder = adh_find_field_walk(env, get_declared_field, get_superclass, target, holder_field);
    if (!holder) { snprintf(err, sizeof(err), "holder field not found (searched the superclass chain)"); goto done; }
    (*env)->CallVoidMethod(env, holder, set_accessible, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, holder, field_get, NULL);
    if (!obj || adh_jni_exception_check(env)) { adh_jni_exception_clear(env); snprintf(err, sizeof(err), "holder field is null (nothing to write to)"); goto done; }

    jclass object_class = (*env)->GetObjectClass(env, obj);
    {
        jstring cn = (jstring)(*env)->CallObjectMethod(env, object_class, get_name);
        if (cn) { const char *c = (*env)->GetStringUTFChars(env, cn, NULL); if (c) { snprintf(obj_class_name, sizeof(obj_class_name), "%s", c); (*env)->ReleaseStringUTFChars(env, cn, c); } }
    }
    jobject field = adh_find_field_walk(env, get_declared_field, get_superclass, object_class, target_field);
    if (!field) { snprintf(err, sizeof(err), "target field not found on %s (searched the superclass chain)", obj_class_name); goto done; }
    (*env)->CallVoidMethod(env, field, set_accessible, JNI_TRUE);

    jobject field_type = (*env)->CallObjectMethod(env, field, field_get_type);
    {
        jstring tn = (jstring)(*env)->CallObjectMethod(env, field_type, get_name);
        if (tn) { const char *c = (*env)->GetStringUTFChars(env, tn, NULL); if (c) { snprintf(type_name, sizeof(type_name), "%s", c); (*env)->ReleaseStringUTFChars(env, tn, c); } }
    }
    // Distinguish "cannot be written at all" (final) from "the value was rejected": the first
    // version lumped both into one "probably final" message.
    {
        jint mods = (*env)->CallIntMethod(env, field, get_modifiers);
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        if ((*env)->CallStaticBooleanMethod(env, mod_class, modifier_is_final, mods)) {
            snprintf(err, sizeof(err), "field '%s' is final (Kotlin val / read-only): reflection cannot write it here", target_field);
            goto done;
        }
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    }
    jobject old_value = (*env)->CallObjectMethod(env, field, field_get, obj);
    if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); snprintf(err, sizeof(err), "could not read the old value"); goto done; }
    adh_object_value_to_str(env, str_class, old_value, value_of, before, sizeof(before));

    if (strcmp(type_name, "boolean") == 0) {
        int b = 0;
        if (!adh_parse_bool_value(value, &b)) { snprintf(err, sizeof(err), "boolean field expects true/false/1/0, got '%s'", value); goto done; }
        (*env)->CallVoidMethod(env, field, set_boolean, obj, b ? JNI_TRUE : JNI_FALSE);
    } else if (strcmp(type_name, "int") == 0) {
        long long x = 0;
        if (!adh_parse_i64_strict(value, &x) || x < INT_MIN || x > INT_MAX) {
            snprintf(err, sizeof(err), "int field expects an integer in int range, got '%s'", value);
            goto done;
        }
        (*env)->CallVoidMethod(env, field, set_int, obj, (jint)x);
    } else if (strcmp(type_name, "long") == 0) {
        long long x = 0;
        if (!adh_parse_i64_strict(value, &x)) {
            snprintf(err, sizeof(err), "long field expects an integer, got '%s'", value);
            goto done;
        }
        (*env)->CallVoidMethod(env, field, set_long, obj, (jlong)x);
    } else if (strcmp(type_name, "float") == 0) {
        double x = 0;
        if (!adh_parse_double_strict(value, &x)) {
            snprintf(err, sizeof(err), "float field expects a finite number, got '%s'", value);
            goto done;
        }
        (*env)->CallVoidMethod(env, field, set_float, obj, (jfloat)x);
    } else if (strcmp(type_name, "double") == 0) {
        double x = 0;
        if (!adh_parse_double_strict(value, &x)) {
            snprintf(err, sizeof(err), "double field expects a finite number, got '%s'", value);
            goto done;
        }
        (*env)->CallVoidMethod(env, field, set_double, obj, (jdouble)x);
    } else if (strcmp(type_name, "java.lang.String") == 0) {
        (*env)->CallVoidMethod(env, field, field_set, obj, (*env)->NewStringUTF(env, value));
    } else {
        snprintf(err, sizeof(err), "unsupported field type '%s' (boolean/int/long/float/double/String)", type_name);
        goto done;
    }
    if (adh_jni_exception_check(env)) {
        adh_jni_exception_clear(env);
        // A final field (Kotlin val) lands here: report it as such instead of pretending it worked.
        snprintf(err, sizeof(err), "set failed - the value is not acceptable for %s (field %s)", type_name, target_field);
        goto done;
    }
    jobject new_value = (*env)->CallObjectMethod(env, field, field_get, obj);
    if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); snprintf(err, sizeof(err), "wrote the field but could not read it back"); goto done; }
    adh_object_value_to_str(env, str_class, new_value, value_of, after, sizeof(after));
    ok = 1;

done:
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    (*env)->PopLocalFrame(env, NULL);
    adh_jni_detach(did);
    char classj[200], fieldj[160], typej[140], beforej[500], afterj[500], errorj[240];
    json_escape(obj_class_name, classj, sizeof(classj));
    json_escape(target_field, fieldj, sizeof(fieldj));
    json_escape(type_name, typej, sizeof(typej));
    json_escape(before, beforej, sizeof(beforej));
    json_escape(after, afterj, sizeof(afterj));
    json_escape(err, errorj, sizeof(errorj));
    char out[1600];
    if (ok) {
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_set\",\"ok\":true,\"objectClass\":\"%s\","
                 "\"field\":\"%s\",\"type\":\"%s\",\"before\":\"%s\",\"after\":\"%s\"}\n",
                 idj, classj, fieldj, typej, beforej, afterj);
    } else {
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_set\",\"ok\":false,\"objectClass\":\"%s\","
                 "\"field\":\"%s\",\"type\":\"%s\",\"error\":\"%s\"}\n",
                 idj, classj, fieldj, typej, errorj);
    }
    send_line(fd, out);
    LOGI("object_set: %s.%s.%s = %s (%s -> %s) ok=%d", class_name, holder_field, target_field, value, before, after, ok);
}

// Runtime footprint. These are observation counters only: no hiding, no fake VMA
// names, no policy decisions. The baseline is captured when the agent is first
// entered (JNI_OnLoad or adh_agent_start), before any hook/trace command runs.
struct footprint_counts {
    int maps;
    int exec;
    int file_exec;
    int memfd_exec;
    int anon_exec;
    int anon_named_exec;
    int rwx;
    int agent_exec;
    int zygisk_exec;
    unsigned long long exec_bytes;
    unsigned long long memfd_exec_bytes;
    unsigned long long anon_exec_bytes;
    unsigned long long anon_named_exec_bytes;
};

static int footprint_scan(struct footprint_counts *c, int *module_count) {
    memset(c, 0, sizeof(*c));
    if (module_count) *module_count = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[1024];
    char last_module[600] = "";
    while (fgets(line, sizeof(line), maps)) {
        c->maps++;
        unsigned long long start = 0, end = 0, offset = 0, inode = 0;
        char perms[5] = {0}, dev[8] = {0}, path[600] = {0};
        int n = sscanf(line, "%llx-%llx %4s %llx %7s %llu %599[^\n]",
                       &start, &end, perms, &offset, dev, &inode, path);
        if (n < 6) continue;

        char *pth = path;
        while (*pth == ' ' || *pth == '\t') pth++;

        if (module_count && pth[0] == '/' && strcmp(pth, last_module) != 0) {
            strncpy(last_module, pth, sizeof(last_module) - 1);
            last_module[sizeof(last_module) - 1] = 0;
            (*module_count)++;
        }
        if (strlen(perms) < 4 || perms[2] != 'x') continue;

        unsigned long long bytes = end > start ? end - start : 0;
        c->exec++;
        c->exec_bytes += bytes;
        if (perms[1] == 'w') c->rwx++;

        if (pth[0] == '/') {
            if (strstr(pth, "/memfd:")) {
                c->memfd_exec++;
                c->memfd_exec_bytes += bytes;
            } else {
                c->file_exec++;
            }
        } else if (strncmp(pth, "[anon:", 6) == 0) {
            c->anon_named_exec++;
            c->anon_named_exec_bytes += bytes;
        } else if (pth[0] == 0 && strcmp(dev, "00:00") == 0 && inode == 0) {
            c->anon_exec++;
            c->anon_exec_bytes += bytes;
        }

        // Use the name WE are actually mapped under (dladdr): a memfd-loaded agent shows up as
        // "/memfd:jit-cache (deleted)", and a hardcoded "libadh_agent.so" would report 0 for it -
        // which would look like "no agent footprint" exactly when the agent is hidden.
        // Count OUR mapping by address range: the memfd name we load under ("jit-cache") is shared
        // with ART's own JIT caches, so a name match would report the target's own pages as ours.
        {
            static unsigned long long self_start, self_end;
            static int self_resolved = 0;
            if (!self_resolved) {
                // Cache only a SUCCESSFUL resolution: caching a transient failure would report
                // "no agent footprint" for the rest of the process lifetime.
                unsigned long long s = 0, e = 0;
                if (adh_self_image_bounds(&s, &e)) { self_start = s; self_end = e; self_resolved = 1; }
            }
            if (self_start && start >= self_start && start < self_end) c->agent_exec++;
        }
        if (strstr(pth, "/zygisk/") || strstr(pth, "libzygisk.so") || strstr(pth, "zygisk_"))
            c->zygisk_exec++;
    }
    fclose(maps);
    return 1;
}

static struct footprint_counts g_footprint_baseline;
static int g_footprint_baseline_valid = 0;
static pthread_once_t g_footprint_once = PTHREAD_ONCE_INIT;

static void footprint_capture_baseline_once(void) {
    g_footprint_baseline_valid = footprint_scan(&g_footprint_baseline, NULL);
}

void adh_footprint_capture_baseline(void) {
    pthread_once(&g_footprint_once, footprint_capture_baseline_once);
}

// Report observed runtime constraints instead of claiming a backend is available from
// compile-time configuration alone. The footprint block exposes both the bootstrap
// baseline and the current counts; a positive anonExec delta means the process gained a
// true anonymous executable mapping after bootstrap (correlate with the command that ran;
// Dobby/QBDI are known producers, ART JIT/other runtimes may also add one).
void adh_cmd_compat_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    adh_footprint_capture_baseline();

    int tracer = -1, seccomp = -1;
    FILE *status = fopen("/proc/self/status", "r");
    if (status) { char line[256];
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "TracerPid:", 10) == 0) tracer = atoi(line + 10);
            else if (strncmp(line, "Seccomp:", 8) == 0) seccomp = atoi(line + 8);
        }
        fclose(status);
    }
    int got_ok = (adh_resolve_sym("libc.so", "access") != NULL);
    int jni_ok = adh_jni_vm_available();

    struct footprint_counts cur;
    int module_count = 0;
    int maps_read_ok = footprint_scan(&cur, &module_count);
    int bv = g_footprint_baseline_valid;
    const struct footprint_counts *base = bv ? &g_footprint_baseline : NULL;

    // Effective read capability. "Can we read target memory" stopped being the same question as
    // "can we open /proc/self/mem" once a target can be non-dumpable: the shared backend then reads
    // directly instead. Both the answer and the route are reported, so a silent downgrade cannot
    // hide behind a single boolean.
    int memread_ok = 0;
    { unsigned char bytes[4];
      memread_ok = (adh_mem_pread(bytes, 4, (unsigned long long)(uintptr_t)&adh_cmd_compat_probe) == 4); }
    const char *mem_backend = adh_mem_backend_name();
    int mem_open_errno = adh_mem_open_errno();
    int jni_symbol = adh_jni_libart_symbol_resolves();
    void *dlprobe = dlopen("libcrypto.so", RTLD_NOW);
    int dlopen_blocked = (dlprobe == NULL);
    if (dlprobe) dlclose(dlprobe);

    char out[3072];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"compat_probe\",\"ok\":true,"
        "\"agentVer\":\"%s\","
        "\"tracerPid\":%d,\"seccomp\":%d,\"backends\":{\"gotHook\":%s,\"jniReflect\":%s,\"artDexCapture\":%s,\"memRead\":%s},"
        "\"memBackend\":\"%s\",\"memOpenErrno\":%d,\"libartJniGetVms\":%s,"
        "\"mapsReadOk\":%s,\"mapsCount\":%d,\"moduleMappings\":%d,"
        "\"execMappings\":%d,\"fileExecMappings\":%d,\"memfdExecMappings\":%d,"
        "\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"rwxMappings\":%d,"
        "\"execKiB\":%llu,\"memfdExecKiB\":%llu,\"anonExecKiB\":%llu,\"anonNamedExecKiB\":%llu,"
        "\"agentExecMappings\":%d,\"zygiskExecMappings\":%d,"
        "\"baselineValid\":%s,"
        "\"baseline\":{\"execMappings\":%d,\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"memfdExecMappings\":%d,\"rwxMappings\":%d,\"agentExecMappings\":%d,\"zygiskExecMappings\":%d},"
        "\"delta\":{\"execMappings\":%d,\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"memfdExecMappings\":%d,\"rwxMappings\":%d},"
        "\"dlopenSystemLibsBlocked\":%s}\n",
        idj, AGENT_VER, tracer, seccomp, got_ok ? "true" : "false", jni_ok ? "true" : "false",
        adh_jni_vm_available() ? "true" : "false", memread_ok ? "true" : "false",
        mem_backend, mem_open_errno, jni_symbol ? "true" : "false",
        maps_read_ok ? "true" : "false", cur.maps, module_count,
        cur.exec, cur.file_exec, cur.memfd_exec, cur.anon_exec, cur.anon_named_exec, cur.rwx,
        (unsigned long long)(cur.exec_bytes / 1024),
        (unsigned long long)(cur.memfd_exec_bytes / 1024),
        (unsigned long long)(cur.anon_exec_bytes / 1024),
        (unsigned long long)(cur.anon_named_exec_bytes / 1024),
        cur.agent_exec, cur.zygisk_exec,
        bv ? "true" : "false",
        bv ? base->exec : -1, bv ? base->anon_exec : -1, bv ? base->anon_named_exec : -1,
        bv ? base->memfd_exec : -1, bv ? base->rwx : -1,
        bv ? base->agent_exec : -1, bv ? base->zygisk_exec : -1,
        bv ? (cur.exec - base->exec) : 0,
        bv ? (cur.anon_exec - base->anon_exec) : 0,
        bv ? (cur.anon_named_exec - base->anon_named_exec) : 0,
        bv ? (cur.memfd_exec - base->memfd_exec) : 0,
        bv ? (cur.rwx - base->rwx) : 0,
        dlopen_blocked ? "true" : "false");
    send_line(fd, out);
    LOGI("compat_probe: tracer=%d seccomp=%d got=%d jni=%d exec=%d anon=%d rwx=%d",
         tracer, seccomp, got_ok, jni_ok, cur.exec, cur.anon_exec, cur.rwx);
}

// The JNI surface probe (jni_probe) is gone: its one assertion (the agent reads the SDK
// level through the app ClassLoader from a native thread) is covered by compat_probe's
// jni/jniReflect fields, and the java_call path proves the same ClassLoader reach.

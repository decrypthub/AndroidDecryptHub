#ifndef ADH_AGENT_RUNTIME_JNI_METHOD_NAMES_H
#define ADH_AGENT_RUNTIME_JNI_METHOD_NAMES_H

#include <jni.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// What kind of member a jmethodID/constructor belongs to.
enum {
    ADH_MEMBER_INSTANCE = 0,
    ADH_MEMBER_STATIC = 1,
    ADH_MEMBER_CTOR = 2,
};

struct AdhMethodInfo {
    int ok;              // 1 when label/signature were resolved
    char label[224];     // "<class>#<name><signature>", e.g. com.x.Foo#bar(Ljava/lang/String;I)
    char sig[192];       // "(Ljava/lang/String;I)V" — used to decode Call* arguments
};

// Resolve a jmethodID to its class/name/signature by comparing it against the reflected
// members of `target` (the receiver object, or the jclass for static calls / constructors).
// Reflection is needed because JNI exposes no reverse mapping from jmethodID.
//
// Bounded by design: a small positive cache keyed by jmethodID plus a hard cap on reflective
// scans per process (ADH_METHOD_LOOKUPS). Lookups are only worth doing while the caller is
// still emitting events, so callers gate on their own budget first. Returns info->ok.
struct AdhMethodInfo *adh_jni_method_info(JNIEnv *env, jobject target, int kind, jmethodID mid,
                                          struct AdhMethodInfo *out);

#ifdef __cplusplus
}
#endif

#endif
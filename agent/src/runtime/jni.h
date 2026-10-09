#ifndef ADH_AGENT_RUNTIME_JNI_H
#define ADH_AGENT_RUNTIME_JNI_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void adh_jni_set_vm(JavaVM *vm);
int adh_jni_vm_available(void);
JavaVM *adh_jni_get_vm(void);
// True when JNI_GetCreatedJavaVMs is resolvable out of the already-loaded libart.so. The fallback
// path only runs when no JavaVM was handed to us (i.e. a real injected target), so this is what
// makes that case diagnosable from outside.
int adh_jni_libart_symbol_resolves(void);
JNIEnv *adh_jni_attach(int *did_attach);
void adh_jni_detach(int did_attach);
jclass adh_jni_load_app_class(JNIEnv *env, const char *dotname);
jobject adh_jni_app_class_loader(JNIEnv *env);
// Resolve a jclass to its dotted name through reflection (Class.getName()). Used
// to make member-ID hook events self-describing; returns "" and clears pending
// exceptions on failure.
void adh_jni_class_name(JNIEnv *env, jclass clazz, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif

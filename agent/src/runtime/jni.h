#ifndef ADH_AGENT_RUNTIME_JNI_H
#define ADH_AGENT_RUNTIME_JNI_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void adh_jni_set_vm(JavaVM *vm);
int adh_jni_vm_available(void);
JNIEnv *adh_jni_attach(int *did_attach);
void adh_jni_detach(int did_attach);
jclass adh_jni_load_app_class(JNIEnv *env, const char *dotname);

#ifdef __cplusplus
}
#endif

#endif

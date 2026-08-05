#ifndef IDH_AGENT_RUNTIME_JNI_H
#define IDH_AGENT_RUNTIME_JNI_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void idh_jni_set_vm(JavaVM *vm);
int idh_jni_vm_available(void);
JNIEnv *idh_jni_attach(int *did_attach);
void idh_jni_detach(int did_attach);
jclass idh_jni_load_app_class(JNIEnv *env, const char *dotname);

#ifdef __cplusplus
}
#endif

#endif

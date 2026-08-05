#ifndef IDH_AGENT_CAPTURE_H
#define IDH_AGENT_CAPTURE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void idh_cmd_crypto_probe(int fd, const char *id);
void idh_cmd_net_hook_test(int fd, const char *id, const char *class_name);
void idh_cmd_file_probe(int fd, const char *id);
void idh_cmd_file_hook_test(int fd, const char *id, const char *module, const char *class_name);
void idh_cmd_flow_watch(int fd, const char *id, const char *class_name);
void idh_cmd_crypto_hook_test(int fd, const char *id, const char *class_name);
void idh_cmd_capture_start(int fd, const char *id, const char *crypto_module, const char *file_module, const char *sys_module);
void idh_cmd_capture_stop(int fd, const char *id);
void idh_cmd_capture_drain(int fd, const char *id);
void idh_cmd_detect_watch(int fd, const char *id, const char *module, const char *class_name);
void idh_cmd_inline_crypto_test(int fd, const char *id, const char *module, const char *symbol, const char *class_name, const char *method);
int idh_capture_register_reporter(JNIEnv *env, const char *report_class);

#ifdef __cplusplus
}
#endif

#endif

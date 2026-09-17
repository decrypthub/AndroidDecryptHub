#ifndef ADH_AGENT_CAPTURE_H
#define ADH_AGENT_CAPTURE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_crypto_probe(int fd, const char *id);
void adh_cmd_net_hook_test(int fd, const char *id, const char *class_name);
void adh_cmd_file_probe(int fd, const char *id);
void adh_cmd_file_hook_test(int fd, const char *id, const char *module, const char *class_name);
void adh_cmd_flow_watch(int fd, const char *id, const char *class_name);
void adh_cmd_crypto_hook_test(int fd, const char *id, const char *class_name);
void adh_cmd_capture_start(int fd, const char *id, const char *crypto_module, const char *file_module, const char *sys_module);
void adh_cmd_capture_stop(int fd, const char *id);
void adh_cmd_capture_drain(int fd, const char *id);
void adh_cmd_detect_watch(int fd, const char *id, const char *module, const char *class_name);
void adh_cmd_inline_crypto_test(int fd, const char *id, const char *module, const char *symbol, const char *class_name, const char *method);
int adh_capture_register_reporter(JNIEnv *env, const char *report_class);
// Push a bounded, target-generated text event (for example a Java hook callback) into the existing capture ring.
void adh_capture_push_text(const char *func, const char *text);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ADH_AGENT_CAPTURE_H
#define ADH_AGENT_CAPTURE_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_file_probe(int fd, const char *id);
void adh_cmd_capture_start(int fd, const char *id, const char *crypto_module, const char *file_module, const char *sys_module);
void adh_cmd_capture_stop(int fd, const char *id);
void adh_cmd_capture_drain(int fd, const char *id);
int adh_capture_register_reporter(JNIEnv *env, const char *report_class);
// Push a bounded, target-generated text event (for example a Java hook callback) into the existing capture ring.
void adh_capture_push_text(const char *func, const char *text);
// Per-package hook policy (which families the target's process is allowed to see installed).
// Applied by the NEXT install, whoever issues it: the agent has no module name of its own to arm
// with (see the note above adh_cmd_capture_start in capture.c).
void adh_capture_set_families(int digest, int hmac, int symmetric, int asymmetric, int tls, int aead);
void adh_capture_get_families(int *digest, int *hmac, int *symmetric, int *asymmetric, int *tls, int *aead);
// Java Cipher/Mac/MessageDigest/Signature hooks report through the same rich-capture records
// as a target-supplied nReport. Observe-only: the caller already ran the original method.
void adh_capture_java(JNIEnv *env, jstring algo, jstring op, jbyteArray key, jbyteArray iv, jbyteArray in, jbyteArray out);

#ifdef __cplusplus
}
#endif

#endif

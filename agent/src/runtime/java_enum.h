#ifndef ADH_AGENT_RUNTIME_JAVA_ENUM_H
#define ADH_AGENT_RUNTIME_JAVA_ENUM_H

#include <jni.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Enumerate a live Java class through reflection. On success returns 1 and stores a
// malloc-backed JSON object in *out_json (free with adh_java_enum_free). On failure
// returns 0 and writes a human-readable reason to error.
int adh_java_enum_json(JNIEnv *env, const char *class_name, char **out_json,
                       char *error, size_t error_size);
void adh_java_enum_free(char *json);

#ifdef __cplusplus
}
#endif

#endif
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
// Invoke a live Java method by reflection. params is a comma-separated parameter-type list;
// args_json is a JSON array of string/number/boolean/null values; field is required for an
// instance method and must name a static field holding the receiver object.
int adh_java_call_json(JNIEnv *env, const char *class_name, const char *method_name,
                       const char *params, const char *field_name, const char *args_json,
                       char **out_json, char *error, size_t error_size);

#ifdef __cplusplus
}
#endif

#endif
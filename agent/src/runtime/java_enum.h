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

// Detached call: run the same invocation on its own attached thread and return a job id (>0), or
// -1 with a reason. A target method that blocks then parks that thread instead of the command
// channel, so the session stays answerable. Poll it with adh_java_call_async_status.
int adh_java_call_async_start(const char *class_name, const char *method_name, const char *params,
                              const char *field_name, const char *args_json,
                              char *error, size_t error_size);
// JSON for one job ("running" | "done" | "failed", with call/error), or NULL if the id is unknown.
// Free with adh_java_enum_free. Safe to call repeatedly.
char *adh_java_call_async_status(int id);
// JSON array summarising every retained job (no results). Free with adh_java_enum_free.
char *adh_java_call_async_list(void);

#ifdef __cplusplus
}
#endif

#endif
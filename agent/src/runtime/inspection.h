#ifndef ADH_AGENT_RUNTIME_INSPECTION_H
#define ADH_AGENT_RUNTIME_INSPECTION_H

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_object_inspect(int fd, const char *id, const char *class_name,
                            const char *field_name);
void adh_cmd_object_invoke(int fd, const char *id, const char *class_name,
                           const char *field_name, const char *method_name);
void adh_footprint_capture_baseline(void);
void adh_cmd_compat_probe(int fd, const char *id);
void adh_cmd_jni_probe(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

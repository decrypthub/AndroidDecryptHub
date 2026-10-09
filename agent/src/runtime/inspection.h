#ifndef ADH_AGENT_RUNTIME_INSPECTION_H
#define ADH_AGENT_RUNTIME_INSPECTION_H

#ifdef __cplusplus
extern "C" {
#endif

// Write one field of a live object (the write counterpart of object_inspect): `field` names the
// STATIC holder that carries the object, `target_field` the field to patch; the value is coerced by
// the field declared type and the reply carries before/after.
void adh_cmd_object_set(int fd, const char *id, const char *class_name, const char *holder_field,
                        const char *target_field, const char *value);
void adh_cmd_object_inspect(int fd, const char *id, const char *class_name,
                            const char *field_name);
void adh_cmd_object_invoke(int fd, const char *id, const char *class_name,
                           const char *field_name, const char *method_name);
void adh_footprint_capture_baseline(void);
void adh_cmd_compat_probe(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

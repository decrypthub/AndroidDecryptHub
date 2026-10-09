#ifndef ADH_AGENT_RUNTIME_ACTIONS_H
#define ADH_AGENT_RUNTIME_ACTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_trigger(int fd, const char *id, const char *class_name, const char *method, int level);
void adh_cmd_load_so(int fd, const char *id, const char *path, const char *symbol);
void adh_cmd_native_call(int fd, const char *id, const char *module, const char *symbol,
                          const char *addr_hex, const char *args_csv);

#ifdef __cplusplus
}
#endif

#endif

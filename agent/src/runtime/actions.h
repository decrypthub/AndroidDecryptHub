#ifndef IDH_AGENT_RUNTIME_ACTIONS_H
#define IDH_AGENT_RUNTIME_ACTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

void idh_cmd_trigger(int fd, const char *id, const char *class_name, const char *method, int level);
void idh_cmd_load_so(int fd, const char *id, const char *path, const char *symbol);

#ifdef __cplusplus
}
#endif

#endif

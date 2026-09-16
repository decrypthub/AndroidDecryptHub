#ifndef ADH_AGENT_TRACE_COMMANDS_H
#define ADH_AGENT_TRACE_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_trace_run(int fd, const char *id, const char *symbol_library,
                       const char *symbol, const char *hook_module,
                       const char *class_name);
void adh_cmd_qbdi_trace(int fd, const char *id, const char *symbol_library,
                        const char *symbol);

#ifdef __cplusplus
}
#endif

#endif

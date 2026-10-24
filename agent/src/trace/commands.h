#ifndef ADH_AGENT_TRACE_COMMANDS_H
#define ADH_AGENT_TRACE_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

void adh_cmd_qbdi_trace(int fd, const char *id, const char *symbol_library,
                        const char *symbol, const char *args_csv, const char *addr_hex,
                        int paged, int budget, int time_ms, int capacity);
void adh_cmd_qbdi_read(int fd, const char *id, unsigned long long trace_id, int offset, int limit, int release);

#ifdef __cplusplus
}
#endif

#endif

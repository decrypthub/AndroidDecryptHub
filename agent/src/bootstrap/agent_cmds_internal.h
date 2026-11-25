#ifndef ADH_AGENT_CMDS_INTERNAL_H
#define ADH_AGENT_CMDS_INTERNAL_H

// Shared state between agent_main.c (lifecycle) and agent_cmds.c
// (report + command handlers + command loop).

extern const char *adh_early_status_json(void);
extern char g_entry[16];
extern char g_package[512];
extern char g_policy[64];
void report(int fd);
void command_loop(int fd);

#endif

#ifndef ADH_AGENT_SSL_BYPASS_H
#define ADH_AGENT_SSL_BYPASS_H

// Java trust-manager hooks. Not installed at inject time: LSPlant rewrites ART, and an app
// that already hooks ART GC dies in MarkCompact. Call adh_ssl_bypass_arm only when a session
// has asked for the bypass.

#ifdef __cplusplus
extern "C" {
#endif

void adh_ssl_bypass_set_enabled(int on);
void adh_ssl_bypass_arm(void);
int adh_ssl_bypass_finished(void);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ADH_AGENT_SSL_BYPASS_H
#define ADH_AGENT_SSL_BYPASS_H

// Java trust decisions for an injected process. The app being in the injection scope is the
// opt-in (the same gesture as enabling an LSPosed module for that app). It stays on.

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

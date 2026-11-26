#ifndef ADH_AGENT_JAVA_CRYPTO_H
#define ADH_AGENT_JAVA_CRYPTO_H

// Hook the JCA entry points (Cipher, Mac, MessageDigest, Signature) in an injected
// process and record algorithm, operation, key, iv, input and output. The original
// method still runs. Families the policy turned off are not installed.

#ifdef __cplusplus
extern "C" {
#endif

void adh_java_crypto_arm(void);
void adh_java_crypto_set_families(unsigned families);
int adh_java_crypto_stop(void); // 0 = all owned observation disabled and memo cleared
void adh_cmd_java_capture(int fd, const char *id, const char *request);
int adh_java_crypto_started(void);
int adh_java_crypto_finished(void);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ADH_AGENT_GOT_H
#define ADH_AGENT_GOT_H

#ifdef __cplusplus
extern "C" {
#endif

int adh_got_replace(const char *module_substr, void *orig, void *wrapper);
int adh_got_replace_by_name(const char *module_substr, const char *symbol, void *wrapper);
void *adh_resolve_sym(const char *module, const char *symbol);
void *adh_resolve_sym_prefix(const char *module, const char *prefix);
void adh_cmd_gothook_selftest(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

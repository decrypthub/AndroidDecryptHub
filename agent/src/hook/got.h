#ifndef IDH_AGENT_GOT_H
#define IDH_AGENT_GOT_H

#ifdef __cplusplus
extern "C" {
#endif

int idh_got_replace(const char *module_substr, void *orig, void *wrapper);
int idh_got_replace_by_name(const char *module_substr, const char *symbol, void *wrapper);
void *idh_resolve_sym(const char *module, const char *symbol);
void *idh_resolve_sym_prefix(const char *module, const char *prefix);
void idh_cmd_gothook_selftest(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

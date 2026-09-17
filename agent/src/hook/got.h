#ifndef ADH_AGENT_GOT_H
#define ADH_AGENT_GOT_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int adh_got_replace(const char *module_substr, void *orig, void *wrapper);
int adh_got_replace_by_name(const char *module_substr, const char *symbol, void *wrapper);
// Exact-module replacement that also returns the first slot address and its previous value.
// Returns the number of modules replaced; callers that need one unambiguous slot must
// treat any value other than 1 as an error.
int adh_got_replace_by_name_ex(const char *module_name, const char *symbol, void *wrapper,
                               void **slot_out, void **value_out);
void *adh_resolve_sym(const char *module, const char *symbol);
void *adh_resolve_sym_prefix(const char *module, const char *prefix);
// Find one relocation slot by symbol name and return both the slot address and its current
// resolved value. This works for imported symbols (e.g. open) even when the symbol is not
// defined by the module itself.
int adh_got_slot_value(const char *module, const char *symbol, void **slot_out, void **value_out);
// Enumerate relocation/GOT entries for one loaded module. filter may be empty/NULL to
// list all entries. Returns a malloc-backed JSON object through out_json; callers free it.
int adh_got_enum_json(const char *module, const char *filter, char **out_json,
                      char *error, size_t error_size);
int adh_addr_is_executable(void *addr);
void adh_cmd_gothook_selftest(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

#ifndef ADH_AGENT_GOT_H
#define ADH_AGENT_GOT_H
#include <link.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int adh_got_replace(const char *module_substr, void *orig, void *wrapper);
// Our own module name as it shows up in /proc/self/maps (works for a memfd-loaded agent too).
const char *adh_self_module_name(void);
// [start,end) address range of the image loaded at base (min/max over its PT_LOAD segments).
// Recognises our own mappings by address, which matters when the name is shared with an unrelated
// module (a memfd agent maps as "jit-cache", the same name ART's own JIT cache uses). 1 on success.
int adh_image_bounds_of(const void *base, unsigned long long *start, unsigned long long *end);
// GNU build ID (PT_NOTE / NT_GNU_BUILD_ID) of the image loaded at base, read straight out of memory.
// Bit-identical for every copy of the same file, so it identifies "another copy of this .so" exactly
// - unlike an image span, which an unrelated module can happen to share. Returns 1 and sets *len.
int adh_build_id_of(const void *base, unsigned char *out, size_t cap, size_t *len);
// Same, but from an already-available phdr table (lets a dl_iterate_phdr callback identify each
// candidate without re-entering the iterator).
int adh_build_id_from_phdr(const void *base, const ElfW(Phdr) *phdrs, int phnum,
                           unsigned char *out, size_t cap, size_t *len);
// The above two for OUR OWN image.
int adh_self_image_bounds(unsigned long long *start, unsigned long long *end);
int adh_self_build_id(unsigned char *out, size_t cap, size_t *len);
// 1 when addr is one of the module's relocation (GOT) slots, 0 for plain data / unknown.
int adh_got_is_slot(const char *module, void *addr);
int adh_got_replace_by_name(const char *module_substr, const char *symbol, void *wrapper);
// Exact-module replacement that also returns the first slot address and its previous value.
// Returns the number of modules replaced; callers that need one unambiguous slot must
// treat any value other than 1 as an error.
// `perms_before_out` (optional) receives the slot page's permission string as it was BEFORE the
// write. got_write_slot puts the protection back, and the caller can compare the live value against
// this one to prove it — a GOT hook that leaves a RELRO page writable is a detectable footprint.
int adh_got_replace_by_name_ex(const char *module_name, const char *symbol, void *wrapper,
                               void **slot_out, void **value_out,
                               char *perms_before_out, size_t perms_before_size);
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
// Swap one pointer-sized slot in a (possibly read-only/RELRO) page and restore the
// original protection. Returns 1 on success. Used by the JNIEnv function-table hooks.
int adh_swap_pointer_in_ro_page(void **slot, void *newval);
// Copy the /proc/self/maps permission string ("r--p") of the mapping containing addr,
// or "?" when unmapped. Used to prove a temporarily-writable page was restored.
void adh_perms_of_addr(void *addr, char *out, int out_size);
// Write raw code bytes in place (make the covering pages writable, memcpy, flush the icache,
// restore protection). Returns 1 on success. Used to restore an inline hook prologue.
int adh_patch_code_bytes(void *addr, const void *bytes, size_t len);
void adh_cmd_gothook_selftest(int fd, const char *id);

#ifdef __cplusplus
}
#endif

#endif

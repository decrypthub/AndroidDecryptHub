#ifndef ADH_NATIVE_INLINE_H
#define ADH_NATIVE_INLINE_H

#ifdef __cplusplus
extern "C" {
#endif

// Install/remove an arm64 function-entry hook. The original trampoline is returned through
// `original`; callers must preserve it until unhook. Returns 1 only when the backend reports
// success, so callers can fail loud instead of claiming a zero-replacement hook succeeded.
int adh_inline_hook(void *target, void *replacement, void **original);
int adh_inline_unhook(void *target);

#ifdef __cplusplus
}
#endif

#endif

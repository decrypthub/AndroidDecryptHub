#ifndef ADH_AGENT_STEALTH_POOL_H
#define ADH_AGENT_STEALTH_POOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opt-in trampoline-pool camouflage (module S / anti-detection). DEFAULT OFF — the project does not
// hide itself unless the operator explicitly asks for it on an authorized target.
//
// Installing an inline hook makes Dobby allocate a trampoline arena with mmap(MAP_ANONYMOUS), which
// shows up in /proc/self/maps as an executable mapping with NO path - the easiest way for a target
// to spot an injected hook framework (measured on Android 15: one hook adds two anonymous 4 KiB
// r-x pages, while a normal ART app only ever shows *named* memfd JIT caches). libdobby.a is linked
// into libadh_agent.so, so Dobby's mmap() calls resolve through this module's own PLT/GOT slot;
// swapping that one slot redirects the arena into a memfd-backed mapping named like the ART JIT
// cache, which blends into the runtime's own mappings.
//
// The redirect window is thread-local and open only around the Dobby calls, but within it EVERY
// matching anonymous allocation on that thread is redirected - not just the arena. That is the
// honest scope: the filter is "anonymous, <= 1 MiB, on the hooking thread, inside the window".
// Every failure falls back to the real mmap (and reports errno), so hooking never depends on the
// camouflage working.
int adh_stealth_pool_set(int enable, char *error, size_t error_size);
int adh_stealth_pool_enabled(void);
// Thread-local guard: the inline-hook backend opens it around Dobby entry points. Nesting is safe.
void adh_stealth_pool_window(int open);
void adh_cmd_stealth(int fd, const char *id, const char *action);

#ifdef __cplusplus
}
#endif

#endif

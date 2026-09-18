// Opt-in trampoline-pool camouflage: turns Dobby's anonymous executable arenas into memfd-backed
// mappings that look like the ART JIT cache. See stealth_pool.h for the evidence and the rationale.
#include "stealth_pool.h"

#include "got.h"
#include "../bootstrap/agent_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

// A Dobby arena is a handful of pages; anything larger is not ours and must not be touched.
#define ADH_POOL_MAX_BYTES (1u << 20)
// Same name family as the runtime's own JIT cache memfds on purpose: the point of the feature is
// that the trampoline pool stops standing out next to them.
#define ADH_POOL_MEMFD_NAME "jit-cache"

typedef void *(*adh_mmap_fn)(void *, size_t, int, int, int, off_t);

static adh_mmap_fn g_real_mmap;
static void *g_last_original;   // reporting only: survives off() so status can name the displaced mmap
static void **g_mmap_slot;
static int g_installed;              // GOT slot currently points at our interposer
static int g_enabled;                // operator asked for camouflage
static int g_memfd_errno;            // last memfd_create/mmap failure (0 = none yet)
static unsigned long long g_redirected, g_failed;
static char g_last_error[160];
// Per-thread redirect window: only the thread that is inside the inline-hook backend redirects, so
// concurrent allocations on other threads (JIT, loader, app code) keep their original semantics.
static __thread int t_window;

static void pool_error(char *error, size_t error_size, const char *msg) {
    snprintf(g_last_error, sizeof(g_last_error), "%s", msg);
    if (error && error_size) snprintf(error, error_size, "%s", msg);
}

// Interposer installed into libadh_agent.so's RELRO GOT slot for mmap.
static void *adh_pool_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    if (t_window <= 0 || fd != -1 || len == 0 || len > ADH_POOL_MAX_BYTES ||
        (flags & MAP_ANONYMOUS) == 0) {
        return g_real_mmap(addr, len, prot, flags, fd, off);
    }
    const int saved_errno = errno;
    int mfd = (int)syscall(__NR_memfd_create, ADH_POOL_MEMFD_NAME, 0);
    if (mfd < 0) {
        g_memfd_errno = errno;
        g_failed++;
        errno = saved_errno;
        return g_real_mmap(addr, len, prot, flags, fd, off);
    }
    if (ftruncate(mfd, (off_t)len) != 0) {
        g_memfd_errno = errno;
        close(mfd);
        g_failed++;
        errno = saved_errno;
        return g_real_mmap(addr, len, prot, flags, fd, off);
    }
    // Keep the caller's request unchanged apart from "anonymous" -> "this memfd": same address
    // hint, same protection. MAP_PRIVATE must be cleared as well: MAP_PRIVATE|MAP_SHARED is
    // MAP_SHARED_VALIDATE on Linux, i.e. an undefined combination that only works by accident.
    // An anonymous mapping has an offset of 0, so passing 0 keeps the request equivalent.
    void *out = g_real_mmap(addr, len, prot,
                            (flags & ~(MAP_ANONYMOUS | MAP_PRIVATE)) | MAP_SHARED, mfd, 0);
    const int map_errno = errno;
    close(mfd);
    if (out == MAP_FAILED) {
        g_memfd_errno = map_errno;
        g_failed++;
        errno = saved_errno;
        return g_real_mmap(addr, len, prot, flags, fd, off);
    }
    g_redirected++;
    errno = saved_errno;
    return out;
}

int adh_stealth_pool_enabled(void) { return g_enabled; }

void adh_stealth_pool_window(int open) {
    if (open) t_window++;
    else if (t_window > 0) t_window--;
}

int adh_stealth_pool_set(int enable, char *error, size_t error_size) {
    if (!enable) {
        if (g_installed && g_mmap_slot && g_real_mmap) {
            // Refuse to write the cached libc pointer back over somebody else's value (another
            // injected library or a relocation fixup could have replaced the slot in the meantime).
            if (*g_mmap_slot != (void *)adh_pool_mmap) {
                snprintf(g_last_error, sizeof(g_last_error),
                         "mmap GOT slot no longer points at the pool interposer (0x%llx) - leaving it alone",
                         (unsigned long long)(uintptr_t)*g_mmap_slot);
                pool_error(error, error_size, g_last_error);
                return 0;
            }
            if (!adh_swap_pointer_in_ro_page(g_mmap_slot, (void *)g_real_mmap)) {
                pool_error(error, error_size, "could not restore the mmap GOT slot (RELRO page not writable)");
                return 0;
            }
            g_installed = 0;
        }
        // Drop the cached slot/symbol: a re-enable resolves them again instead of writing to a
        // possibly re-mapped GOT page.
        g_mmap_slot = NULL;
        g_real_mmap = NULL;
        g_enabled = 0;
        t_window = 0;
        return 1;
    }
    if (!g_installed) {
        void *slot = NULL, *value = NULL;
        if (!adh_got_slot_value(adh_self_module_name(), "mmap", &slot, &value) || !slot || !value) {
            pool_error(error, error_size, "mmap GOT slot not found in our own module (cannot camouflage the pool)");
            return 0;
        }
        if (value == (void *)adh_pool_mmap) {
            pool_error(error, error_size, "mmap GOT slot already points at the pool interposer");
            return 0;
        }
        g_mmap_slot = (void **)slot;
        g_real_mmap = (adh_mmap_fn)value;
        g_last_original = value;
        if (!adh_swap_pointer_in_ro_page(g_mmap_slot, (void *)adh_pool_mmap)) {
            pool_error(error, error_size, "could not swap the mmap GOT slot (RELRO page not writable)");
            g_mmap_slot = NULL;
            g_real_mmap = NULL;
            return 0;
        }
        g_installed = 1;
    }
    if (!g_enabled) {
        g_redirected = 0;
        g_failed = 0;
        g_memfd_errno = 0;
        g_last_error[0] = 0;
    }
    g_enabled = 1;
    return 1;
}

// Honest status: whether camouflage is on, how many allocations it actually redirected, and why it
// failed when it did (memfd_create may be refused by a hardened policy - then the real mmap is used
// and anonExecMappings stays as it always was; nothing silently pretends to be hidden).
void adh_cmd_stealth(int fd, const char *id, const char *action) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    char error[160] = "";
    int ok = 1;
    if (strcmp(action, "on") == 0) {
        ok = adh_stealth_pool_set(1, error, sizeof(error));
    } else if (strcmp(action, "off") == 0) {
        ok = adh_stealth_pool_set(0, error, sizeof(error));
    } else if (strcmp(action, "status") != 0) {
        snprintf(error, sizeof(error), "unknown stealth action '%s' (on|off|status)", action ? action : "");
        ok = 0;
    }
    // Read the slot now instead of trusting g_installed: the operator can then compare it against
    // originalMmap without believing a cached boolean.
    void *slot_now = (g_mmap_slot && g_installed) ? *g_mmap_slot : NULL;
    int memfd_probe = (int)syscall(__NR_memfd_create, ADH_POOL_MEMFD_NAME, 0);
    int memfd_errno = memfd_probe < 0 ? errno : 0;
    if (memfd_probe >= 0) close(memfd_probe);

    char out[1024];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"stealth\",\"ok\":%s,\"error\":\"%s\","
             "\"enabled\":%s,\"installed\":%s,\"active\":%s,\"redirected\":%llu,\"failed\":%llu,"
             "\"memfdAvailable\":%s,\"memfdErrno\":%d,\"memfdName\":\"%s\","
             "\"poolRedirectErrno\":%d,\"mmapSlot\":\"0x%llx\",\"slotNow\":\"0x%llx\","
             "\"originalMmap\":\"0x%llx\",\"lastError\":\"%s\"}\n",
             idj, ok ? "true" : "false", error,
             g_enabled ? "true" : "false", g_installed ? "true" : "false",
             (g_enabled && g_redirected > 0) ? "true" : "false",
             g_redirected, g_failed,
             memfd_probe >= 0 ? "true" : "false", memfd_errno, ADH_POOL_MEMFD_NAME,
             g_memfd_errno,
             (unsigned long long)(uintptr_t)g_mmap_slot,
             (unsigned long long)(uintptr_t)slot_now,
             (unsigned long long)(uintptr_t)(g_real_mmap ? (void *)g_real_mmap : g_last_original),
             g_last_error);
    send_line(fd, out);
}

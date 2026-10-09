// mem_read.c — the agent's memory-read backend.
//
// Reading target memory through /proc/self/mem is the safe way to do it: an unmapped or
// non-resident page comes back as a short read or an error instead of a fault. But that fd is
// gated on the process being DUMPABLE: a target that calls prctl(PR_SET_DUMPABLE, 0) — which
// SecNeo/Bangcle and several other protectors do on startup — makes open("/proc/self/mem") fail
// with EACCES *even for the process itself*. Every ADH read path used to route through that fd,
// so on such a target read / search / magic-scan / dump / art_dexfiles all died at once with no
// way to tell why.
//
// The agent is already inside the address space, so it can simply read the bytes. A direct read
// is not free of consequences though: touching an unmapped page takes the whole process down with
// SIGSEGV (SIGBUS for a file-backed page past EOF). So the fallback is (a) clamped to a range
// /proc/self/maps says is readable and (b) wrapped in a short signal guard that turns a fault
// into a failed read.
//
// Backend selection is deliberately conservative: when /proc/self/mem can be opened, that is what
// every read uses, byte-for-byte as before. The direct path only runs when the fd is refused, so
// targets that were fine continue to behave identically.
#include "agent_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>

static int g_mem_fd = -1;                 // cached /proc/self/mem, -1 = not usable
static int g_mem_open_errno = 0;          // why the last open failed (reported by compat_probe)

// Forced direct read. A target that refuses /proc/self/mem cannot be reproduced on demand — on this
// ROM even prctl(PR_SET_DUMPABLE,0) leaves self-reads working — so the fallback was only ever tested
// on the one read path that has a per-call override (`via=direct`), leaving search / magic-scan /
// dump / art_dexfiles uncovered on the direct route. Forcing it here covers all of them at once:
// every call site already branches on `adh_mem_fd() >= 0`, so returning -1 puts the whole module on
// the direct path with no per-site change.
static int g_forced_direct = 0;

#define ADH_BACKEND_PROC_SELF_MEM 0
#define ADH_BACKEND_DIRECT        1

// "auto" (default) | "direct" (force) | "proc" (back to auto). Unknown values are rejected by the
// command layer; returns the effective mode name for the reply.
const char *adh_mem_set_backend(const char *name) {
    if (name && strcmp(name, "direct") == 0) g_forced_direct = 1;
    else if (name && (name[0] == 0 || strcmp(name, "auto") == 0 || strcmp(name, "proc") == 0)) g_forced_direct = 0;
    return adh_mem_backend_name();
}

int adh_mem_forced_direct(void) { return g_forced_direct; }

// The cached fd, or -1. A failed open is NOT cached: if the target ever becomes dumpable again
// (e.g. a prctl round-trip), the cheap fd path comes back on its own.
int adh_mem_fd(void) {
    if (g_forced_direct) return -1;       // forced direct: no fd, every caller takes the direct branch
    int fd = __atomic_load_n(&g_mem_fd, __ATOMIC_ACQUIRE);
    if (fd >= 0) return fd;
    int new_fd = open("/proc/self/mem", O_RDONLY);
    if (new_fd < 0) {
        __atomic_store_n(&g_mem_open_errno, errno, __ATOMIC_RELEASE);
        return -1;
    }
    int expected = -1;
    if (!__atomic_compare_exchange_n(&g_mem_fd, &expected, new_fd, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        close(new_fd);
        return expected;                  // another thread won the race
    }
    return new_fd;
}

int adh_mem_backend(void) { return adh_mem_fd() >= 0 ? ADH_BACKEND_PROC_SELF_MEM : ADH_BACKEND_DIRECT; }
const char *adh_mem_backend_name(void) {
    if (g_forced_direct) return "direct(forced)";
    return adh_mem_backend() == ADH_BACKEND_PROC_SELF_MEM ? "proc-self-mem" : "direct";
}
// The errno from the last real open attempt. Deliberately does NOT re-probe when the direct route is
// forced, so the reported reason still describes why the fd route is unavailable.
int adh_mem_open_errno(void) {
    if (!g_forced_direct) adh_mem_fd();
    return g_mem_open_errno;
}

// Is `addr` inside a readable mapping? On success *end gets that mapping's end address.
// /proc/self/maps is sorted by address, so the first entry that starts past `addr` ends the search.
int adh_mem_region_end(unsigned long long addr, unsigned long long *end) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), m)) {
        char sa[64], ea[64], perms[8];
        if (sscanf(line, "%63[0-9a-f]-%63[0-9a-f] %7s", sa, ea, perms) < 3) continue;
        unsigned long long s = strtoull(sa, NULL, 16);
        unsigned long long e = strtoull(ea, NULL, 16);
        if (e <= s) continue;
        if (addr < s) break;                       // sorted: nothing later can contain addr
        if (addr < e) { found = (perms[0] == 'r'); if (found && end) *end = e; break; }
    }
    fclose(m);
    return found;
}

// ---- signal-guarded direct copy ---------------------------------------------------------
// A direct read of a bad page faults instead of returning an error. The guard turns that fault
// into a failed read for THIS thread only; a fault that is not ours (another thread, a real crash
// in the target) is handed straight back to whatever disposition was installed before us.
static pthread_mutex_t g_guard_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction g_prev_segv, g_prev_bus;
static __thread sigjmp_buf *t_guard;
static __thread volatile sig_atomic_t t_guard_on;

static void adh_mem_fault_handler(int sig, siginfo_t *info, void *uc) {
    (void)info; (void)uc;                          // SA_SIGINFO signature; neither is needed here
    if (t_guard_on) { t_guard_on = 0; if (t_guard) siglongjmp(*t_guard, 1); }
    // Not our read: restore the previous disposition and re-raise so the target sees its own crash.
    struct sigaction *prev = (sig == SIGBUS) ? &g_prev_bus : &g_prev_segv;
    sigaction(sig, prev, NULL);
    raise(sig);
}

// memcpy that reports a fault as -1 instead of killing the target. `n` is the caller's promise
// that [src, src+n) is inside one readable mapping; the guard covers a mapping that goes away
// underneath us (another thread munmaps) and a file-backed page past EOF (SIGBUS).
static ssize_t adh_mem_copy_guarded(void *dst, const void *src, size_t n) {
    struct sigaction act, prev_segv, prev_bus, prev_bus_check;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = adh_mem_fault_handler;
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&act.sa_mask);

    pthread_mutex_lock(&g_guard_lock);
    if (sigaction(SIGSEGV, NULL, &prev_segv) != 0 ||
        sigaction(SIGBUS, NULL, &prev_bus_check) != 0) {
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }
    prev_bus = prev_bus_check;
    g_prev_segv = prev_segv;
    g_prev_bus = prev_bus;
    if (sigaction(SIGSEGV, &act, NULL) != 0 || sigaction(SIGBUS, &act, NULL) != 0) {
        sigaction(SIGSEGV, &prev_segv, NULL);
        sigaction(SIGBUS, &prev_bus, NULL);
        pthread_mutex_unlock(&g_guard_lock);
        return -1;
    }

    sigjmp_buf jb;
    t_guard = &jb;
    t_guard_on = 1;
    ssize_t out;
    if (sigsetjmp(jb, 1) == 0) {
        memcpy(dst, src, n);
        out = (ssize_t)n;
    } else {
        out = -1;                                  // faulted mid-copy: say so, don't report success
    }
    t_guard_on = 0;
    t_guard = NULL;

    sigaction(SIGSEGV, &prev_segv, NULL);
    sigaction(SIGBUS, &prev_bus, NULL);
    pthread_mutex_unlock(&g_guard_lock);
    return out;
}

// Generic read: /proc/self/mem when the target allows it, otherwise a bounds-checked direct read.
// Semantics match pread(): bytes read, short on an unreadable tail, -1 when nothing is readable.
ssize_t adh_mem_pread(void *dst, size_t n, unsigned long long addr) {
    if (!dst || n == 0) return 0;
    int fd = adh_mem_fd();
    if (fd >= 0) return pread(fd, dst, n, (off_t)addr);
    return adh_mem_read_direct(dst, n, addr);
}

// The direct route on its own, with no fd preference. Used as adh_mem_pread's fallback and by the
// explicit `read ... via=direct` diagnostic, which lets a caller compare the two routes on a target
// that answers /proc/self/mem with plausible garbage (some protectors hook it).
ssize_t adh_mem_read_direct(void *dst, size_t n, unsigned long long addr) {
    if (!dst || n == 0) return 0;
    if (addr < 0x1000) { errno = EFAULT; return -1; }          // page 0 is never mapped
    unsigned long long end = 0;
    if (!adh_mem_region_end(addr, &end)) { errno = EFAULT; return -1; }
    if (end - addr < n) n = (size_t)(end - addr);
    if (n == 0) { errno = EFAULT; return -1; }
    return adh_mem_copy_guarded(dst, (const void *)(uintptr_t)addr, n);
}

// Drop the cached fd. Callers that open it for a bounded command release it when they are done, so
// ADH does not leave a standing /proc/self/mem descriptor in the target between commands (that open
// fd is itself an observable "someone is reading my memory" signal). The trace preview keeps it,
// as it did before, because it runs inside a hot hook.
void adh_mem_fd_release(void) {
    int fd = __atomic_exchange_n(&g_mem_fd, -1, __ATOMIC_ACQ_REL);
    if (fd >= 0) close(fd);
}

// Direct read for callers that already iterated /proc/self/maps themselves (the scan loops) and
// therefore know [addr, addr+n) is readable. Only valid on the direct backend — callers must have
// checked adh_mem_fd() themselves and must keep using pread() when the fd exists.
ssize_t adh_mem_read_in_region(void *dst, size_t n, unsigned long long addr,
                               unsigned long long region_end) {
    if (!dst || n == 0) return 0;
    if (region_end <= addr) return -1;
    if (region_end - addr < n) n = (size_t)(region_end - addr);
    return adh_mem_copy_guarded(dst, (const void *)(uintptr_t)addr, n);
}

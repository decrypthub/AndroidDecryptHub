// Hardware watchpoints inside the target: perf_event_open(PERF_TYPE_BREAKPOINT) + a sampling ring.
//
// "Who wrote / read this buffer" cannot be answered by hooking known functions (the accessor is
// usually a non-exported block) nor by an instruction trace of a large flattened function (the
// interesting instruction is one load among millions). A watchpoint answers it directly: arm the
// address, trigger the target once, and the kernel reports the faulting instruction and the call
// chain. Android normally forbids perf events for apps (perf_event_paranoid=2/3 or SELinux); the
// command fails loud with the errno instead of pretending to watch.
//
// Two ways to arm:
//   action:set    - an absolute address, armed now.
//   action:after  - "the next time this native hook returns, arm on <reg>+<off>". That form is what
//                  makes a *transient* buffer observable: a function's output buffer usually does
//                  not exist until the function has produced it, so arming after the return is the
//                  only moment the address is both known and still live.
#include "hw_watch.h"

#include "../capture/capture.h"

#include <android/log.h>
#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TAG "hook.hww"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

namespace {
struct Watch {
    int fd = -1;
    volatile int active = 0;
    void *ring = nullptr;
    size_t ring_size = 0;
    size_t page = 0;
    uint64_t addr = 0;
    int len = 0;
    char mode[8] = {0};      // "w" | "rw" | "x"
    char label[48] = {0};
    // Diagnostics: without these, "no hit" cannot be told apart from "the event never woke us".
    int poll_rc = -1;
    int poll_revents = 0;
    int records = 0;
    int last_type = -1;
    unsigned last_size = 0;
    unsigned long long head_seen = 0;
    // The hit itself. Kept in the slot and served by `status` instead of only being pushed into
    // the capture ring: the ring needs the daemon's drain loop to be running, and a watchpoint hit
    // is too important to lose because a different consumer forgot to arm capture.
    uint64_t hit_ip = 0;
    uint32_t hit_tid = 0;
    size_t hit_frames = 0;
    uint64_t hit_chain[16] = {0};
};
Watch g_watch[ADH_HW_WATCH_MAX];
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// "arm when this native hook returns" table, keyed by the USER-VISIBLE hook id.
struct AfterArm {
    int hook_uid;
    int reg;
    int off;
    int len;
};
AfterArm g_after[ADH_HW_WATCH_MAX];

// Copy `n` bytes out of the ring, honouring the wrap at data_sz.
bool ring_copy(const char *data, size_t data_sz, size_t off, void *dst, size_t n) {
    if (n > data_sz) return false;
    if (off + n <= data_sz) { memcpy(dst, data + off, n); return true; }
    size_t first = data_sz - off;
    memcpy(dst, data + off, first);
    memcpy((char *)dst + first, data, n - first);
    return true;
}
}  // namespace

// One thread per watch: poll the perf fd, parse the first sample, keep the hit, disarm.
static void *hw_watch_thread(void *arg) {
    Watch *w = (Watch *)arg;
    struct pollfd pfd;
    pfd.fd = w->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, 15000);   // bounded: no thread lives forever if nothing fires
    w->poll_rc = rc;
    w->poll_revents = pfd.revents;
    if (rc <= 0) return nullptr;

    struct perf_event_mmap_page *meta = (struct perf_event_mmap_page *)w->ring;
    uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;
    w->head_seen = head;
    char *data = (char *)w->ring + w->page;
    size_t data_sz = w->ring_size - w->page;
    bool reported = false;

    while (tail < head && !reported) {
        struct perf_event_header hdr;
        if (!ring_copy(data, data_sz, (size_t)(tail % data_sz), &hdr, sizeof(hdr))) break;
        if (hdr.size < sizeof(hdr) || hdr.size > data_sz) break;
        w->records++;
        w->last_type = hdr.type;
        w->last_size = hdr.size;
        if (hdr.type == PERF_RECORD_SAMPLE) {
            // Payload order follows sample_type bits: IP, TID, CALLCHAIN.
            unsigned char payload[1024];
            size_t n = hdr.size - sizeof(hdr);
            if (n <= sizeof(payload) &&
                ring_copy(data, data_sz, (size_t)((tail + sizeof(hdr)) % data_sz), payload, n)) {
                size_t p = 0;
                uint64_t ip = 0, nr = 0;
                uint32_t pid = 0, tid = 0;
                uint64_t chain[32];
                size_t nchain = 0;
                if (p + 8 <= n) { memcpy(&ip, payload + p, 8); p += 8; }
                if (p + 8 <= n) { memcpy(&pid, payload + p, 4); p += 4; memcpy(&tid, payload + p, 4); p += 4; }
                if (p + 8 <= n) {
                    memcpy(&nr, payload + p, 8); p += 8;
                    size_t want = nr < 32 ? (size_t)nr : 32;
                    for (size_t i = 0; i < want && p + 8 <= n; i++, p += 8) {
                        uint64_t a = 0;
                        memcpy(&a, payload + p, 8);
                        chain[nchain++] = a;
                    }
                }
                char chain_txt[900];
                size_t cl = 0;
                chain_txt[0] = 0;
                for (size_t i = 0; i < nchain && cl + 20 < sizeof(chain_txt); i++) {
                    cl += snprintf(chain_txt + cl, sizeof(chain_txt) - cl, "%s0x%llx",
                                   i ? "," : "", (unsigned long long)chain[i]);
                }
                w->hit_ip = ip;
                w->hit_tid = tid;
                w->hit_frames = nchain < 16 ? nchain : 16;
                for (size_t i = 0; i < w->hit_frames; i++) w->hit_chain[i] = chain[i];
                // The hit lives in the slot (served by status, which never blocks). Pushing it into
                // the capture ring as well made the watcher depend on the drain loop: with the ring
                // full, the pushing thread could sit there and the `status` answer became
                // unreachable. The LOGI line keeps the same information in logcat.
                LOGI("hw_watch hit ip=0x%llx tid=%u pid=%u frames=%zu chain=[%s]",
                     (unsigned long long)ip, tid, pid, nchain, chain_txt);
                reported = true;
            }
        }
        tail += hdr.size;
    }
    meta->data_tail = tail;
    ioctl(w->fd, PERF_EVENT_IOC_DISABLE, 0);
    __atomic_store_n(&w->active, 0, __ATOMIC_RELEASE);
    return nullptr;
}

// Arm one watch. Caller must NOT hold g_lock: this takes it, and it must never span a
// pthread_create/mmap while another thread wants status (measured: holding the lock across the
// hook's after-stub made `hw_watch status` time out in the target).
static int arm_one_locked(uint64_t addr, int len, const char *mode, const char *label_prefix,
                          char *out, size_t outsz);
static int arm_one_locked(uint64_t addr, int len, const char *mode, const char *label_prefix,
                   char *out, size_t outsz) {
    if (!addr) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"addr is 0\"}");
        return -1;
    }
    if (!(len == 1 || len == 2 || len == 4 || len == 8)) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"len must be 1, 2, 4 or 8\"}");
        return -1;
    }
    int free_slot = -1;
    for (int i = 0; i < ADH_HW_WATCH_MAX; i++) if (g_watch[i].fd < 0) { free_slot = i; break; }
    if (free_slot < 0) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"all %d watch slots are in use\"}", ADH_HW_WATCH_MAX);
        return -1;
    }
    Watch *w = &g_watch[free_slot];
    memset(&w->hit_chain, 0, sizeof(w->hit_chain));
    w->hit_ip = 0;
    w->hit_frames = 0;
    w->records = 0;
    w->last_type = -1;
    w->last_size = 0;
    w->head_seen = 0;
    w->poll_rc = -1;
    w->poll_revents = 0;
    w->addr = addr;
    w->len = len;
    snprintf(w->mode, sizeof(w->mode), "%s", mode && mode[0] ? mode : "w");

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = strcmp(w->mode, "rw") == 0 ? HW_BREAKPOINT_RW
                 : strcmp(w->mode, "x") == 0 ? HW_BREAKPOINT_X
                                             : HW_BREAKPOINT_W;
    attr.bp_addr = w->addr;
    attr.bp_len = (uint64_t)len;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.disabled = 0;
    attr.wakeup_events = 1;   // wake the poller on the very first event
    // pid 0 = this process, cpu -1 = all CPUs (a breakpoint must follow the thread).
    long fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (fd < 0) {
        int e = errno;
        snprintf(out, outsz,
                 "{\"ok\":false,\"error\":\"perf_event_open failed: %s (errno %d)  - perf events are "
                 "usually forbidden for apps (perf_event_paranoid=2/3), and SELinux can deny them "
                 "even when the sysctl allows it\",\"errno\":%d}",
                 strerror(e), e, e);
        w->fd = -1;
        return -1;
    }
    w->fd = (int)fd;
    w->page = (size_t)sysconf(_SC_PAGESIZE);
    w->ring_size = w->page * 9;   // 1 metadata page + 8 data pages
    w->ring = mmap(nullptr, w->ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, w->fd, 0);
    if (w->ring == MAP_FAILED) {
        int e = errno;
        w->ring = nullptr;
        close(w->fd);
        w->fd = -1;
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"mmap of the perf ring failed: %s\",\"errno\":%d}",
                 strerror(e), e);
        return -1;
    }
    // Breakpoints are NOT reliably live just because disabled=0; without ENABLE the event never
    // counts and poll() simply times out (measured with a forced write to the watched address).
    ioctl(w->fd, PERF_EVENT_IOC_ENABLE, 0);
    snprintf(w->label, sizeof(w->label), "%s%s%llx", label_prefix ? label_prefix : "",
             strcmp(w->mode, "rw") == 0 ? "rw:" : "w:", (unsigned long long)w->addr);
    __atomic_store_n(&w->active, 1, __ATOMIC_RELEASE);
    pthread_t th;
    pthread_attr_t ta;
    pthread_attr_init(&ta);
    pthread_attr_setdetachstate(&ta, PTHREAD_CREATE_DETACHED);
    int prc = pthread_create(&th, &ta, hw_watch_thread, w);
    pthread_attr_destroy(&ta);
    if (prc != 0) {
        munmap(w->ring, w->ring_size);
        close(w->fd);
        w->ring = nullptr;
        w->fd = -1;
        __atomic_store_n(&w->active, 0, __ATOMIC_RELEASE);
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"pthread_create failed: %d\"}", prc);
        return -1;
    }
    snprintf(out, outsz,
             "{\"ok\":true,\"slot\":%d,\"addr\":\"0x%llx\",\"len\":%d,\"mode\":\"%s\","
             "\"note\":\"the first access is reported as HW_WATCH (faulting ip + call chain); "
             "one shot per arm, poll status for the hit\"}",
             free_slot, (unsigned long long)w->addr, len, w->mode);
    return free_slot;
}

// Locking wrapper: every caller arms through this, so no caller has to know about g_lock.
static int arm_one(uint64_t addr, int len, const char *mode, const char *label_prefix,
                   char *out, size_t outsz) {
    pthread_mutex_lock(&g_lock);
    int rc = arm_one_locked(addr, len, mode, label_prefix, out, outsz);
    pthread_mutex_unlock(&g_lock);
    return rc;
}

int adh_hw_watch_cmd(const char *action, const char *addr_hex, int len, const char *mode,
                     int slot, char *out, size_t outsz) {
    // The READ-ONLY actions (`status`, `hit`) must NEVER block: they are how a caller finds out
    // what happened, so a stuck arm cannot be allowed to make the answer unreachable. Measured:
    // after a hit, a plain lock made status time out in the target (the agent looked hung while
    // ping still answered). `hit` had the same defect - it is the only way to get the call chain,
    // and it went through the blocking path, so the moment an arm was in flight the chain was
    // unreachable exactly when a caller was most likely to ask for it.
    const int read_only = strcmp(action, "status") == 0 || strcmp(action, "hit") == 0;
    if (read_only && pthread_mutex_trylock(&g_lock) != 0) {
        snprintf(out, outsz,
                 "{\"ok\":false,\"action\":\"%s\",\"error\":\"busy: an arm is in flight\","
                 "\"hint\":\"retry in a moment; the hit itself is kept in the slot\"}", action);
        return -1;
    }
    if (!read_only) pthread_mutex_lock(&g_lock);
    if (strcmp(action, "status") == 0) {
        size_t n = 0;
        n += snprintf(out + n, outsz > n ? outsz - n : 0, "{\"ok\":true,\"slots\":[");
        for (int i = 0; i < ADH_HW_WATCH_MAX; i++) {
            char chain_txt[400];
            size_t cl = 0;
            chain_txt[0] = 0;
            for (size_t k = 0; k < g_watch[i].hit_frames && cl + 20 < sizeof(chain_txt); k++) {
                cl += snprintf(chain_txt + cl, sizeof(chain_txt) - cl, "%s0x%llx", k ? "," : "",
                               (unsigned long long)g_watch[i].hit_chain[k]);
            }
            n += snprintf(out + n, outsz > n ? outsz - n : 0,
                          "%s{\"slot\":%d,\"active\":%s,\"addr\":\"0x%llx\",\"len\":%d,\"mode\":\"%s\","
                          "\"pollRc\":%d,\"revents\":%d,\"records\":%d,\"lastType\":%d,\"lastSize\":%u,"
                          "\"head\":\"0x%llx\",\"hit\":{\"ip\":\"0x%llx\",\"tid\":%u,\"frames\":%zu}}",
                          i ? "," : "", i, g_watch[i].active ? "true" : "false",
                          (unsigned long long)g_watch[i].addr, g_watch[i].len, g_watch[i].mode,
                          g_watch[i].poll_rc, g_watch[i].poll_revents, g_watch[i].records,
                          g_watch[i].last_type, g_watch[i].last_size, g_watch[i].head_seen,
                          (unsigned long long)g_watch[i].hit_ip, g_watch[i].hit_tid,
                          g_watch[i].hit_frames);
            (void)chain_txt;
        }
        snprintf(out + n, outsz > n ? outsz - n : 0, "]}");
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    if (strcmp(action, "clear") == 0) {
        if (slot < 0 || slot >= ADH_HW_WATCH_MAX) {
            snprintf(out, outsz, "{\"ok\":false,\"error\":\"slot out of range\"}");
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
        Watch *w = &g_watch[slot];
        if (w->fd >= 0) {
            ioctl(w->fd, PERF_EVENT_IOC_DISABLE, 0);
            if (w->ring) munmap(w->ring, w->ring_size);
            close(w->fd);
            w->fd = -1;
            w->ring = nullptr;
            w->ring_size = 0;
            __atomic_store_n(&w->active, 0, __ATOMIC_RELEASE);
        }
        snprintf(out, outsz, "{\"ok\":true,\"cleared\":%d}", slot);
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    if (strcmp(action, "hit") == 0) {
        // The call chain of one hit, in a SMALL reply. Kept separate from status on purpose: a
        // status reply that embedded every chain grew large enough to matter, and the hit is the
        // part worth fetching deliberately.
        int i = (slot >= 0 && slot < ADH_HW_WATCH_MAX) ? slot : -1;
        if (i >= 0 && !g_watch[i].hit_ip) i = -1;
        if (i < 0) {
            for (int k = 0; k < ADH_HW_WATCH_MAX; k++) if (g_watch[k].hit_ip) { i = k; break; }
        }
        if (i < 0) {
            snprintf(out, outsz, "{\"ok\":false,\"error\":\"no hit in any slot yet\"}");
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
        char chain_txt[420];
        size_t cl = 0;
        chain_txt[0] = 0;
        for (size_t k = 0; k < g_watch[i].hit_frames && cl + 22 < sizeof(chain_txt); k++) {
            cl += snprintf(chain_txt + cl, sizeof(chain_txt) - cl, "%s0x%llx", k ? "," : "",
                           (unsigned long long)g_watch[i].hit_chain[k]);
        }
        snprintf(out, outsz,
                 "{\"ok\":true,\"slot\":%d,\"ip\":\"0x%llx\",\"tid\":%u,\"frames\":%zu,\"chain\":[%s]}",
                 i, (unsigned long long)g_watch[i].hit_ip, g_watch[i].hit_tid,
                 g_watch[i].hit_frames, chain_txt);
        pthread_mutex_unlock(&g_lock);
        return 0;
    }
    if (strcmp(action, "set") == 0) {
        // arm_one takes the lock itself: never hold it across pthread_create/mmap, or a status
        // request from another thread waits for the whole arm.
        pthread_mutex_unlock(&g_lock);
        return arm_one(strtoull(addr_hex, nullptr, 0), len, mode, "", out, outsz);
    }
    snprintf(out, outsz, "{\"ok\":false,\"error\":\"action must be set, after, hit, clear or status\"}");
    pthread_mutex_unlock(&g_lock);
    return -1;
}

// Arm from inside a hook's after-stub: the caller (native_hooks) passes the saved x0..x8.
int adh_hw_watch_arm_for_hook(int hook_uid, const uint64_t *regs) {
    if (!regs || hook_uid <= 0) return -1;
    // Copy the config under the lock, then arm OUTSIDE it: this runs on the target thread inside a
    // hook's after-stub, and holding g_lock across perf_event_open/mmap/pthread_create made a
    // concurrent `hw_watch status` time out in the target (measured).
    int reg = -1, off = 0, len = 0;
    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < ADH_HW_WATCH_MAX; i++) {
        if (g_after[i].hook_uid != hook_uid) continue;
        reg = g_after[i].reg;
        off = g_after[i].off;
        len = g_after[i].len;
        break;
    }
    pthread_mutex_unlock(&g_lock);
    if (reg < 0) return -1;
    uint64_t addr = regs[reg] + (uint64_t)off;
    char res[320] = "";
    int slot = arm_one(addr, len, "rw", "after:", res, sizeof(res));
    // Deliberately NOT pushed into the capture ring: that ring needs the daemon's drain loop, and
    // pushing from a hook after-stub made the arm path depend on a second subsystem (a full ring
    // then kept the stub busy). The hit is kept in the slot and served by status; the LOGI line
    // still records the arm for logcat.
    LOGI("hw_watch arm_for_hook uid=%d addr=0x%llx slot=%d (%s)", hook_uid,
         (unsigned long long)addr, slot, res);
    return slot;
}

// Configure "arm when hook_uid returns". spec is x0:8 / x2+16:4 / x0:1.
int adh_hw_watch_config_after(int hook_uid, const char *spec, char *out, size_t outsz) {
    if (hook_uid <= 0 || !spec || !spec[0]) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"after needs hookId and spec (e.g. x0:8)\"}");
        return -1;
    }
    const char *p = spec;
    while (*p == ' ') p++;
    if (p[0] != 'x' || p[1] < '0' || p[1] > '8' || (p[2] != ':' && p[2] != '+')) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"spec must look like x0:8 or x2+16:4\"}");
        return -1;
    }
    int reg = p[1] - '0';
    int off = 0, len = 0;
    p += 2;
    if (*p == '+') {
        p++;
        while (*p >= '0' && *p <= '9') {
            off = off * 10 + (*p - '0');
            if (off > 65535) { snprintf(out, outsz, "{\"ok\":false,\"error\":\"offset too large\"}"); return -1; }
            p++;
        }
    }
    if (*p != ':') {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"spec must look like x0:8 or x2+16:4\"}");
        return -1;
    }
    p++;
    while (*p >= '0' && *p <= '9') {
        len = len * 10 + (*p - '0');
        if (len > 8) { snprintf(out, outsz, "{\"ok\":false,\"error\":\"after len must be 1..8\"}"); return -1; }
        p++;
    }
    if (!(len == 1 || len == 2 || len == 4 || len == 8)) {
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"after len must be 1, 2, 4 or 8\"}");
        return -1;
    }
    pthread_mutex_lock(&g_lock);
    size_t used = 0;
    for (size_t i = 0; i < ADH_HW_WATCH_MAX; i++) if (g_after[i].hook_uid > 0) used++;
    if (used >= ADH_HW_WATCH_MAX) {
        pthread_mutex_unlock(&g_lock);
        snprintf(out, outsz, "{\"ok\":false,\"error\":\"after-arms are full (max %d)\"}", ADH_HW_WATCH_MAX);
        return -1;
    }
    // Replace an existing config for the same hook instead of stacking duplicates.
    for (size_t i = 0; i < ADH_HW_WATCH_MAX; i++) {
        if (g_after[i].hook_uid == hook_uid) {
            g_after[i].reg = reg; g_after[i].off = off; g_after[i].len = len;
            pthread_mutex_unlock(&g_lock);
            snprintf(out, outsz, "{\"ok\":true,\"hookId\":%d,\"spec\":\"x%d+%d:%d\",\"replaced\":true}",
                     hook_uid, reg, off, len);
            return 0;
        }
    }
    for (size_t i = 0; i < ADH_HW_WATCH_MAX; i++) {
        if (g_after[i].hook_uid == 0) {
            g_after[i].hook_uid = hook_uid;
            g_after[i].reg = reg; g_after[i].off = off; g_after[i].len = len;
            pthread_mutex_unlock(&g_lock);
            snprintf(out, outsz, "{\"ok\":true,\"hookId\":%d,\"spec\":\"x%d+%d:%d\"}", hook_uid, reg, off, len);
            return 0;
        }
    }
    pthread_mutex_unlock(&g_lock);
    snprintf(out, outsz, "{\"ok\":false,\"error\":\"no after-arm slot\"}");
    return -1;
}

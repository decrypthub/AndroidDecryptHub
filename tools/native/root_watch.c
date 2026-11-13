// Root-side collector. perf records the real target execution; no ptrace, app patch,
// function replay, SELinux change, or in-process agent dependency is involved.
//
// 2026-11-13: a run may watch up to four hardware slots on the same thread and, on every
// event, snapshot small memory windows derived from the sampled registers. The second part
// is what makes a stateful VM tractable: the kernel record keeps the registers of the hit,
// and the collector reads the fields they point at *at the moment of the hit*, instead of
// leaving the caller to re-read memory after the target has moved on.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VERSION "ADH_ROOT_WATCH_V1"
// https://github.com/torvalds/linux/blob/v5.10/arch/arm64/include/uapi/asm/perf_regs.h
#define REGS 33 // Linux arm64 perf ABI: x0..x29, lr, sp, pc (not pstate).
#define PAGES 256
#define MAX_BP 4
#define MAX_MEM 4
#define MAX_MEM_BYTES 256

static volatile sig_atomic_t stopping;
static void on_signal(int sig) { (void)sig; stopping = 1; }
static int64_t millis(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}
static int fail(const char *stage) {
    printf("{\"ready\":false,\"stage\":\"%s\",\"errno\":%d,\"error\":\"%s\"}\n", stage, errno, strerror(errno));
    return 1;
}
static int number(const char *s, uint64_t *out) {
    if (!s || !*s || *s == '-' || *s == '+') return 0;
    char *end; errno = 0; *out = strtoull(s, &end, 0);
    return !errno && end != s && !*end;
}
static void ring_copy(void *out, const unsigned char *ring, size_t size, uint64_t at, size_t n) {
    size_t off = at % size, first = n < size - off ? n : size - off;
    memcpy(out, ring + off, first);
    if (first < n) memcpy((char *)out + first, ring, n - first);
}
static uint64_t u64(const unsigned char *p) { uint64_t n; memcpy(&n, p, 8); return n; }

// ---- memory windows -------------------------------------------------------
// Grammar: [@]REG[+/-OFFSET][:LEN]
//   "x13:32"       bytes at the address held in x13
//   "@x12+0x40:16" dereference (x12+0x40), then read 16 bytes at that pointer
// REG is x0..x30, sp, lr or pc. OFFSET accepts 0x.. or decimal. LEN defaults to 16.
struct memspec { char text[64]; int reg; int64_t off; int depth; unsigned len; };
static struct memspec mems[MAX_MEM];
static int mem_count;

static int reg_of(const char *s, size_t n) {
    if (n == 2 && s[0] == 'x' && s[1] >= '0' && s[1] <= '9') return s[1] - '0';
    if (n == 3 && s[0] == 'x' && s[1] >= '1' && s[1] <= '2' && s[2] >= '0' && s[2] <= '9') {
        int v = (s[1] - '0') * 10 + (s[2] - '0');
        return v <= 30 ? v : -1;
    }
    if (n == 2 && !strncmp(s, "lr", 2)) return 30;
    if (n == 2 && !strncmp(s, "sp", 2)) return 31;
    if (n == 2 && !strncmp(s, "pc", 2)) return 32;
    return -1;
}
static int parse_mem(const char *text) {
    if (mem_count >= MAX_MEM || !text || !*text) return 0;
    struct memspec m; memset(&m, 0, sizeof(m));
    snprintf(m.text, sizeof(m.text), "%s", text);
    const char *p = text;
    while (*p == '@' && m.depth < 2) { m.depth++; p++; }
    const char *colon = strchr(p, ':');
    size_t head_len = colon ? (size_t)(colon - p) : strlen(p);
    const char *sign = NULL;
    for (size_t i = 0; i < head_len; i++) if (p[i] == '+' || p[i] == '-') { sign = p + i; break; }
    size_t reg_len = sign ? (size_t)(sign - p) : head_len;
    m.reg = reg_of(p, reg_len);
    if (m.reg < 0) return 0;
    if (sign) {
        char *end = NULL; errno = 0;
        m.off = strtoll(sign, &end, 0);
        if (errno || !end || end != colon) return 0;
    }
    m.len = 16;
    if (colon) {
        char *end = NULL; errno = 0;
        unsigned long v = strtoul(colon + 1, &end, 0);
        if (errno || !end || *end || v == 0 || v > MAX_MEM_BYTES) return 0;
        m.len = (unsigned)v;
    }
    mems[mem_count++] = m;
    return 1;
}
// Root reading another process' memory is allowed on this product ROM; both routes are tried
// so an SELinux denial on one is reported as data, never as "no window".
static int read_target(pid_t pid, uint64_t addr, void *buf, size_t n) {
    struct iovec local = { buf, n }, remote = { (void *)(uintptr_t)addr, n };
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)n) return 0;
    char path[40]; snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t got = pread(fd, buf, n, (off_t)addr);
    close(fd);
    return got == (ssize_t)n ? 0 : -1;
}
static void print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

// ---- one perf slot per breakpoint ----------------------------------------
struct perfbp {
    uint64_t addr; uint32_t width; uint32_t type;
    int fd; size_t map_size, data_size;
    struct perf_event_mmap_page *meta;
    unsigned char *data;
    struct pollfd pfd;
};
static struct perfbp bps[MAX_BP];
static int bp_count;

static int open_bp(struct perfbp *b, pid_t tid, uint64_t addr, uint64_t width, uint32_t type,
                   uint64_t stack_bytes) {
    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_BREAKPOINT; attr.size = sizeof(attr);
    attr.bp_type = type; attr.bp_addr = addr; attr.bp_len = width;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
                       PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_REGS_USER;
    attr.sample_regs_user = (UINT64_C(1) << REGS) - 1;
    if (stack_bytes) { attr.sample_type |= PERF_SAMPLE_STACK_USER; attr.sample_stack_user = stack_bytes; }
    // mmap of a task event with inherit enabled is rejected on the reference kernel.
    // The contract names ONE existing thread; never silently claim to cover new threads.
    attr.inherit = 0; attr.disabled = 1; attr.exclude_kernel = 1; attr.exclude_hv = 1; attr.wakeup_events = 1;
    int fd = syscall(__NR_perf_event_open, &attr, (int)tid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) return -1;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t data_size = page * PAGES, map_size = data_size + page;
    struct perf_event_mmap_page *meta = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (meta == MAP_FAILED) { int err = errno; close(fd); errno = err; return -1; }
    b->addr = addr; b->width = (uint32_t)width; b->type = type;
    b->fd = fd; b->map_size = map_size; b->data_size = data_size; b->meta = meta;
    b->data = (unsigned char *)meta + page;
    b->pfd.fd = fd; b->pfd.events = POLLIN; b->pfd.revents = 0;
    return 0;
}
static void close_bp(struct perfbp *b) {
    if (b->fd >= 0) { (void)ioctl(b->fd, PERF_EVENT_IOC_DISABLE, 0); munmap(b->meta, b->map_size); close(b->fd); }
    b->fd = -1;
}

static void emit_mem(pid_t pid, const uint64_t *regs) {
    if (!mem_count) return;
    printf(",\"mem\":[");
    for (int i = 0; i < mem_count; i++) {
        struct memspec *m = &mems[i];
        uint64_t addr = (uint64_t)((int64_t)regs[m->reg] + m->off);
        const char *err = NULL;
        for (int d = 0; d < m->depth && !err; d++) {
            uint64_t ptr = 0;
            if (read_target(pid, addr, &ptr, 8)) err = "unreadable-pointer";
            else if (!ptr) err = "null-pointer";
            else addr = ptr;
        }
        unsigned char buf[MAX_MEM_BYTES];
        if (!err && read_target(pid, addr, buf, m->len)) err = "unreadable";
        printf("%s{\"spec\":\"%s\",\"addr\":\"0x%llx\"", i ? "," : "", m->text, (unsigned long long)addr);
        if (err) printf(",\"error\":\"%s\"}", err);
        else { printf(",\"hex\":\""); print_hex(buf, m->len); printf("\"}"); }
    }
    printf("]");
}

static volatile uint64_t fixture_value;
static volatile uint64_t fixture_ptr;
static int handle_sample(int bp_index, unsigned char *body, size_t n,
                         pid_t pid, pid_t tid, uint64_t stack_bytes, uint64_t *samples,
                         int self_test, uint64_t *self_ok, uint64_t addr) {
    if (n < 40) return 0;
    uint64_t ip = u64(body), time_ns = u64(body + 16), address = u64(body + 24), count = u64(body + 32);
    uint32_t sample_pid, sample_tid; memcpy(&sample_pid, body + 8, 4); memcpy(&sample_tid, body + 12, 4);
    if (count > (n - 40) / 8 || (pid_t)sample_pid != pid || (pid_t)sample_tid != tid) return 0;
    size_t regoff = 40 + (size_t)count * 8;
    if (regoff + 8 + REGS * 8 > n || u64(body + regoff) != PERF_SAMPLE_REGS_ABI_64) return 0;
    uint64_t regs[REGS]; memcpy(regs, body + regoff + 8, sizeof(regs));
    size_t stackoff = regoff + 8 + sizeof(regs); uint64_t captured = 0, reserved = 0;
    if (stack_bytes) {
        if (stackoff + 8 > n) return 0;
        reserved = u64(body + stackoff);
        if (reserved > stack_bytes || reserved > n - stackoff - 8 ||
            (reserved && stackoff + 8 + reserved + 8 > n)) return 0;
        if (reserved) captured = u64(body + stackoff + 8 + reserved);
        if (captured > reserved) return 0;
    }
    (*samples)++;
    printf("{\"seq\":%llu,\"bp\":%d,\"ip\":\"0x%llx\",\"pid\":%u,\"tid\":%u,\"timeNs\":\"%llu\",\"addr\":\"0x%llx\",\"regs\":[",
           (unsigned long long)*samples, bp_index, (unsigned long long)ip, sample_pid, sample_tid,
           (unsigned long long)time_ns, (unsigned long long)address);
    for (int j = 0; j < REGS; j++) printf("%s\"0x%llx\"", j ? "," : "", (unsigned long long)regs[j]);
    printf("],\"chain\":[");
    size_t emitted_chain = count < 64 ? (size_t)count : 64;
    for (size_t j = 0; j < emitted_chain; j++) printf("%s\"0x%llx\"", j ? "," : "", (unsigned long long)u64(body + 40 + j * 8));
    printf("],\"chainTruncated\":%s", count > 64 ? "true" : "false");
    emit_mem(pid, regs);
    printf(",\"stack\":{\"addr\":\"0x%llx\",\"requested\":%llu,\"got\":%llu,\"hex\":\"",
           (unsigned long long)regs[31], (unsigned long long)stack_bytes, (unsigned long long)captured);
    for (size_t j = 0; j < captured; j++) printf("%02x", body[stackoff + 8 + j]);
    puts("\"}}"); fflush(stdout);
    if (self_test && regs[0] == addr && regs[1] == (uint64_t)(uintptr_t)&fixture_value) *self_ok = 1;
    if (self_test && bp_index == 1) *self_ok |= 2;
    return 1;
}

__attribute__((naked, noinline)) static void fixture(volatile uint64_t *p, uint64_t value) {
    __asm__ volatile("str x1, [x0]\nret");
}
__attribute__((naked, noinline)) static void fixture_load(volatile uint64_t *p) {
    __asm__ volatile("ldr x0, [x0]\nret");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts(VERSION); return 0; }
    if (geteuid() != 0) { errno = EPERM; return fail("root-required"); }
    uint64_t pid, tid, addr, width, duration, maximum, stack_bytes;
    const char *stop_file = NULL;
    uint32_t type;
    int test_child = -1, gate[2] = {-1, -1};
    int self_test = argc == 2 && !strcmp(argv[1], "--self-test");
    int self_test_read = 0;
    int first_extra = argc;
    if (self_test) {
        if (pipe(gate)) return fail("self-test-pipe");
        test_child = fork();
        if (test_child < 0) return fail("self-test-fork");
        if (!test_child) {
            close(gate[1]); char b;
            if (read(gate[0], &b, 1) == 1) { fixture(&fixture_value, UINT64_C(0x1122334455667788)); fixture(&fixture_ptr, (uint64_t)(uintptr_t)&fixture_value); fixture_load(&fixture_value); }
            close(gate[0]); usleep(200000); _exit(0);
        }
        close(gate[0]); gate[0] = -1;
        pid = tid = (uint64_t)test_child; addr = (uintptr_t)&fixture_ptr;
        width = 8; duration = 1000; maximum = 3; stack_bytes = 256; type = HW_BREAKPOINT_W;
        // Self-test also proves the memory-window path: the fixture stores a known
        // value at a known address, so a window on x0 must read it back.
        if (!parse_mem("x0:8")) return fail("self-test-mem");
        if (!parse_mem("@@x0:8")) return fail("self-test-mem2");

        self_test_read = 1;
        first_extra = 2;
    } else {
        if (argc < 9 || !number(argv[1], &pid) || !number(argv[2], &tid) ||
            !number(argv[3], &addr) || !number(argv[4], &width) ||
            !number(argv[6], &duration) || !number(argv[7], &maximum) || !number(argv[8], &stack_bytes)) {
            fprintf(stderr, "usage: adh-root-watch PID TID ADDRESS WIDTH w|r|rw|x DURATION_MS MAX_EVENTS STACK_BYTES [STOP_FILE] [bp=ADDR:WIDTH:MODE] [mem=SPEC]\n");
            return 2;
        }
        type = !strcmp(argv[5], "w") ? HW_BREAKPOINT_W : !strcmp(argv[5], "r") ? HW_BREAKPOINT_R :
               !strcmp(argv[5], "rw") ? HW_BREAKPOINT_RW : !strcmp(argv[5], "x") ? HW_BREAKPOINT_X : 0;
        if (!pid || pid > INT32_MAX || !tid || tid > INT32_MAX || !addr || !type ||
            !(width == 1 || width == 2 || width == 4 || width == 8) || addr % width ||
            (type == HW_BREAKPOINT_X && width != 4) || duration < 1 || duration > 30000 ||
            maximum < 1 || maximum > 2048 || stack_bytes > 16384 || stack_bytes % 8) return 2;
        int at = 9;
        if (argc > at && strncmp(argv[at], "bp=", 3) && strncmp(argv[at], "mem=", 4)) {
            const char *prefix = "/data/local/tmp/adh-root-watch-stop-";
            size_t prefix_len = strlen(prefix);
            if (strncmp(argv[at], prefix, prefix_len) || strlen(argv[at] + prefix_len) != 36) return 2;
            for (const char *p = argv[at] + prefix_len; *p; p++)
                if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || *p == '-')) return 2;
            stop_file = argv[at];
            at++;
        }
        first_extra = at;
        char path[80], line[256]; snprintf(path, sizeof(path), "/proc/%llu/status", (unsigned long long)tid);
        FILE *f = fopen(path, "r"); if (!f) return fail("thread-status");
        unsigned long owner = 0;
        while (fgets(line, sizeof(line), f)) if (sscanf(line, "Tgid: %lu", &owner) == 1) break;
        fclose(f);
        if (owner != pid) { errno = EINVAL; return fail("tid-does-not-belong-to-pid"); }
    }
    bps[0].addr = addr; bps[0].width = (uint32_t)width; bps[0].type = type; bps[0].fd = -1;
    bp_count = 1;
    if (self_test_read) { bps[1].addr = (uintptr_t)&fixture_value; bps[1].width = 8; bps[1].type = HW_BREAKPOINT_R; bps[1].fd = -1; bp_count = 2; }
    for (int i = first_extra; i < argc; i++) {
        const char *arg = argv[i];
        if (!strncmp(arg, "mem=", 4)) {
            if (!parse_mem(arg + 4)) { fprintf(stderr, "bad mem spec: %s\n", arg + 4); return 2; }
        } else if (!strncmp(arg, "bp=", 3)) {
            if (bp_count >= MAX_BP) { fprintf(stderr, "at most %d breakpoints\n", MAX_BP); return 2; }
            char *p = (char *)arg + 3, *c1 = strchr(p, ':');
            if (!c1) { fprintf(stderr, "bad bp spec: %s\n", arg); return 2; }
            *c1 = 0; char *c2 = strchr(c1 + 1, ':');
            if (!c2) { fprintf(stderr, "bad bp spec: %s\n", arg); return 2; }
            *c2 = 0;
            uint64_t a2, w2;
            if (!number(p, &a2) || !number(c1 + 1, &w2)) return 2;
            uint32_t t2 = !strcmp(c2 + 1, "w") ? HW_BREAKPOINT_W : !strcmp(c2 + 1, "r") ? HW_BREAKPOINT_R :
                          !strcmp(c2 + 1, "rw") ? HW_BREAKPOINT_RW : !strcmp(c2 + 1, "x") ? HW_BREAKPOINT_X : 0;
            if (!a2 || !t2 || !(w2 == 1 || w2 == 2 || w2 == 4 || w2 == 8) || a2 % w2 ||
                (t2 == HW_BREAKPOINT_X && w2 != 4)) { fprintf(stderr, "bad bp spec\n"); return 2; }
            bps[bp_count].addr = a2; bps[bp_count].width = (uint32_t)w2; bps[bp_count].type = t2;
            bps[bp_count].fd = -1; bp_count++;
        } else { fprintf(stderr, "unknown extra arg: %s\n", arg); return 2; }
    }
    // perf exposes a small number of hardware slots per thread; fail loud rather than
    // silently dropping the slots that did not fit.
    for (int i = 0; i < bp_count; i++) {
        if (open_bp(&bps[i], (pid_t)tid, bps[i].addr, bps[i].width, bps[i].type, stack_bytes)) {
            int err = errno;
            for (int j = 0; j < i; j++) close_bp(&bps[j]);
            if (test_child > 0) { close(gate[1]); waitpid(test_child, 0, 0); }
            errno = err;
            return fail(i == 0 ? "perf_event_open" : "perf_event_open_extra");
        }
    }
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal);
    for (int i = 0; i < bp_count; i++)
        if (ioctl(bps[i].fd, PERF_EVENT_IOC_ENABLE, 0)) {
            for (int j = 0; j < bp_count; j++) close_bp(&bps[j]);
            return fail("enable");
        }
    printf("{\"ready\":true,\"version\":\"%s\",\"collectorPid\":%d,\"pid\":%llu,\"tid\":%llu,\"breakpoints\":%d,\"mem\":%d}\n",
           VERSION, getpid(), (unsigned long long)pid, (unsigned long long)tid, bp_count, mem_count);
    fflush(stdout);
    if (self_test) { (void)write(gate[1], "x", 1); close(gate[1]); gate[1] = -1; }
    uint64_t samples = 0, lost = 0, throttles = 0, malformed = 0;
    uint64_t self_ok = 0; int64_t until = millis() + (int64_t)duration;
    int disabled = 0, thread_exited = 0;
    for (;;) {
        if (stop_file && access(stop_file, F_OK) == 0) stopping = 1;
        if (!disabled && (stopping || millis() >= until || samples >= maximum)) {
            for (int i = 0; i < bp_count; i++) if (ioctl(bps[i].fd, PERF_EVENT_IOC_DISABLE, 0)) malformed++;
            disabled = 1;
        }
        // Disable BEFORE the last drain. Otherwise a final write can land between
        // the last head snapshot and close(), while the report says complete.
        int rc = 0;
        if (!disabled) {
            rc = poll(&bps[0].pfd, (nfds_t)bp_count, 50);
            if (rc < 0 && errno != EINTR) { malformed++; break; }
            for (int i = 0; i < bp_count; i++) {
                if (bps[i].pfd.revents & (POLLHUP | POLLERR)) {
                    if (bps[i].pfd.revents & POLLERR) malformed++;
                    thread_exited |= (bps[i].pfd.revents & POLLHUP) != 0;
                    for (int j = 0; j < bp_count; j++) (void)ioctl(bps[j].fd, PERF_EVENT_IOC_DISABLE, 0);
                    disabled = 1;
                }
            }
        }
        for (int i = 0; i < bp_count; i++) {
            struct perfbp *b = &bps[i];
            uint64_t head = __atomic_load_n(&b->meta->data_head, __ATOMIC_ACQUIRE), tail = b->meta->data_tail;
            if (head - tail > b->data_size) { malformed++; tail = head; }
            while (tail < head && samples < maximum) {
                struct perf_event_header h; ring_copy(&h, b->data, b->data_size, tail, sizeof(h));
                if (h.size < sizeof(h) || h.size > b->data_size || h.size > head - tail) { malformed++; tail = head; break; }
                unsigned char body[32768]; size_t n = h.size - sizeof(h);
                if (n > sizeof(body)) { malformed++; tail += h.size; continue; }
                ring_copy(body, b->data, b->data_size, tail + sizeof(h), n);
                if (h.type == PERF_RECORD_LOST && n >= 16) lost += u64(body + 8);
                else if (h.type == PERF_RECORD_THROTTLE) throttles++;
                else if (h.type == PERF_RECORD_SAMPLE) {
                    if (!handle_sample(i, body, n, (pid_t)pid, (pid_t)tid, stack_bytes,
                                       &samples, self_test, &self_ok, addr)) { /* skipped */ }
                }
                tail += h.size;
            }
            __atomic_store_n(&b->meta->data_tail, tail, __ATOMIC_RELEASE);
        }
        if (disabled) break;
    }
    for (int i = 0; i < bp_count; i++) close_bp(&bps[i]);
    if (stop_file) (void)unlink(stop_file);
    if (test_child > 0) waitpid(test_child, NULL, 0);
    int capped = samples >= maximum;
    printf("{\"done\":true,\"samples\":%llu,\"lost\":%llu,\"throttles\":%llu,\"malformed\":%llu,\"complete\":%s,\"stopReason\":\"%s\",\"selfTest\":%s}\n",
           (unsigned long long)samples, (unsigned long long)lost, (unsigned long long)throttles, (unsigned long long)malformed,
           !lost && !throttles && !malformed && !capped && !stopping ? "true" : "false",
           stopping ? "stopped" : capped ? "event-limit" : thread_exited ? "thread-exited" : "time-budget", self_test ? (self_ok ? "true" : "false") : "null");
    return self_test && self_ok != 3 ? 1 : 0;
}

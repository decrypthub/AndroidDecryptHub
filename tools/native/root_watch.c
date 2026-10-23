// Root-side collector. perf records the real target execution; no ptrace, app patch,
// function replay, SELinux change, or in-process agent dependency is involved.
#define _GNU_SOURCE
#include <errno.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VERSION "ADH_ROOT_WATCH_V1"
// https://github.com/torvalds/linux/blob/v5.10/arch/arm64/include/uapi/asm/perf_regs.h
#define REGS 33 // Linux arm64 perf ABI: x0..x29, lr, sp, pc (not pstate).
#define PAGES 256
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

static volatile uint64_t fixture_value;
__attribute__((naked, noinline)) static void fixture(volatile uint64_t *p, uint64_t value) {
    __asm__ volatile("str x1, [x0]\nret");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts(VERSION); return 0; }
    if (geteuid() != 0) { errno = EPERM; return fail("root-required"); }
    uint64_t pid, tid, addr, width, duration, maximum, stack_bytes;
    const char *stop_file = NULL;
    int type, test_child = -1, gate[2] = {-1, -1};
    int self_test = argc == 2 && !strcmp(argv[1], "--self-test");
    if (self_test) {
        if (pipe(gate)) return fail("self-test-pipe");
        test_child = fork();
        if (test_child < 0) return fail("self-test-fork");
        if (!test_child) {
            close(gate[1]); char b;
            if (read(gate[0], &b, 1) == 1) fixture(&fixture_value, UINT64_C(0x1122334455667788));
            close(gate[0]); usleep(200000); _exit(0);
        }
        close(gate[0]); gate[0] = -1;
        pid = tid = (uint64_t)test_child; addr = (uintptr_t)&fixture_value;
        width = 8; duration = 1000; maximum = 2; stack_bytes = 256; type = HW_BREAKPOINT_W;
    } else {
        if ((argc != 9 && argc != 10) || !number(argv[1], &pid) || !number(argv[2], &tid) ||
            !number(argv[3], &addr) || !number(argv[4], &width) ||
            !number(argv[6], &duration) || !number(argv[7], &maximum) || !number(argv[8], &stack_bytes)) {
            fprintf(stderr, "usage: adh-root-watch PID TID ADDRESS WIDTH w|r|rw|x DURATION_MS MAX_EVENTS STACK_BYTES\n");
            return 2;
        }
        type = !strcmp(argv[5], "w") ? HW_BREAKPOINT_W : !strcmp(argv[5], "r") ? HW_BREAKPOINT_R :
               !strcmp(argv[5], "rw") ? HW_BREAKPOINT_RW : !strcmp(argv[5], "x") ? HW_BREAKPOINT_X : 0;
        if (!pid || pid > INT32_MAX || !tid || tid > INT32_MAX || !addr || !type ||
            !(width == 1 || width == 2 || width == 4 || width == 8) || addr % width ||
            (type == HW_BREAKPOINT_X && width != 4) || duration < 1 || duration > 30000 ||
            maximum < 1 || maximum > 2048 || stack_bytes > 16384 || stack_bytes % 8) return 2;
        if (argc == 10) {
            const char *prefix = "/data/local/tmp/adh-root-watch-stop-";
            size_t prefix_len = strlen(prefix);
            if (strncmp(argv[9], prefix, prefix_len) || strlen(argv[9] + prefix_len) != 36) return 2;
            for (const char *p = argv[9] + prefix_len; *p; p++)
                if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || *p == '-')) return 2;
            stop_file = argv[9];
        }
        char path[80], line[256]; snprintf(path, sizeof(path), "/proc/%llu/status", (unsigned long long)tid);
        FILE *f = fopen(path, "r"); if (!f) return fail("thread-status");
        unsigned long owner = 0;
        while (fgets(line, sizeof(line), f)) if (sscanf(line, "Tgid: %lu", &owner) == 1) break;
        fclose(f);
        if (owner != pid) { errno = EINVAL; return fail("tid-does-not-belong-to-pid"); }
    }
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
    if (fd < 0) { if (test_child > 0) { close(gate[1]); waitpid(test_child, 0, 0); } return fail("perf_event_open"); }
    size_t page = (size_t)sysconf(_SC_PAGESIZE), data_size = page * PAGES, map_size = data_size + page;
    struct perf_event_mmap_page *meta = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (meta == MAP_FAILED) { int err = errno; close(fd); errno = err; return fail("mmap"); }
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal);
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) { int err = errno; munmap(meta, map_size); close(fd); errno = err; return fail("enable"); }
    printf("{\"ready\":true,\"version\":\"%s\",\"collectorPid\":%d,\"pid\":%llu,\"tid\":%llu}\n",
           VERSION, getpid(), (unsigned long long)pid, (unsigned long long)tid); fflush(stdout);
    if (self_test) { (void)write(gate[1], "x", 1); close(gate[1]); gate[1] = -1; }
    unsigned char *data = (unsigned char *)meta + page;
    uint64_t samples = 0, lost = 0, throttles = 0, malformed = 0;
    int self_ok = 0; int64_t until = millis() + (int64_t)duration;
    struct pollfd pollfd = {fd, POLLIN, 0};
    int disabled = 0, thread_exited = 0;
    for (;;) {
        if (stop_file && access(stop_file, F_OK) == 0) stopping = 1;
        if (!disabled && (stopping || millis() >= until || samples >= maximum)) {
            if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0)) malformed++;
            disabled = 1;
        }
        // Disable BEFORE the last drain. Otherwise a final write can land between
        // the last head snapshot and close(), while the report says complete.
        int rc = disabled ? 0 : poll(&pollfd, 1, 50);
        if (rc < 0 && errno != EINTR) { malformed++; break; }
        if (!disabled && (pollfd.revents & (POLLHUP | POLLERR))) {
            if (pollfd.revents & POLLERR) malformed++;
            thread_exited = (pollfd.revents & POLLHUP) != 0;
            (void)ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            disabled = 1;
        }
        uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE), tail = meta->data_tail;
        if (head - tail > data_size) { malformed++; tail = head; }
        while (tail < head && samples < maximum) {
            struct perf_event_header h; ring_copy(&h, data, data_size, tail, sizeof(h));
            if (h.size < sizeof(h) || h.size > data_size || h.size > head - tail) { malformed++; tail = head; break; }
            unsigned char body[32768]; size_t n = h.size - sizeof(h);
            if (n > sizeof(body)) { malformed++; tail += h.size; continue; }
            ring_copy(body, data, data_size, tail + sizeof(h), n);
            if (h.type == PERF_RECORD_LOST && n >= 16) lost += u64(body + 8);
            else if (h.type == PERF_RECORD_THROTTLE) throttles++;
            else if (h.type == PERF_RECORD_SAMPLE) {
                if (n < 40) { malformed++; tail += h.size; continue; }
                uint64_t ip = u64(body), time_ns = u64(body + 16), address = u64(body + 24), count = u64(body + 32);
                uint32_t sample_pid, sample_tid; memcpy(&sample_pid, body + 8, 4); memcpy(&sample_tid, body + 12, 4);
                if (count > (n - 40) / 8 || sample_pid != pid || sample_tid != tid) { malformed++; tail += h.size; continue; }
                size_t regoff = 40 + (size_t)count * 8;
                if (regoff + 8 + REGS * 8 > n || u64(body + regoff) != PERF_SAMPLE_REGS_ABI_64) { malformed++; tail += h.size; continue; }
                uint64_t regs[REGS]; memcpy(regs, body + regoff + 8, sizeof(regs));
                size_t stackoff = regoff + 8 + sizeof(regs); uint64_t captured = 0, reserved = 0;
                if (stack_bytes) {
                    if (stackoff + 8 > n) { malformed++; tail += h.size; continue; }
                    reserved = u64(body + stackoff);
                    if (reserved > stack_bytes || reserved > n - stackoff - 8 ||
                        (reserved && stackoff + 8 + reserved + 8 > n)) { malformed++; tail += h.size; continue; }
                    if (reserved) captured = u64(body + stackoff + 8 + reserved);
                    if (captured > reserved) { malformed++; tail += h.size; continue; }
                }
                samples++;
                printf("{\"seq\":%llu,\"ip\":\"0x%llx\",\"pid\":%u,\"tid\":%u,\"timeNs\":\"%llu\",\"addr\":\"0x%llx\",\"regs\":[",
                       (unsigned long long)samples, (unsigned long long)ip, sample_pid, sample_tid,
                       (unsigned long long)time_ns, (unsigned long long)address);
                for (int j = 0; j < REGS; j++) printf("%s\"0x%llx\"", j ? "," : "", (unsigned long long)regs[j]);
                printf("],\"chain\":[");
                size_t emitted_chain = count < 64 ? (size_t)count : 64;
                for (size_t j = 0; j < emitted_chain; j++) printf("%s\"0x%llx\"", j ? "," : "", (unsigned long long)u64(body + 40 + j * 8));
                printf("],\"chainTruncated\":%s,\"stack\":{\"addr\":\"0x%llx\",\"requested\":%llu,\"got\":%llu,\"hex\":\"",
                       count > 64 ? "true" : "false", (unsigned long long)regs[31],
                       (unsigned long long)stack_bytes, (unsigned long long)captured);
                for (size_t j = 0; j < captured; j++) printf("%02x", body[stackoff + 8 + j]);
                puts("\"}}"); fflush(stdout);
                if (self_test && regs[0] == addr && regs[1] == UINT64_C(0x1122334455667788)) self_ok = 1;
            }
            tail += h.size;
        }
        __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
        if (disabled) break;
    }
    (void)ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); munmap(meta, map_size); close(fd);
    if (stop_file) (void)unlink(stop_file);
    if (test_child > 0) waitpid(test_child, NULL, 0);
    int capped = samples >= maximum;
    printf("{\"done\":true,\"samples\":%llu,\"lost\":%llu,\"throttles\":%llu,\"malformed\":%llu,\"complete\":%s,\"stopReason\":\"%s\",\"selfTest\":%s}\n",
           (unsigned long long)samples, (unsigned long long)lost, (unsigned long long)throttles, (unsigned long long)malformed,
           !lost && !throttles && !malformed && !capped && !stopping ? "true" : "false",
           stopping ? "stopped" : capped ? "event-limit" : thread_exited ? "thread-exited" : "time-budget", self_test ? (self_ok ? "true" : "false") : "null");
    return self_test && !self_ok ? 1 : 0;
}

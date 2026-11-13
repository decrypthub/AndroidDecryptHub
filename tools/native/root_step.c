// Root-side single-step tracer. Attaches to one EXISTING thread with ptrace, steps it
// one instruction at a time and records the program counter, the stack pointer and the
// integer argument registers before each step. This is the out-of-process answer to "what
// does this code actually execute": no agent, no code patching, no function replay.
//
// Honest limits, because they decide whether a trace is trustworthy:
//   * ptrace sets TracerPid, so a target that inspects itself can see the tracer;
//   * only the named TID is traced, and it must belong to PID;
//   * a step budget and a wall-clock budget are always enforced;
//   * the trace is a prefix: when the budget is reached the thread is detached and the
//     reply says complete:false.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define VERSION "ADH_ROOT_STEP_V1"
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#define MAX_STEPS 200000

// aarch64 NT_PRSTATUS payload (struct user_pt_regs).
struct pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

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
static int get_regs(pid_t tid, struct pt_regs *regs) {
    struct iovec io = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &io);
}

static volatile int sink;
__attribute__((noinline)) static void tick(void) {
    __asm__ volatile("add %w0, %w0, #1" : "+r"(sink));
    __asm__ volatile("nop; nop; nop");
}
static void spin_forever(void) {
    // Re-enters tick() forever, so a breakpoint written on its entry is executed again.
    for (;;) tick();
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) { puts(VERSION); return 0; }
    if (geteuid() != 0) { errno = EPERM; return fail("root-required"); }
    uint64_t pid = 0, tid = 0, steps = 0, budget_ms = 0, break_addr = 0;
    int self_test_bp = argc == 2 && !strcmp(argv[1], "--self-test-bp");
    int self_test = self_test_bp || (argc == 2 && !strcmp(argv[1], "--self-test"));
    pid_t child = -1;
    if (self_test) {
        child = fork();
        if (child < 0) return fail("self-test-fork");
        if (!child) { spin_forever(); _exit(0); }
        pid = tid = (uint64_t)child; steps = 8; budget_ms = 2000;
        if (self_test_bp) break_addr = (uint64_t)(uintptr_t)&spin_forever;
    } else {
        if ((argc != 5 && argc != 6) || !number(argv[1], &pid) || !number(argv[2], &tid) ||
            !number(argv[3], &steps) || !number(argv[4], &budget_ms)) {
            fprintf(stderr, "usage: adh-root-step PID TID STEPS TIMEOUT_MS [BREAK_ADDR]\n");
            return 2;
        }
        if (!pid || pid > INT32_MAX || !tid || tid > INT32_MAX || !steps || steps > MAX_STEPS ||
            !budget_ms || budget_ms > 120000) return 2;
        // The collector must not silently trace a different thread than the one asked for.
        char path[64], line[256]; snprintf(path, sizeof(path), "/proc/%llu/status", (unsigned long long)tid);
        FILE *f = fopen(path, "r"); if (!f) return fail("thread-status");
        unsigned long owner = 0;
        while (fgets(line, sizeof(line), f)) if (sscanf(line, "Tgid: %lu", &owner) == 1) break;
        fclose(f);
        if (owner != pid) { errno = EINVAL; return fail("tid-does-not-belong-to-pid"); }
    }
    if (ptrace(PTRACE_ATTACH, (pid_t)tid, NULL, NULL)) return fail("ptrace-attach");
    int status = 0;
    if (waitpid((pid_t)tid, &status, __WALL) < 0) return fail("wait-attach");
    if (!WIFSTOPPED(status)) { errno = ESRCH; return fail("attach-not-stopped"); }
    if (argc == 6 || self_test_bp) {
        if (argc == 6 && (!number(argv[5], &break_addr) || !break_addr)) { errno = EINVAL; return fail("break-address"); }
        errno = 0;
        unsigned long orig = ptrace(PTRACE_PEEKDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, NULL);
        if (errno) return fail("peek-break");
        unsigned long brk = (orig & ~0xffffffffUL) | 0xd4200000UL; /* brk #0 */
        if (ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)brk)) return fail("poke-break");
        int armed = 0;
        int64_t break_until = millis() + (int64_t)budget_ms;
        while (!armed) {
            if (ptrace(PTRACE_CONT, (pid_t)tid, NULL, NULL)) {
                (void)ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig);
                return fail("cont");
            }
            if (waitpid((pid_t)tid, &status, __WALL) < 0) {
                (void)ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig);
                return fail("wait-break");
            }
            if (millis() > break_until) {
                (void)ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig);
                errno = ETIMEDOUT; return fail("break-timeout");
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                (void)ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig);
                errno = ESRCH; return fail("break-thread-exited");
            }
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { armed = 1; break; }
            if (WIFSTOPPED(status)) {
                /* Not our trap: deliver the signal and keep waiting for the breakpoint. */
                if (ptrace(PTRACE_CONT, (pid_t)tid, NULL, (void *)(long)WSTOPSIG(status))) {
                    (void)ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig);
                    return fail("signal-forward");
                }
            }
        }
        if (ptrace(PTRACE_POKEDATA, (pid_t)tid, (void *)(uintptr_t)break_addr, (void *)orig)) return fail("restore-break");
        struct pt_regs br;
        if (get_regs((pid_t)tid, &br)) return fail("break-getregs");
        br.pc = break_addr;
        struct iovec io = { &br, sizeof(br) };
        if (ptrace(PTRACE_SETREGSET, (pid_t)tid, (void *)NT_PRSTATUS, &io)) return fail("break-setregs");
        printf("{\"break\":\"0x%llx\",\"hit\":true}\n", (unsigned long long)break_addr);
        fflush(stdout);
    }
    printf("{\"ready\":true,\"version\":\"%s\",\"collectorPid\":%d,\"pid\":%llu,\"tid\":%llu,\"budget\":%llu,\"budgetMs\":%llu}\n",
           VERSION, getpid(), (unsigned long long)pid, (unsigned long long)tid,
           (unsigned long long)steps, (unsigned long long)budget_ms);
    fflush(stdout);
    int64_t until = millis() + (int64_t)budget_ms;
    uint64_t done = 0, unreadable = 0;
    const char *stop = "budget";
    for (;;) {
        if (done >= steps) { stop = "step-budget"; break; }
        if (millis() >= until) { stop = "time-budget"; break; }
        struct pt_regs r;
        if (get_regs((pid_t)tid, &r)) { stop = "getregs"; break; }
        unsigned char insn[4]; int have = read_target((pid_t)tid, r.pc, insn, 4) == 0;
        if (!have) unreadable++;
        printf("{\"n\":%llu,\"pc\":\"0x%llx\",\"sp\":\"0x%llx\",\"lr\":\"0x%llx\""
               ",\"x0\":\"0x%llx\",\"x1\":\"0x%llx\",\"x2\":\"0x%llx\",\"x3\":\"0x%llx\""
               ",\"x4\":\"0x%llx\",\"x5\":\"0x%llx\",\"x6\":\"0x%llx\",\"x7\":\"0x%llx\""
               ",\"x8\":\"0x%llx\",\"x9\":\"0x%llx\",\"x10\":\"0x%llx\",\"x11\":\"0x%llx\",\"x12\":\"0x%llx\"",
               (unsigned long long)done, (unsigned long long)r.pc, (unsigned long long)r.sp,
               (unsigned long long)r.regs[30], (unsigned long long)r.regs[0], (unsigned long long)r.regs[1],
               (unsigned long long)r.regs[2], (unsigned long long)r.regs[3], (unsigned long long)r.regs[4],
               (unsigned long long)r.regs[5], (unsigned long long)r.regs[6], (unsigned long long)r.regs[7],
               (unsigned long long)r.regs[8], (unsigned long long)r.regs[9], (unsigned long long)r.regs[10],
               (unsigned long long)r.regs[11], (unsigned long long)r.regs[12]);
        if (have) {
            unsigned word; memcpy(&word, insn, 4);
            printf(",\"insn\":\"0x%08x\"", word);
        }
        puts("}");
        fflush(stdout);
        done++;
        if (ptrace(PTRACE_SINGLESTEP, (pid_t)tid, NULL, NULL)) { stop = "singlestep"; break; }
        if (waitpid((pid_t)tid, &status, __WALL) < 0) { stop = "wait-step"; break; }
        if (WIFEXITED(status) || WIFSIGNALED(status)) { stop = "thread-exited"; break; }
        if (!WIFSTOPPED(status)) { stop = "not-stopped"; break; }
    }
    (void)ptrace(PTRACE_DETACH, (pid_t)tid, NULL, NULL);
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    printf("{\"done\":true,\"steps\":%llu,\"unreadable\":%llu,\"stopReason\":\"%s\",\"complete\":%s,\"selfTest\":%s}\n",
           (unsigned long long)done, (unsigned long long)unreadable, stop,
           (done && strcmp(stop, "budget") != 0) ? "true" : "false",
           self_test ? (done >= 5 ? "true" : "false") : "null");
    return self_test && done < 5 ? 1 : 0;
}

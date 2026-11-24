// ---- native hooks (split from native_hooks.cpp) -------------------------
#include "native_hooks_internal.h"

 int trace_from_stub_index(const char *spec, char *canon, size_t canon_size) {
    if (!spec || !spec[0]) return -1;
    const char *p = spec;
    while (*p == ' ') p++;
    if (*p != 'x') return -2;
    p++;
    char *end = nullptr;
    long n = strtol(p, &end, 10);
    if (end == p) return -2;
    while (*end == ' ') end++;
    if (*end) return -2;
    int idx;
    if (n >= 0 && n <= 9) idx = (int)n;
    else if (n == 29) idx = 10;
    else if (n == 30) idx = 11;
    else return -2;
    if (canon && canon_size) snprintf(canon, canon_size, "x%ld", n);
    return idx;
}

// One `x<reg>[+<off>]:<len>` window. `mem` (up to four), the single post-call `memAfter` window and
// the hardware-watch after-arm all name the SAME thing, so they share one parser and one canonical
// spelling. Three hand-rolled copies used to exist and had already drifted: different error text for
// the same mistake, and a per-window ceiling baked into whichever copy you were reading. The only
// difference that is real is the length ceiling (a `mem` window is copied on every hit, an output

 int parse_window(const char **pp, int max_len, const char *label, WinSpec *w,
                        char *error, size_t error_size) {
    const char *p = *pp;
    while (*p == ' ') p++;
    w->deref = 0;
    w->from_win = 0;
    w->absolute = 0;
    w->abs_addr = 0;
    if (*p == '@' && p[1] == '#') {
        // "@#<n>[+<off>]:<len>" - follow a pointer that an earlier window already copied.
        p += 2;
        if (*p < '1' || *p > '9') {
            set_error(error, error_size, "%s window reference must be @#<n> with n >= 1", label);
            return 0;
        }
        long long win = 0;
        while (*p >= '0' && *p <= '9') {
            win = win * 10 + (*p - '0');
            if (win > ADH_MEM_WIN_MAX) {
                set_error(error, error_size, "%s window reference exceeds %d", label, ADH_MEM_WIN_MAX);
                return 0;
            }
            p++;
        }
        w->from_win = (int)win;
        w->reg = -1;
        w->off = 0;
        w->deref = 2;
    } else if (*p == '@') {
        // One level of indirection. A VM frame, a dispatch slot or a list head is a pointer OF a
        // pointer: the bytes that matter are not at the register, so a plain window can only ever
        // report the frame's own links. Measured on libjdg: the interpreter's current instruction
        // record is at *[x2+0x20], and without this the bytecode was unreadable at the one moment it
        // was live.
        w->deref = 1;
        p++;
    }
    if (w->deref != 2) {
        // Absolute form: "0x7443113690:32". Only the write watch accepts it (a `mem` window must start at a
        // register); it is what lets a caller watch an address learned from an earlier hit.
        const char *q = p;
        int is_abs = 0;
        if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) { q += 2; is_abs = 1; }
        else if (q[0] >= '0' && q[0] <= '9') { is_abs = 1; }
        if (is_abs) {
            unsigned long long addr = 0;
            int digits = 0;
            while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
                int d = (*q <= '9') ? (*q - '0') : ((*q | 0x20) - 'a' + 10);
                if (digits >= 16) break;
                addr = (addr << 4) | (unsigned long long)d;
                digits++;
                q++;
            }
            if (digits < 1) {
                set_error(error, error_size, "%s window must look like x0:64, x2+16:32, x3-40:40 or 0xADDR:32", label);
                return 0;
            }
            w->absolute = 1;
            w->abs_addr = addr;
            w->reg = -1;
            w->off = 0;
            p = q;
        } else {
            if (p[0] != 'x' || p[1] < '0' || p[1] > '8') {
                set_error(error, error_size, "%s window must look like x0:64, x2+16:32, x3-40:40, @x2+32:512 or @#2+8:256", label);
                return 0;
            }
            w->absolute = 0;
            w->abs_addr = 0;
            w->reg = p[1] - '0';
            p += 2;
            w->off = 0;
        }
    }
    if (*p == '+' || *p == '-') {
        // A NEGATIVE offset is what makes "what did the code do just before this" readable: a template
        // interpreter keeps its instruction records in one contiguous array, so the record that produced
        // the value a handler is about to render sits at `pc - 10`, i.e. BEFORE the pointer the handler
        // was given. Without this, a hit-time window can only ever look forward.
        const int negative = (*p == '-');
        p++;
        if (*p < '0' || *p > '9') {
            set_error(error, error_size, "%s offset must be a decimal number", label);
            return 0;
        }
        long long off = 0;
        while (*p >= '0' && *p <= '9') {
            off = off * 10 + (*p - '0');
            if (off > ADH_MEM_WIN_OFF_MAX) {
                set_error(error, error_size, "%s offset exceeds %d", label, ADH_MEM_WIN_OFF_MAX);
                return 0;
            }
            p++;
        }
        // @#<n> offsets index into an earlier window's BYTES, so they stay unsigned: a negative index
        // there would be a different (and meaningless) question.
        if (negative && w->deref == 2) {
            set_error(error, error_size, "%s window reference offset must be positive (@#<n>+<off>)", label);
            return 0;
        }
        w->off = negative ? -(int)off : (int)off;
    }
    if (*p != ':') {
        set_error(error, error_size, "%s window must look like x0:64, x2+16:32, x3-40:40, @x2+32:512 or @#2+8:256", label);
        return 0;
    }
    p++;
    if (*p < '0' || *p > '9') {
        set_error(error, error_size, "%s length must be a decimal number", label);
        return 0;
    }
    long long len = 0;
    while (*p >= '0' && *p <= '9') {
        len = len * 10 + (*p - '0');
        if (len > max_len) {
            set_error(error, error_size, "%s length must be 1..%d", label, max_len);
            return 0;
        }
        p++;
    }
    if (len < 1) {
        set_error(error, error_size, "%s length must be 1..%d", label, max_len);
        return 0;
    }
    w->len = (int)len;
    *pp = p;
    return 1;
}

// Canonical spelling of a window: a zero offset is dropped. Printing it unconditionally produced
// "x00:64", which looks like a typo in every log line and in status.
 int format_window(char *buf, size_t n, const WinSpec *w) {
    if (w->deref == 2) {
        if (w->off) return snprintf(buf, n, "@#%d+%d:%d", w->from_win, w->off, w->len);
        return snprintf(buf, n, "@#%d:%d", w->from_win, w->len);
    }
    const char *at = w->deref ? "@" : "";
    if (w->absolute) return snprintf(buf, n, "0x%llx:%d", w->abs_addr, w->len);
    // A negative offset keeps its sign in the canonical spelling ("x3-40:40"): the status echo is what a
    // caller re-reads to know whether a window looks backwards, and "+-40" would be unparseable.
    if (w->off > 0) return snprintf(buf, n, "%sx%d+%d:%d", at, w->reg, w->off, w->len);
    if (w->off < 0) return snprintf(buf, n, "%sx%d-%d:%d", at, w->reg, -w->off, w->len);
    return snprintf(buf, n, "%sx%d:%d", at, w->reg, w->len);
}

// "auto", or "x0:64" / "x2+16:32", comma-separated. Canonical form drops a zero offset
// and spaces. nout == -1 means auto (windows are chosen per hit). A bad spec fails the
// install; it must not become "hook installed, window silently absent".
 int parse_mem_spec(const char *spec, int *regs, int *offsets, int *lens, int *derefs, int *froms,
                          unsigned long long *abs_addrs, int *is_abs, int *nout,
                          char *canon, size_t canon_sz, char *error, size_t error_size) {
    if (nout) *nout = 0;
    if (canon && canon_sz) canon[0] = 0;
    if (!spec) return 1;
    while (*spec == ' ') spec++;
    if (!spec[0]) return 1;
    const char *end = spec + strlen(spec);
    while (end > spec && end[-1] == ' ') end--;
    if ((size_t)(end - spec) == 4 && memcmp(spec, "auto", 4) == 0) {
        if (nout) *nout = -1;
        if (!canon || canon_sz < 5) {
            set_error(error, error_size, "mem spec does not fit");
            return 0;
        }
        memcpy(canon, "auto", 5);
        return 1;
    }
    int n = 0;
    int total = 0;
    size_t coff = 0;
    const char *p = spec;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (n >= ADH_MEM_WIN_MAX) {
            set_error(error, error_size, "mem allows at most %d windows", ADH_MEM_WIN_MAX);
            return 0;
        }
        WinSpec w;
        if (!parse_window(&p, ADH_MEM_WIN_LEN, "mem", &w, error, error_size)) return 0;
        // An absolute window is allowed here (unlike memAfter): reading "what does this address hold at
        // this hit" is exactly how a value's origin is bisected, and the address is re-read per hit like
        // any other window. No deref/from_win combination is allowed with it - there is no register to
        // take the offset from.
        if (w.absolute && (w.deref || w.from_win)) {
            set_error(error, error_size, "an absolute mem window cannot also dereference (0xADDR:len)");
            return 0;
        }
        while (*p == ' ') p++;
        if (*p == ',') {
            p++;
            while (*p == ' ') p++;
            if (!*p) {
                set_error(error, error_size, "mem window must look like x0:64, x2+16:32 or x3-40:40");
                return 0;
            }
        } else if (*p) {
            set_error(error, error_size, "mem window must look like x0:64, x2+16:32 or x3-40:40");
            return 0;
        }
        total += w.len;
        if (total > ADH_MEM_WIN_TOTAL) {
            set_error(error, error_size, "mem total exceeds %d", ADH_MEM_WIN_TOTAL);
            return 0;
        }
        // "@#n" must name a window that was already parsed, otherwise the pointer it is supposed to
        // follow does not exist yet and the install would silently copy nothing.
        if (w.from_win) {
            if (w.from_win < 1 || w.from_win > n) {
                set_error(error, error_size, "mem window @#%d must reference an earlier window (1..%d)", w.from_win, n);
                return 0;
            }
            if (w.off < 0 || w.off + 8 > lens[w.from_win - 1]) {
                set_error(error, error_size, "mem window @#%d+%d needs 8 bytes inside window %d (length %d)",
                          w.from_win, w.off, w.from_win, lens[w.from_win - 1]);
                return 0;
            }
        }
        regs[n] = w.reg;
        offsets[n] = w.off;
        lens[n] = w.len;
        if (derefs) derefs[n] = w.deref;
        if (froms) froms[n] = w.from_win;
        if (is_abs) is_abs[n] = w.absolute;
        if (abs_addrs) abs_addrs[n] = w.abs_addr;
        char piece[32];
        int pn = format_window(piece, sizeof(piece), &w);
        if (pn < 0 || (size_t)pn >= sizeof(piece) || !canon || coff + (n ? 1 : 0) + (size_t)pn + 1 > canon_sz) {
            set_error(error, error_size, "mem spec does not fit");
            return 0;
        }
        if (n) canon[coff++] = ',';
        memcpy(canon + coff, piece, (size_t)pn);
        coff += (size_t)pn;
        canon[coff] = 0;
        n++;
    }
    if (nout) *nout = n;
    return 1;
}

// Copy [addr, addr+n) without raising SIGSEGV in the target. process_vm_readv returns EFAULT
// for an unmapped page. The /proc/self/mem fallback exists for a seccomp filter that blocks
// that syscall; it is not used when the first read works, so a dumpable process does not gain
// a standing mem fd just because a window was configured. The signal-guarded direct copy is
// deliberately not used here: swapping the process SIGSEGV handler on a hit thread races the
// target's own crash handler.
 int hook_mem_copy(uint64_t addr, unsigned char *dst, int n) {
    if (!dst || n <= 0) return -1;
    if (addr < 0x1000) return -1;
    if (addr > ~0ull - (uint64_t)n) return -1;
    struct iovec local;
    struct iovec remote;
    local.iov_base = dst;
    local.iov_len = (size_t)n;
    remote.iov_base = (void *)(uintptr_t)addr;
    remote.iov_len = (size_t)n;
    ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (got > 0) return (int)got;
    int fd = adh_mem_fd();
    if (fd < 0) return -1;
    ssize_t via_fd = pread(fd, dst, (size_t)n, (off_t)addr);
    if (via_fd > 0) return (int)via_fd;
    return -1;
}

 void hex_encode(const unsigned char *bytes, int n, char *out) {
    static const char *kHex = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = kHex[bytes[i] >> 4];
        out[i * 2 + 1] = kHex[bytes[i] & 0xf];
    }
    out[n * 2] = 0;
}

// At-hit caller chain. The x29 chain must be read WHILE the hit is live: reading it later from the
// host reads a stack that the process has already reused (the first version did that and found zeros
// where the frame records had been). The current thread's stack bounds come from
// pthread_attr_getstack - cached per thread, so a bogus frame pointer can never make this read
// outside the stack.

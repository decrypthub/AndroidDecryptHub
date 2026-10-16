// ADH Zygisk module — early-inject libadh_agent.so into allowlisted packages.
// Scope file: /data/adb/adh/scope.json  ({"version":1,"mode":"allowlist","packages":["…"]})
// Never injects zygote / system_server / com.adh.manager.
#include <android/log.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>   // MFD_CLOEXEC
#include <cstdio>
#include <cstring>
#include <string>

#include "zygisk.hpp"

#define LOG_TAG "adh-zygisk"
// Injection decisions must be auditable after the fact: logd is not reliably reachable in the
// pre-specialize window, and a silent "no inject" is impossible to debug from outside. Every
// decision is written to a root-readable file as well as to logcat.
#define ADH_DECISION_LOG "/data/adb/adh/zygisk_inject.log"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr const char *kScopePath = "/data/adb/adh/scope.json"; // == com.adh.core.AdhPaths.SCOPE_PATH
static constexpr const char *kLoaderMarker = "/data/adb/adh/zygisk_loaded"; // == com.adh.core.AdhPaths.LOADER_MARKER
static constexpr const char *kManagerPkg = "com.adh.manager";         // == com.adh.core.AdhPaths.MANAGER_PKG
static constexpr const char *kAgentName = "libadh_agent.so";          // == com.adh.core.AdhPaths.AGENT_SO_NAME

#include <cstdarg>
static zygisk::Api *g_api_for_log = nullptr;   // set in onLoad, used to relay logs (see note())
static bool g_debug_verbose = false;           // /data/adb/adh/zygisk_debug exists (opt-in)
static char g_debug_pkg[256];                  // package name, for the app-cache debug fallback

// These control messages are tiny, but a single write() may still come up short, and a plain
// write(...) != len check would silently drop a decision line. Both directions are checked.
static bool write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += (size_t)n;
    }
    return true;
}

// Sockets: a companion that closed early must fail the write, not kill the target with SIGPIPE
// (this runs in the app process, whose SIGPIPE disposition we do not control).
static bool send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += (size_t)n;
    }
    return true;
}

// Read one reply LINE (without the terminator) from a companion socket. Requires a real '\n' inside
// the cap: a short read, a timed-out read (SO_RCVTIMEO) or a missing terminator all report failure,
// so a half-consumed old reply can never be mistaken for this request's answer.
static bool read_reply_line(int fd, char *buf, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        if (c == '\n') {
            buf[used] = 0;
            return true;
        }
        buf[used++] = c;
    }
    buf[used] = 0;
    return false;
}

static bool reply_is(int fd, const char *expect) {
    char buf[16];
    return read_reply_line(fd, buf, sizeof(buf)) && strcmp(buf, expect) == 0;
}

// Companion side: bound the wait for the next byte so a half-open client (killed between connect and
// its request line) cannot pin this loop forever. Linux poll() works on sockets on every supported
// kernel; a timeout is treated exactly like a closed peer.
static constexpr int kCompanionIdleMs = 15000;

static bool wait_readable(int fd, int timeout_ms) {
    struct pollfd p {};
    p.fd = fd;
    p.events = POLLIN;
    int r = poll(&p, 1, timeout_ms);
    return r > 0;
}

// Read one request line: at most cap-1 bytes, terminated by '\n'. Returns the line length, -1 when the
// peer closed / timed out, or -2 when the line did not fit (the rest of that line is drained first, so
// the stream stays aligned). A truncated or over-long request is never acted on - the previous
// read-once code let leftover bytes fall through to "mark".
static ssize_t read_request_line(int fd, char *buf, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        if (!wait_readable(fd, kCompanionIdleMs)) return -1;
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;          // peer closed: nothing more to serve
        if (c == '\n') {
            buf[used] = 0;
            return (ssize_t)used;
        }
        buf[used++] = c;
    }
    buf[used] = 0;
    // Drain the rest of the over-long line (bounded, EOF/timeout ends it) before reporting it.
    for (size_t drained = 0; drained < 8192; drained++) {
        if (!wait_readable(fd, kCompanionIdleMs)) break;
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0 || c == '\n') break;
    }
    return -2;
}

// The companion relay exists for the pre-specialize window only (Zygisk Next dlcloses the module
// library afterwards), so the socket is cached instead of being reopened for every single log line.
static int g_companion_socket = -1;
static int g_companion_fails = 0;
static constexpr int kCompanionMaxFails = 3;

// ...and it is RELEASED at the end of that window. After specialize the instance runs with the app's
// uid, the socket no longer works (measured - the connection does not survive the switch), and an fd
// left open here lives for the whole life of the app process. Zygisk Next 1.5+ reports exactly that
// as improper Companion API use ("1 module(s) with issue: adh" / "may cause process crashes and
// memory leaks"), and it is right: the descriptor is dead weight in a process we already handed the
// agent to. Closing it also stops note() from opening a NEW companion socket post-specialize, which
// is not a legal place to call connectCompanion().
static bool g_companion_relay_open = true;

static void release_companion_relay(void) {
    if (g_companion_socket >= 0) {
        close(g_companion_socket);
        g_companion_socket = -1;
    }
    g_companion_relay_open = false;
}

// A companion socket with bounded reads/writes: this runs on the app's startup path, so a wedged
// companion must cost at most ~1 s per attempt instead of blocking the process indefinitely.
static int connect_companion(void) {
    if (!g_api_for_log) return -1;
    int fd = g_api_for_log->connectCompanion();
    if (fd < 0) return -1;
    struct timeval tv {};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

static bool companion_log_line(const char *line) {
    if (!g_companion_relay_open) return false;   // post-specialize: relay released, see above
    if (g_companion_fails >= kCompanionMaxFails) return false;
    if (g_companion_socket < 0) {
        g_companion_socket = connect_companion();
        if (g_companion_socket < 0) {
            g_companion_fails++;
            return false;
        }
    }
    char req[600];
    int len = snprintf(req, sizeof(req), "log %s\n", line);
    // "ok" is required: a refusal ("err") or a truncated reply must let note() fall back instead of
    // silently dropping the line.
    if (len <= 0 || !send_all(g_companion_socket, req, (size_t)len) ||
        !reply_is(g_companion_socket, "ok")) {
        close(g_companion_socket);
        g_companion_socket = -1;
        g_companion_fails++;
        return false;
    }
    return true;
}

// The debug fallback writes into /data/data/<pkg>/cache, so only a plain package-name character set
// is accepted: a '/', a ".." or whitespace would escape the directory the operator opted into.
static bool valid_pkg_name(const char *pkg) {
    if (!pkg || !pkg[0]) return false;
    size_t len = strlen(pkg);
    if (len > 200) return false;
    for (size_t i = 0; i < len; i++) {
        char c = pkg[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '_')
            continue;
        return false;
    }
    return true;
}

// Bound the decision log: it is root-readable state that accumulates across reboots. The cap is
// enforced by truncating in place (no second file): several module instances append concurrently and
// a rename would race with them, possibly moving a just-written line out of the file the operator
// reads. Returns false when the line did not reach the file, so callers can fall back.
static constexpr off_t kDecisionLogMaxBytes = 512 * 1024;

static bool append_decision_line(const char *line) {
    int fd = open(ADH_DECISION_LOG, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    struct stat st {};
    if (fstat(fd, &st) == 0 && st.st_size >= kDecisionLogMaxBytes) (void)ftruncate(fd, 0);
    bool ok = write_all(fd, line, strlen(line)) && write_all(fd, "\n", 1);
    if (!ok) LOGE("decision log write failed: %s", strerror(errno));
    close(fd);
    return ok;
}

static void note(const char *fmt, ...) {
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", line);
    // The module INSTANCE runs with the app's uid, where /data/adb (0700) is unreadable and
    // unwritable, so its decisions would otherwise be invisible. Try the direct file first (this is
    // how the root companion writes) and relay through the companion otherwise.
    if (access(ADH_DECISION_LOG, W_OK) == 0 && append_decision_line(line)) return;
    if (companion_log_line(line)) return;
    // Post-specialize the instance is the app uid: /data/adb is out of reach and the companion socket
    // is no longer usable (measured - the connection does not survive the switch). The loader OUTCOME
    // is still auditable per session: the agent reports its own mapped path (hello.selfModule) to the
    // Host ADH Daemon, which records "/memfd:jit-cache (deleted)" vs a module path. This last fallback
    // is the opt-in, target-visible one: the app's own cache, off unless the operator asked for it.
    if (g_debug_verbose && valid_pkg_name(g_debug_pkg)) {
        char path[400];
        snprintf(path, sizeof(path), "/data/data/%s/cache/adh_zygisk.log", g_debug_pkg);
        int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) {
            struct stat st {};
            if (fstat(fd, &st) == 0 && st.st_size >= 256 * 1024) (void)ftruncate(fd, 0);
            (void)write_all(fd, line, strlen(line));
            (void)write_all(fd, "\n", 1);
            close(fd);
        }
    }
}

// The marker records "the Zygisk loader ran in this boot"; the request itself arrives once per app
// instance, so a second call is not an error (O_EXCL keeps the file content at "active").
static void mark_loader_active(void) {
    int fd = open(kLoaderMarker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd >= 0) {
        static constexpr char kActive[] = "active\n";
        (void)write_all(fd, kActive, sizeof(kActive) - 1);
        close(fd);
    }
}

static bool is_hard_exclude(const char *pkg) {
    if (!pkg || !pkg[0]) return true;
    if (strcmp(pkg, "system_server") == 0) return true;
    if (strcmp(pkg, "zygote") == 0 || strcmp(pkg, "zygote64") == 0) return true;
    if (strcmp(pkg, kManagerPkg) == 0) return true;
    // Isolated / webview processes often share a prefix; still allow if explicitly listed.
    return false;
}

// Zygisk hands us the PROCESS name in nice_name; for a secondary process that is
// `com.example.app:core`, not the package. Everything else in ADH is keyed by PACKAGE - the scope
// file, the per-app hook policy, the Manager UI - and a multi-process app is ONE scope entry, not
// one per process (REQUIREMENTS: "支持多进程 App：每个进程独立 session"). So the lookups below try
// the exact process name FIRST (an operator can narrow the scope to a single process on purpose)
// and the package prefix second, which is what makes "tick the app" cover all of it.
//
// Measured before this existed, on a three-process target, by writing each name into the allowlist
// alone: only `com.x:core` listed -> only the :core process got an agent; only `com.x` listed -> only
// the main process did. The app's network stack can live in either one, so which process you happen
// to have named decided whether a capture worked at all.
static std::string package_of(const std::string &process) {
    size_t at = process.find(':');
    return at == std::string::npos ? process : process.substr(0, at);
}

// Minimal allowlist check: look for "\"pkg\"" inside the packages array region.
// Fail-loud: missing/unreadable file → no inject (empty allowlist).
static bool package_in_scope(const char *pkg) {
    int fd = open(kScopePath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    // Prefer the packages array if present; otherwise scan whole file.
    const char *scan = buf;
    const char *arr = strstr(buf, "\"packages\"");
    if (arr) {
        const char *lb = strchr(arr, '[');
        const char *rb = lb ? strchr(lb, ']') : nullptr;
        if (lb && rb && rb > lb) {
            // Temporarily truncate for the search window (buf is mutable).
            char save = *rb;
            *const_cast<char *>(rb) = '\0';
            scan = lb;
            char needle[512];
            snprintf(needle, sizeof(needle), "\"%s\"", pkg);
            bool hit = strstr(scan, needle) != nullptr;
            *const_cast<char *>(rb) = save;
            return hit;
        }
    }
    char needle[512];
    snprintf(needle, sizeof(needle), "\"%s\"", pkg);
    return strstr(buf, needle) != nullptr;
}

// One family flag out of a policy slice: "d":true / "d": false → 1 / 0; anything else keeps the
// default (ON). Same fail-open rule as the Kotlin codec, so a hand-edited or truncated scope file
// can only ever mean "hook more", never "hook less".
static int family_on(const char *obj, const char *key, int dflt) {
    char needle[8];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(obj, needle);
    if (!p) return dflt;
    p = strchr(p + strlen(needle), ':');
    if (!p) return dflt;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return dflt;
}

// Cheap well-formedness guard for the scope file. Brace matching alone cannot tell "this package's
// object" from "this package's object merged with the next one" when the file is malformed but its
// braces still balance overall. A whole-file balance check catches the truncation/typo class that
// matters, and a file that fails it yields NO policy at all, which leaves the agent on families-ON.
// A brace inside a string value would be a false positive, and no scope field can carry one
// (packages, "c", "d".."e", "b", "s", true/false).
static bool scope_json_balances(const char *buf) {
    int depth = 0;
    for (const char *p = buf; *p; p++) {
        if (*p == '{') depth++;
        else if (*p == '}' && --depth < 0) return false;
    }
    return depth == 0;
}

// Copy the {...} object that follows "key" within [from] into out. false when the key or its brace
// is absent. Bounded at the matching close brace so a later section's keys cannot be read.
static bool object_slice(const char *from, const char *key, char *out, size_t cap) {
    char needle[16];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = from ? strstr(from, needle) : nullptr;
    const char *brace = p ? strchr(p, '{') : nullptr;
    if (!brace) return false;
    const char *end = brace;
    int depth = 0;
    for (; *end; end++) {
        if (*end == '{') depth++;
        else if (*end == '}' && --depth == 0) { end++; break; }
    }
    size_t len = static_cast<size_t>(end - brace);
    if (len >= cap) len = cap - 1;
    memcpy(out, brace, len);
    out[len] = '\0';
    return true;
}

// Render one package's hook policy as the flag line the agent consumes ("d=1,h=0,…").
// false = this package carries no capture section, which leaves the agent on its own defaults
// (every capture family on, and SSL bypass on). "b" is the bypass flag on the package object;
// a missing key stays on.
static bool policy_flags_for(const char *pkg, char *out, size_t cap) {
    if (!pkg || !pkg[0]) return false;
    int fd = open(kScopePath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    if (!scope_json_balances(buf)) return false;    // malformed file: refuse, do not guess

    const char *policy = strstr(buf, "\"policy\"");
    if (!policy) return false;
    char needle[512];
    snprintf(needle, sizeof(needle), "\"%s\"", pkg);
    const char *entry = strstr(policy, needle);
    if (!entry) return false;

    // Bound EVERY lookup to this package's own object. Searching from `entry` to the end of the file
    // let one package inherit a later package's keys.
    char pkg_obj[1024];
    const char *open = strchr(entry, '{');
    if (!open) return false;
    const char *walk = open;
    int depth = 0;
    bool closed = false;
    for (; *walk && (size_t)(walk - open) < sizeof(pkg_obj) - 1; walk++) {
        if (*walk == '{') depth++;
        else if (*walk == '}' && --depth == 0) { walk++; closed = true; break; }
    }
    // A package object that never closes means the file is malformed. Refuse the whole entry rather
    // than guess: the agent then keeps its own defaults, which are families ON.
    if (!closed) return false;
    size_t olen = (size_t)(walk - open);
    if (olen >= sizeof(pkg_obj)) olen = sizeof(pkg_obj) - 1;
    memcpy(pkg_obj, open, olen);
    pkg_obj[olen] = '\0';

    char capture[512] = "";
    if (!object_slice(pkg_obj, "c", capture, sizeof(capture))) return false;

    snprintf(out, cap, "d=%d,h=%d,s=%d,a=%d,t=%d,e=%d,b=%d",
             family_on(capture, "d", 1),
             family_on(capture, "h", 1),
             family_on(capture, "s", 1),
             family_on(capture, "a", 1),
             family_on(capture, "t", 1),
             family_on(capture, "e", 1),
             family_on(pkg_obj, "b", 1));
    return true;
}

static int open_agent_fd(zygisk::Api *api, std::string *where) {
    // Open the agent while we are still in the pre-specialize window. Calling
    // getModuleDir() from postAppSpecialize deadlocks on Zygisk Next, so keep
    // the daemon interaction here and pass only the plain fd to the linker.
    int dirfd = api->getModuleDir();
    if (dirfd < 0) {
        LOGE("getModuleDir failed");
        return -1;
    }
    int fd = openat(dirfd, kAgentName, O_RDONLY | O_CLOEXEC);
    int saved_errno = errno;
    close(dirfd);
    if (fd < 0) {
        LOGE("openat(module dir, %s) failed: %s", kAgentName, strerror(saved_errno));
        return -1;
    }
    if (where) *where = "module-dir fd";
    return fd;
}

// Copy the agent into a memfd named like the runtime's own JIT cache and load THAT, so the target
// never sees a /data/adb/modules/adh/libadh_agent.so entry in its maps - only
// "/memfd:jit-cache (deleted)", which looks exactly like ART's own JIT caches. Any failure falls
// back to the plain module-dir fd so injection still works (fail-soft, logged loudly).
static int copy_agent_to_memfd(int src_fd) {
    if (src_fd < 0) return -1;
    int mfd = (int)syscall(__NR_memfd_create, "jit-cache", MFD_CLOEXEC);
    if (mfd < 0) {
        LOGE("memfd_create failed: %s", strerror(errno));
        return -1;
    }
    if (lseek(src_fd, 0, SEEK_SET) != 0) {
        LOGE("lseek(agent fd) failed: %s", strerror(errno));
        close(mfd);
        return -1;
    }
    char buf[65536];
    for (;;) {
        ssize_t n = read(src_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            LOGE("read(agent fd) failed: %s", strerror(errno));
            close(mfd);
            return -1;
        }
        if (n == 0) break;
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(mfd, buf + off, (size_t)(n - off));
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                LOGE("write(memfd) failed: %s", strerror(errno));
                close(mfd);
                return -1;
            }
            off += w;
        }
    }
    if (lseek(mfd, 0, SEEK_SET) != 0) {
        LOGE("lseek(memfd) failed: %s", strerror(errno));
        close(mfd);
        return -1;
    }
    note("agent copied into memfd %d", mfd);
    return mfd;
}

static void *dlopen_agent_fd(int fd, const std::string &where) {
    if (fd < 0) return nullptr;
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    // Strategy 1: the documented one (USE_LIBRARY_FD + /proc/self/fd path).
    {
        android_dlextinfo extinfo{};
        extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
        extinfo.library_fd = fd;
        void *h = android_dlopen_ext(proc_path, RTLD_NOW, &extinfo);
        if (h) return h;
        note("dlopen strategy 1 (USE_LIBRARY_FD) failed for %s: %s", where.c_str(), dlerror());
    }
    // Strategy 2: a READ-ONLY descriptor. Some linker versions refuse a writable fd, and a memfd from
    // memfd_create() is O_RDWR by default - this is the one that matters for the memfd path.
    {
        int ro = open(proc_path, O_RDONLY | O_CLOEXEC);
        if (ro >= 0) {
            android_dlextinfo extinfo{};
            extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
            extinfo.library_fd = ro;
            void *h = android_dlopen_ext(proc_path, RTLD_NOW, &extinfo);
            int saved = errno;
            if (!h) note("dlopen strategy 2 (read-only fd) failed for %s: %s (errno=%d)", where.c_str(), dlerror(), saved);
            close(ro);
            if (h) return h;
        } else {
            note("read-only dup failed for %s: %s", where.c_str(), strerror(errno));
        }
    }
    // Strategy 3: plain dlopen by path (the linker resolves /proc/self/fd itself).
    {
        void *h = dlopen(proc_path, RTLD_NOW);
        if (h) return h;
        note("dlopen strategy 3 (plain path) failed for %s: %s", where.c_str(), dlerror());
    }
    return nullptr;
}

class AdhModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        g_api_for_log = api;
        // The companion is not needed after postAppSpecialize; ask Zygisk Next
        // to dlclose it so /data/adb/modules/adh/zygisk/*.so does not linger in
        // the target maps. The agent .so stays loaded for the session.
        if (api) api->setOption(zygisk::Api::DLCLOSE_MODULE_LIBRARY);
    }

    // The pre-specialize body. preAppSpecialize() below wraps it so the companion relay is released
    // on EVERY exit path, including the early returns for hard-excluded and out-of-scope packages -
    // that is exactly where an fd used to be left behind for the whole process.
    void pre_specialize_inner(zygisk::AppSpecializeArgs *args) {
        should_inject = false;
        agent_path.clear();
        if (!marker_requested) {
            marker_requested = true;
            int client = connect_companion();
            if (client >= 0) {
                if (!send_all(client, "mark\n", 5) || !reply_is(client, "ok"))
                    LOGE("loader marker request was not acknowledged");
                close(client);
            } else {
                LOGE("companion unavailable; loader marker not written this boot");
            }
        }
        if (!g_debug_pkg[0]) {
            g_debug_verbose = (access("/data/adb/adh/zygisk_debug", F_OK) == 0);
        }
        note("preAppSpecialize uid=%d debug=%d", (int)getuid(), g_debug_verbose ? 1 : 0);
        if (!args || !args->nice_name) return;

        const char *pkg = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!pkg) return;
        std::string package(pkg);
        package_name = package;
        snprintf(g_debug_pkg, sizeof(g_debug_pkg), "%s", package.c_str());
        env->ReleaseStringUTFChars(args->nice_name, pkg);

        // Hard exclude on BOTH keys: a manager secondary process is still the manager.
        const std::string pkg_name = package_of(package);
        if (is_hard_exclude(package.c_str()) || is_hard_exclude(pkg_name.c_str())) {
            note("skip hard-exclude pkg=%s", package.c_str());
            return;
        }
        // Which keys name this process, in priority order. One entry when the process IS the
        // package (the common case), two for a secondary process.
        std::string keys[2] = { package, pkg_name };
        const int n_keys = (pkg_name == package) ? 1 : 2;

        int scope_answer = -1;   // -1 unknown, 0 no, 1 yes
        for (int i = 0; i < n_keys; i++) {
            int sock = connect_companion();
            if (sock < 0) continue;
            char req[320];
            int len = snprintf(req, sizeof(req), "scope %s\n", keys[i].c_str());
            char reply[8] = {0};
            if (len > 0 && send_all(sock, req, (size_t)len) &&
                read_reply_line(sock, reply, sizeof(reply))) {
                if (reply[0] == '1') { scope_answer = 1; close(sock); break; }
                // A "no" for the narrow key is not final: the package may still be listed.
                if (reply[0] == '0') scope_answer = 0;
                else note("companion refused scope query pkg=%s reply=%s", keys[i].c_str(), reply);
            }
            close(sock);
        }
        if (scope_answer < 0) {
            // Fallbacks, in order: the direct read (works when the instance is root) and nothing.
            for (int i = 0; i < n_keys; i++) {
                if (package_in_scope(keys[i].c_str())) { scope_answer = 1; break; }
            }
            if (scope_answer < 0) scope_answer = 0;
            note("scope query fell back to a direct read pkg=%s -> %d", package.c_str(), scope_answer);
        }
        if (scope_answer != 1) {
            note("skip not-in-scope pkg=%s (companion answer=%d)", package.c_str(), scope_answer);
            return;
        }
        note("in scope pkg=%s", package.c_str());

        // Which hook families this package is allowed to see installed. Asked here because the
        // companion socket does not survive specialization; the agent applies it when it starts.
        // Same two-key rule, narrow first: a policy written for one process beats the app's.
        policy_flags.clear();
        for (int i = 0; i < n_keys && policy_flags.empty(); i++) {
            int sock = connect_companion();
            if (sock >= 0) {
                char req[320];
                int len = snprintf(req, sizeof(req), "policy %s\n", keys[i].c_str());
                char reply[80] = {0};
                if (len > 0 && send_all(sock, req, (size_t)len) &&
                    read_reply_line(sock, reply, sizeof(reply))) {
                    if (reply[0] && strncmp(reply, "default", 7) != 0) policy_flags = reply;
                }
                close(sock);
            }
            if (policy_flags.empty()) {
                // Same fallback order as the scope query: a direct read works when this instance
                // happens to be root, and silence simply leaves the agent on its defaults.
                char direct[64];
                if (policy_flags_for(keys[i].c_str(), direct, sizeof(direct))) policy_flags = direct;
            }
        }
        if (!policy_flags.empty()) note("policy pkg=%s %s", package.c_str(), policy_flags.c_str());

        should_inject = true;
        int src_fd = open_agent_fd(api, &agent_path);
        if (src_fd < 0) {
            should_inject = false;
            return;
        }
        // Keep the module-dir fd open: it is the source of the copy taken AFTER specialization.
        // Creating the memfd here does not work - the memfd would belong to the pre-specialize
        // (zygote) domain and the app-domain linker cannot even stat /proc/self/fd/N for it
        // ("unable to stat file for the library ... Permission denied", measured on the device).
        agent_fd = src_fd;
        agent_path += " (module-dir fd, copied into a memfd after specialization)";
        note("will inject pkg=%s via %s (fd=%d)", package.c_str(), agent_path.c_str(), agent_fd);
    }

    // Always the LAST thing we do before the uid/domain switch: every note() above had its chance to
    // relay through the companion, and nothing after this point can use that socket anyway.
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        pre_specialize_inner(args);
        release_companion_relay();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Idempotent backstop: if a future edit adds an exit path that skips the wrapper, the fd is
        // still closed here rather than living for the life of the app process.
        release_companion_relay();
        (void)args;
        if (!should_inject || agent_path.empty() || agent_fd < 0) return;

        // Now that we run with the app's own uid/domain, a memfd created here is loadable by the
        // linker. Copy the already-open source fd (opened pre-specialize, as required) into it.
        int memfd = copy_agent_to_memfd(agent_fd);
        void *handle = nullptr;
        if (memfd >= 0) {
            handle = dlopen_agent_fd(memfd, "memfd:jit-cache");
            close(memfd);
            if (handle) agent_path += " -> memfd:jit-cache (loaded)";
        }
        if (!handle) {
            note("memfd load failed pkg=%s; loading from the module path instead", package_name.c_str());
            handle = dlopen_agent_fd(agent_fd, agent_path + " (module path)");
        }
        close(agent_fd);
        agent_fd = -1;
        if (!handle) {
            note("dlopen failed pkg=%s via %s", package_name.c_str(), agent_path.c_str());
            return;
        }
        note("agent loaded pkg=%s via %s", package_name.c_str(), agent_path.c_str());
        using set_pkg_fn = void (*)(const char *);
        auto set_pkg = reinterpret_cast<set_pkg_fn>(dlsym(handle, "adh_agent_set_package"));
        if (set_pkg && !package_name.empty()) set_pkg(package_name.c_str());
        else LOGE("adh_agent_set_package not found; agent will infer package from cmdline");
        // Hand over the per-package hook policy before the agent starts: it arms from this, so a
        // trimmed app never installs the hooks the user switched off.
        if (!policy_flags.empty()) {
            using set_policy_fn = void (*)(const char *);
            auto set_policy = reinterpret_cast<set_policy_fn>(dlsym(handle, "adh_agent_set_policy"));
            if (set_policy) set_policy(policy_flags.c_str());
            else LOGE("adh_agent_set_policy not found; agent keeps every family on");
        }
        using start_fn = void (*)();
        auto start = reinterpret_cast<start_fn>(dlsym(handle, "adh_agent_start"));
        if (!start) {
            LOGE("dlsym(adh_agent_start) failed: %s", dlerror());
            return;
        }
        start();
        LOGI("ADH agent start called");
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool should_inject = false;
    bool marker_requested = false;
    int agent_fd = -1;
    std::string agent_path;
    std::string package_name;
    // Hook-family policy line for this package (empty = none configured → agent defaults to all on).
    std::string policy_flags;
};

REGISTER_ZYGISK_MODULE(AdhModule)
// Companion protocol (module instance -> companion process), one request line per message. A single
// connection may carry several request lines: the instance caches one connection for the whole
// pre/post-specialize window (the post-specialize lines are exactly the memfd-load outcome), and the
// companion serves them in order until the client closes. The companion runs as root, the module
// instance does not: /data/adb is 0700, so the instance can never read the scope file itself.
//
//   "mark\n"              -> creates the loader marker, replies "ok\n"
//   "scope <package>\n"   -> replies "1\n" (in allowlist) or "0\n"
//   "policy <package>\n"  -> replies "d=1,h=0,s=1,a=1,t=1,e=0,b=1\n", or "default\n" when the
//                            package carries no policy at all. Capture families and SSL bypass
//                            both default ON. b=0 is the explicit off switch.
//   "log <line>\n"        -> appends to the root decision log, replies "ok\n"
// Anything else - including a line that arrived truncated or over-long - is refused with "err\n":
// the companion never guesses, so an incomplete request can no longer be mistaken for a "mark".
static void companion_serve(int client) {
    if (client < 0) return;
    char req[1024];
    for (;;) {
        ssize_t n = read_request_line(client, req, sizeof(req));
        if (n == -1) break;                     // client closed: done serving
        if (n == -2) {                          // unusable line: refuse it, keep the stream usable
            (void)send_all(client, "err\n", 4);
            continue;
        }
        if (strcmp(req, "mark") == 0) {
            mark_loader_active();
            (void)send_all(client, "ok\n", 3);
            continue;
        }
        if (strncmp(req, "log ", 4) == 0) {
            // Only acknowledge what actually reached the file: the client uses "ok" to decide whether
            // to fall back to its own log, so a refused write must answer "err".
            const char *ack = append_decision_line(req + 4) ? "ok\n" : "err\n";
            (void)send_all(client, ack, strlen(ack));
            continue;
        }
        if (strncmp(req, "scope ", 6) == 0) {
            const char *pkg = req + 6;
            char reply[4] = "0\n";
            if (package_in_scope(pkg)) reply[0] = '1';
            note("companion scope query pkg=%s -> %c", pkg, reply[0]);
            (void)send_all(client, reply, 2);
            continue;
        }
        if (strncmp(req, "policy ", 7) == 0) {
            // Per-package hook policy. "default" (not a flag line) means this package carries none,
            // so the instance hands over nothing and the agent keeps every family on.
            const char *pkg = req + 7;
            char flags[64];
            if (policy_flags_for(pkg, flags, sizeof(flags))) {
                note("companion policy query pkg=%s -> %s", pkg, flags);
                char reply[72];
                snprintf(reply, sizeof(reply), "%s\n", flags);
                (void)send_all(client, reply, strlen(reply));
            } else {
                note("companion policy query pkg=%s -> default", pkg);
                (void)send_all(client, "default\n", 8);
            }
            continue;
        }
        note("companion refused unknown command");
        (void)send_all(client, "err\n", 4);
    }
    close(client);
}

REGISTER_ZYGISK_COMPANION(companion_serve)

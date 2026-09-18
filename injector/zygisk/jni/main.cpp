// ADH Zygisk module — early-inject libadh_agent.so into allowlisted packages.
// Scope file: /data/adb/adh/scope.json  ({"version":1,"mode":"allowlist","packages":["…"]})
// Never injects zygote / system_server / com.adh.manager.
#include <android/log.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
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

static void append_decision_line(const char *line) {
    int fd = open(ADH_DECISION_LOG, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) return;
    (void)write(fd, line, strlen(line));
    (void)write(fd, "\n", 1);
    close(fd);
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
    if (access(ADH_DECISION_LOG, W_OK) == 0) {
        append_decision_line(line);
        return;
    }
    if (g_api_for_log) {
        int sock = g_api_for_log->connectCompanion();
        if (sock >= 0) {
            char req[600];
            int len = snprintf(req, sizeof(req), "log %s\n", line);
            if (len > 0) {
                (void)write(sock, req, (size_t)len);
                char ack[4] = {0};
                (void)read(sock, ack, sizeof(ack) - 1);
            }
            close(sock);
            return;
        }
    }
    // Post-specialize the instance is the app uid: /data/adb is out of reach and the companion socket
    // is no longer usable. With the opt-in debug flag we may write into the app's own cache, which is
    // the only place that uid can write - target-visible, so it stays off unless the operator asked.
    if (g_debug_verbose && g_debug_pkg[0]) {
        char path[400];
        snprintf(path, sizeof(path), "/data/data/%s/cache/adh_zygisk.log", g_debug_pkg);
        int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) {
            (void)write(fd, line, strlen(line));
            (void)write(fd, "\n", 1);
            close(fd);
        }
    }
}

static void mark_loader_active(int client) {
    int fd = open(kLoaderMarker, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd >= 0) {
        static constexpr char kActive[] = "active\n";
        (void)write(fd, kActive, sizeof(kActive) - 1);
        close(fd);
    }
    close(client);
}

static bool is_hard_exclude(const char *pkg) {
    if (!pkg || !pkg[0]) return true;
    if (strcmp(pkg, "system_server") == 0) return true;
    if (strcmp(pkg, "zygote") == 0 || strcmp(pkg, "zygote64") == 0) return true;
    if (strcmp(pkg, kManagerPkg) == 0) return true;
    // Isolated / webview processes often share a prefix; still allow if explicitly listed.
    return false;
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

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        should_inject = false;
        agent_path.clear();
        if (!marker_requested) {
            marker_requested = true;
            int client = api->connectCompanion();
            if (client >= 0) {
                (void)write(client, "mark\n", 5);
                char ack[4] = {0};
                (void)read(client, ack, sizeof(ack) - 1);
                close(client);
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

        if (is_hard_exclude(package.c_str())) {
            note("skip hard-exclude pkg=%s", package.c_str());
            return;
        }
        int scope_answer = -1;   // -1 unknown, 0 no, 1 yes
        {
            int sock = api->connectCompanion();
            if (sock >= 0) {
                char req[320];
                int len = snprintf(req, sizeof(req), "scope %s\n", package.c_str());
                if (len > 0 && write(sock, req, (size_t)len) == len) {
                    char reply[4] = {0};
                    ssize_t got = read(sock, reply, sizeof(reply) - 1);
                    if (got > 0 && (reply[0] == '0' || reply[0] == '1')) scope_answer = reply[0] - '0';
                }
                close(sock);
            }
        }
        if (scope_answer < 0) {
            // Fallbacks, in order: the direct read (works when the instance is root) and nothing.
            scope_answer = package_in_scope(package.c_str()) ? 1 : 0;
            note("scope query fell back to a direct read pkg=%s -> %d", package.c_str(), scope_answer);
        }
        if (scope_answer != 1) {
            note("skip not-in-scope pkg=%s (companion answer=%d)", package.c_str(), scope_answer);
            return;
        }
        note("in scope pkg=%s", package.c_str());

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

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
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
    int fallback_fd = -1;
    std::string fallback_path;
    std::string agent_path;
    std::string package_name;
};

REGISTER_ZYGISK_MODULE(AdhModule)
// Companion protocol (module instance -> companion process):
//   "mark\n"              -> writes the loader marker, replies "ok\n"
//   "scope <package>\n"   -> replies "1\n" (in allowlist) or "0\n"
// The companion runs as root, the module instance does not: /data/adb is 0700, so the instance can
// never read the scope file itself.
static void companion_serve(int client) {
    if (client < 0) return;
    char req[512];
    ssize_t n = read(client, req, sizeof(req) - 1);
    if (n <= 0) {
        close(client);
        return;
    }
    req[n] = 0;
    // Trim at the first newline.
    char *nl = strchr(req, '\n');
    if (nl) *nl = 0;

    if (strncmp(req, "log ", 4) == 0) {
        append_decision_line(req + 4);          // relayed from an app-uid instance
        (void)write(client, "ok\n", 3);
        close(client);
        return;
    }
    if (strncmp(req, "scope ", 6) == 0) {
        const char *pkg = req + 6;
        char reply[4] = "0\n";
        if (package_in_scope(pkg)) reply[0] = '1';
        note("companion scope query pkg=%s -> %c", pkg, reply[0]);
        (void)write(client, reply, 2);
        close(client);
        return;
    }
    mark_loader_active(client);   // "mark" and anything else: legacy behaviour
}

REGISTER_ZYGISK_COMPANION(companion_serve)

// ADH Zygisk module — early-inject libadh_agent.so into allowlisted packages.
// Scope file: /data/adb/adh/scope.json  ({"version":1,"mode":"allowlist","packages":["…"]})
// Never injects zygote / system_server / com.adh.manager.
#include <android/log.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "zygisk.hpp"

#define LOG_TAG "adh-zygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr const char *kScopePath = "/data/adb/adh/scope.json"; // == com.adh.core.AdhPaths.SCOPE_PATH
static constexpr const char *kLoaderMarker = "/data/adb/adh/zygisk_loaded"; // == com.adh.core.AdhPaths.LOADER_MARKER
static constexpr const char *kManagerPkg = "com.adh.manager";         // == com.adh.core.AdhPaths.MANAGER_PKG
static constexpr const char *kAgentName = "libadh_agent.so";          // == com.adh.core.AdhPaths.AGENT_SO_NAME
// Legacy on-disk name: a module dir flashed before the ADH rename still carries this file, and
// the companion stays compatible with it (the payload file itself is not ABI-bound).
static constexpr const char *kLegacyAgentName = "libidh_agent.so";

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
    if (dirfd >= 0) {
        int fd = openat(dirfd, kAgentName, O_RDONLY | O_CLOEXEC);
        if (fd < 0) fd = openat(dirfd, kLegacyAgentName, O_RDONLY | O_CLOEXEC);   // legacy on-disk name
        close(dirfd);
        if (fd >= 0) {
            if (where) *where = "module-dir fd";
            return fd;
        }
        LOGE("openat(module dir fd=%d, %s) failed: %s", dirfd, kAgentName, strerror(errno));
    } else {
        LOGE("getModuleDir failed");
    }

    // Fallback: the file is normally visible in the pre-specialize namespace. Try the current
    // name first, then the legacy one (see kLegacyAgentName).
    const char *candidates[] = {
        "/data/adb/modules/adh/libadh_agent.so",
        "/data/adb/modules/adh/libidh_agent.so",
    };
    for (const char *cand : candidates) {
        int fd = open(cand, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (where) *where = cand;
            return fd;
        }
        LOGE("open(%s) failed: %s", cand, strerror(errno));
    }
    return -1;
}

static void *dlopen_agent_fd(int fd, const std::string &where) {
    if (fd < 0) return nullptr;
    android_dlextinfo extinfo{};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = fd;
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    void *handle = android_dlopen_ext(proc_path, RTLD_NOW, &extinfo);
    if (!handle) LOGE("android_dlopen_ext(%s, fd=%d) failed: %s", where.c_str(), fd, dlerror());
    return handle;
}

class AdhModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
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
            if (client >= 0) close(client);
        }
        if (!args || !args->nice_name) return;

        const char *pkg = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!pkg) return;
        std::string package(pkg);
        package_name = package;
        env->ReleaseStringUTFChars(args->nice_name, pkg);

        if (is_hard_exclude(package.c_str())) {
            LOGI("skip hard-exclude %s", package.c_str());
            return;
        }
        if (!package_in_scope(package.c_str())) {
            return;
        }

        should_inject = true;
        agent_fd = open_agent_fd(api, &agent_path);
        if (agent_fd < 0) {
            should_inject = false;
            return;
        }
        LOGI("will inject %s via %s (fd=%d)", package.c_str(), agent_path.c_str(), agent_fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        (void)args;
        if (!should_inject || agent_path.empty()) return;

        void *handle = dlopen_agent_fd(agent_fd, agent_path);
        close(agent_fd);
        agent_fd = -1;
        if (!handle) return;
        LOGI("ADH agent loaded via %s", agent_path.c_str());
        using set_pkg_fn = void (*)(const char *);
        auto set_pkg = reinterpret_cast<set_pkg_fn>(dlsym(handle, "adh_agent_set_package"));
        if (set_pkg && !package_name.empty()) set_pkg(package_name.c_str());
        else LOGE("adh_agent_set_package not found; agent will infer package from cmdline");
        using start_fn = void (*)();
        auto start = reinterpret_cast<start_fn>(dlsym(handle, "adh_agent_start"));
        if (!start) {
            dlerror();
            start = reinterpret_cast<start_fn>(dlsym(handle, "idh_agent_start"));
            if (!start) {
                LOGE("dlsym(adh_agent_start/idh_agent_start) failed: %s", dlerror());
                return;
            }
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
};

REGISTER_ZYGISK_MODULE(AdhModule)
REGISTER_ZYGISK_COMPANION(mark_loader_active)

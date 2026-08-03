// ADH Zygisk module — early-inject libidh_agent.so into allowlisted packages.
// Scope file: /data/adb/adh/scope.json  ({"version":1,"mode":"allowlist","packages":["…"]})
// Never injects zygote / system_server / com.adh.manager.
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "zygisk.hpp"

#define LOG_TAG "adh-zygisk"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr const char *kScopePath = "/data/adb/adh/scope.json";
static constexpr const char *kManagerPkg = "com.adh.manager";
static constexpr const char *kAgentName = "libidh_agent.so";

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

static std::string module_agent_path(zygisk::Api *api) {
    int dirfd = api->getModuleDir();
    if (dirfd < 0) return {};
    // Resolve /proc/self/fd/<dirfd>/libidh_agent.so
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);
    char dir[512];
    ssize_t len = readlink(link, dir, sizeof(dir) - 1);
    close(dirfd);
    if (len <= 0) return {};
    dir[len] = '\0';
    std::string path = std::string(dir) + "/" + kAgentName;
    return path;
}

class AdhModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        should_inject = false;
        agent_path.clear();
        if (!args || !args->nice_name) return;

        const char *pkg = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!pkg) return;
        std::string package(pkg);
        env->ReleaseStringUTFChars(args->nice_name, pkg);

        if (is_hard_exclude(package.c_str())) {
            LOGI("skip hard-exclude %s", package.c_str());
            return;
        }
        if (!package_in_scope(package.c_str())) {
            return;
        }

        agent_path = module_agent_path(api);
        if (agent_path.empty()) {
            // Fallback fixed module path (Magisk module id = adh).
            agent_path = std::string("/data/adb/modules/adh/") + kAgentName;
        }
        should_inject = true;
        LOGI("will inject %s via %s", package.c_str(), agent_path.c_str());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        (void)args;
        if (!should_inject || agent_path.empty()) return;

        void *handle = dlopen(agent_path.c_str(), RTLD_NOW);
        if (!handle) {
            LOGE("dlopen(%s) failed: %s", agent_path.c_str(), dlerror());
            return;
        }
        using start_fn = void (*)();
        auto start = reinterpret_cast<start_fn>(dlsym(handle, "idh_agent_start"));
        if (!start) {
            LOGE("dlsym(idh_agent_start) failed: %s", dlerror());
            return;
        }
        start();
        LOGI("idh_agent_start() called");
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool should_inject = false;
    std::string agent_path;
};

REGISTER_ZYGISK_MODULE(AdhModule)

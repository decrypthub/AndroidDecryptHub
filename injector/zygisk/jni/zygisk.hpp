/* Vendored from Magisk Zygisk module sample (topjohnwu/zygisk-module-sample).
 * Public Zygisk API header — modules are expected to ship a copy. */
#pragma once

#include <jni.h>
#include <unistd.h>
#include <vector>
#include <cstdint>

#define ZYGISK_API_VERSION 4

namespace zygisk {

struct Api;
struct AppSpecializeArgs;
struct ServerSpecializeArgs;

class ModuleBase {
public:
    virtual void onLoad([[maybe_unused]] Api *api, [[maybe_unused]] JNIEnv *env) {}
    virtual void preAppSpecialize([[maybe_unused]] AppSpecializeArgs *args) {}
    virtual void postAppSpecialize([[maybe_unused]] const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize([[maybe_unused]] ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize([[maybe_unused]] const ServerSpecializeArgs *args) {}
    virtual ~ModuleBase() = default;
};

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    jintArray *const fds_to_ignore;
    jboolean *const is_child_zygote;
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
    jboolean *const mount_sysprops;

    AppSpecializeArgs() = delete;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;

    ServerSpecializeArgs() = delete;
};

namespace internal {
struct api_table;
template <class T> void entry_impl(api_table *, JNIEnv *);
} // namespace internal

struct Api {
    enum Option : uint32_t {
        FORCE_DENYLIST_UNMOUNT = 0,
        DLCLOSE_MODULE_LIBRARY = 1,
    };
    enum StateFlag : uint32_t {
        PROCESS_GRANTED_ROOT = (1u << 0),
        PROCESS_ON_DENYLIST = (1u << 1),
    };

    void setOption(Option opt);
    uint32_t getFlags();
    int connectCompanion();
    int getModuleDir();
    bool pltHookRegister(const char *regex, const char *symbol, void *newFunc, void **oldFunc);
    bool pltHookExclude(const char *regex, const char *symbol);
    bool pltHookCommit();
    void hookJniNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *methods, int numMethods);

    // Do not use. Internal only.
    internal::api_table *impl;
};

#define REGISTER_ZYGISK_MODULE(clazz) \
extern "C" __attribute__((visibility("default"))) \
void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) { \
    zygisk::internal::entry_impl<clazz>(table, env);                        \
}

#define REGISTER_ZYGISK_COMPANION(func) \
extern "C" __attribute__((visibility("default"))) \
void zygisk_companion_entry(int client) { func(client); }

namespace internal {

struct module_abi {
    long api_version;
    ModuleBase *module;
    void (*preAppSpecialize)(ModuleBase *, AppSpecializeArgs *);
    void (*postAppSpecialize)(ModuleBase *, const AppSpecializeArgs *);
    void (*preServerSpecialize)(ModuleBase *, ServerSpecializeArgs *);
    void (*postServerSpecialize)(ModuleBase *, const ServerSpecializeArgs *);

    module_abi(ModuleBase *m) : api_version(ZYGISK_API_VERSION), module(m) {
        preAppSpecialize = [](ModuleBase *m, AppSpecializeArgs *args) { m->preAppSpecialize(args); };
        postAppSpecialize = [](ModuleBase *m, const AppSpecializeArgs *args) { m->postAppSpecialize(args); };
        preServerSpecialize = [](ModuleBase *m, ServerSpecializeArgs *args) { m->preServerSpecialize(args); };
        postServerSpecialize = [](ModuleBase *m, const ServerSpecializeArgs *args) { m->postServerSpecialize(args); };
    }
};

struct api_table {
    void *this_;
    bool (*registerModule)(api_table *, module_abi *);

    void (*hookJniNativeMethods)(JNIEnv *, const char *, JNINativeMethod *, int);
    void (*pltHookRegister)(const char *, const char *, void *, void **);
    void (*pltHookExclude)(const char *, const char *);
    bool (*pltHookCommit)();
    int (*connectCompanion)(void *);
    void (*setOption)(void *, Api::Option);
    int (*getModuleDir)(void *);
    uint32_t (*getFlags)(void *);
};

template <class T>
void entry_impl(api_table *table, JNIEnv *env) {
    static Api api{};
    api.impl = table;
    static T module;
    ModuleBase *m = &module;
    static module_abi abi(m);
    if (!table->registerModule(table, &abi)) return;
    m->onLoad(&api, env);
}

} // namespace internal

inline void Api::hookJniNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *methods, int numMethods) {
    if (impl && impl->hookJniNativeMethods) impl->hookJniNativeMethods(env, className, methods, numMethods);
}
inline void Api::setOption(Option opt) {
    if (impl && impl->setOption) impl->setOption(impl->this_, opt);
}
inline int Api::connectCompanion() {
    return (impl && impl->connectCompanion) ? impl->connectCompanion(impl->this_) : -1;
}
inline int Api::getModuleDir() {
    return (impl && impl->getModuleDir) ? impl->getModuleDir(impl->this_) : -1;
}
inline uint32_t Api::getFlags() {
    return (impl && impl->getFlags) ? impl->getFlags(impl->this_) : 0;
}
inline bool Api::pltHookRegister(const char *regex, const char *symbol, void *newFunc, void **oldFunc) {
    if (!impl || !impl->pltHookRegister) return false;
    impl->pltHookRegister(regex, symbol, newFunc, oldFunc);
    return true;
}
inline bool Api::pltHookExclude(const char *regex, const char *symbol) {
    if (!impl || !impl->pltHookExclude) return false;
    impl->pltHookExclude(regex, symbol);
    return true;
}
inline bool Api::pltHookCommit() {
    return (impl && impl->pltHookCommit) ? impl->pltHookCommit() : false;
}

} // namespace zygisk

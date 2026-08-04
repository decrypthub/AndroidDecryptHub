#include "native_inline.h"

#include "dobby.h"
#include <pthread.h>
#include <android/log.h>

#define ITAG "IDH_INLINE"
#define ILOGE(...) __android_log_print(ANDROID_LOG_ERROR, ITAG, __VA_ARGS__)

static pthread_once_t g_dobby_once = PTHREAD_ONCE_INIT;

static void init_dobby() {
    // The near trampoline is required when a target and replacement are more than the
    // arm64 branch range apart (common for injected libraries in a large app process).
    dobby_enable_near_branch_trampoline();
}

extern "C" int idh_inline_hook(void *target, void *replacement, void **original) {
    if (!target || !replacement || !original) return 0;
    pthread_once(&g_dobby_once, init_dobby);
    *original = nullptr;
    const auto rc = DobbyHook(target, replacement, original);
    if (rc != RS_SUCCESS) {
        ILOGE("DobbyHook failed target=%p rc=%d", target, (int)rc);
        return 0;
    }
    return *original != nullptr ? 1 : 0;
}

extern "C" int idh_inline_unhook(void *target) {
    if (!target) return 0;
    const auto rc = DobbyDestroy(target);
    if (rc != RT_SUCCESS) {
        ILOGE("DobbyDestroy failed target=%p rc=%d", target, (int)rc);
        return 0;
    }
    return 1;
}

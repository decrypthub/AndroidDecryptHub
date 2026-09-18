#include "native_inline.h"

#include "dobby.h"
#include "stealth_pool.h"
#include <pthread.h>
#include <android/log.h>

#define ITAG "rt.inline"
#define ILOGE(...) __android_log_print(ANDROID_LOG_ERROR, ITAG, __VA_ARGS__)

static pthread_once_t g_dobby_once = PTHREAD_ONCE_INIT;

static void init_dobby() {
    // The near trampoline is required when a target and replacement are more than the
    // arm64 branch range apart (common for injected libraries in a large app process).
    dobby_enable_near_branch_trampoline();
}

extern "C" int adh_inline_hook(void *target, void *replacement, void **original) {
    if (!target || !replacement || !original) return 0;
    pthread_once(&g_dobby_once, init_dobby);
    *original = nullptr;
    // Dobby allocates its trampoline arena during this call. With the opt-in pool camouflage
    // enabled, the window makes that allocation land in a memfd instead of an anonymous r-x page.
    adh_stealth_pool_window(1);
    const auto rc = DobbyHook(target, replacement, original);
    adh_stealth_pool_window(0);
    if (rc != RS_SUCCESS) {
        ILOGE("inline patch failed target=%p rc=%d", target, (int)rc);
        return 0;
    }
    return *original != nullptr ? 1 : 0;
}

extern "C" int adh_inline_unhook(void *target) {
    if (!target) return 0;
    adh_stealth_pool_window(1);
    const auto rc = DobbyDestroy(target);
    adh_stealth_pool_window(0);
    if (rc != RT_SUCCESS) {
        ILOGE("inline patch removal failed target=%p rc=%d", target, (int)rc);
        return 0;
    }
    return 1;
}

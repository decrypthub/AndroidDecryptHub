#include "native_inline.h"

#include "dobby.h"
#include "stealth_pool.h"
#include <pthread.h>
#include <android/log.h>

#define ITAG "rt.inline"
#define ILOGE(...) __android_log_print(ANDROID_LOG_ERROR, ITAG, __VA_ARGS__)

static pthread_once_t g_dobby_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_patch_lock = PTHREAD_MUTEX_INITIALIZER;
struct PatchLock { PatchLock(){pthread_mutex_lock(&g_patch_lock);} ~PatchLock(){pthread_mutex_unlock(&g_patch_lock);} };

static void init_dobby() {
    // Keep the existing native-hook preference. ART installs choose a full absolute
    // redirect below; the near-branch option is process-global in Dobby.
    dobby_enable_near_branch_trampoline();
}

static int install_hook(void *target, void *replacement, void **original, bool art) {
    PatchLock lock;
    if (!target || !replacement || !original) return 0;
    pthread_once(&g_dobby_once, init_dobby);
    *original = nullptr;
    // Dobby allocates its trampoline arena during this call. With the opt-in pool camouflage
    // enabled, the window makes that allocation land in a memfd instead of an anonymous r-x page.
    struct CallScope {
        bool art;
        explicit CallScope(bool value):art(value){adh_stealth_pool_window(1);if(art)dobby_disable_near_branch_trampoline();}
        ~CallScope(){if(art)dobby_enable_near_branch_trampoline();adh_stealth_pool_window(0);}
    } scope(art);
    const auto rc = DobbyHook(target, replacement, original);
    if (rc != RS_SUCCESS) {
        ILOGE("inline patch failed target=%p rc=%d", target, (int)rc);
        return 0;
    }
    return *original != nullptr ? 1 : 0;
}

extern "C" int adh_inline_hook(void *target, void *replacement, void **original) {return install_hook(target,replacement,original,false);}
extern "C" int adh_inline_hook_art(void *target, void *replacement, void **original) {return install_hook(target,replacement,original,true);}

extern "C" int adh_inline_unhook(void *target) {
    PatchLock lock;
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

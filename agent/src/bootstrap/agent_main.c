// Agent bootstrap: lifecycle, start policy, copy-owner detection.
// Report payload + per-command handlers + the command loop live in agent_cmds.c.

#include "agent_cmds_internal.h"

// libadh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - adh_agent_start() : exported C symbol for injector-driven load
// Both connect to the Host ADH Daemon over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <sys/system_properties.h>

#include "../hook/got.h"
#include "../capture/capture.h"
#include "../runtime/actions.h"
#include "../runtime/art.h"
#include "../runtime/inspection.h"
#include "../runtime/jni.h"
#include "../runtime/jni_hooks.h"
#include "../runtime/jni_env_hooks.h"
#include "../runtime/jni_onload.h"
#include "../runtime/dlopen_watch.h"
#include "../runtime/java_enum.h"
#include "../trace/commands.h"
#include "../trace/qbdi_trace.h"
#include "../hook/native_hooks.h"
#include "../hook/hw_watch.h"
#include "../hook/stealth_pool.h"
#include "../hook/site_hooks.h"

#ifdef ADH_HAVE_LSPLANT
#include "../hook/java_lsplant.h"
#include "../hook/ssl_bypass.h"
#include "../hook/java_crypto.h"
#ifndef ADH_LSPLANT_VERSION
#define ADH_LSPLANT_VERSION "unknown"
#endif
#endif

// Common macros (AGENT_VER/ADH_HOST/ADH_PORT/TAG/LOGI/LOGE/FRAME_*) + cross-module prototypes
// Shared bootstrap helpers live in agent_internal.h.
#include "agent_internal.h"
#include "process_identity.h"

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
 char g_entry[16] = "start";
 char g_package[512] = "";
// Per-package hook policy line from the Zygisk companion ("d=1,h=0,…,y=0"); empty = no policy →
// crypto families on, system detection off.
 char g_policy[64] = "";
extern const char *adh_early_status_json(void);

static void *agent_thread(void *arg) {
    (void)arg;
    int failed = 0;
    for (;;) {
        int fd = connect_adhd();
        if (fd >= 0) {
            if (failed) LOGI("reconnected to host daemon %s:%d after %d failed attempts", ADH_HOST, ADH_PORT, failed);
            else LOGI("connected to host daemon %s:%d", ADH_HOST, ADH_PORT);
            failed = 0;
            report(fd);
            command_loop(fd);
            close(fd);
            LOGI("host daemon connection closed; reconnecting");
            usleep(1000 * 1000);   // give a restarting daemon time to bind before re-dialling
            continue;
        }
        if (failed == 0 || failed % 20 == 0)
            LOGE("host unreachable (attempt %d, loopback tcp:%d failed)", failed + 1, ADH_PORT);
        failed++;
        usleep(500 * 1000);
    }
    return NULL;
}

static void do_start(void) {
    // Optional bootstrap hook: registrations that happen before the host's first command are the
    // interesting ones on a hardened target (they name the VM's native entry points). Off by
    // default; `setprop adh.jni_early 1` (root) arms it for the NEXT process start.
    {
        char early[PROP_VALUE_MAX] = "";
        if (__system_property_get("adh.jni_early", early) > 0 && early[0] == '1') {
            adh_jni_hook_install_early();
        }
    }
    // The per-package policy is applied by whatever install comes next — it is NOT armed here.
    // Arming would mean the agent picking a module for its own GOT patch, and the agent carries no
    // module name by design (WS-B red line, tools/verify_v87_mcp_operability.sh); the only module it
    // could pick without a caller is "scan every file-backed module", which the settings contract
    // warns against as a default. So: the policy travels companion → agent at specialize time and
    // decides the FAMILIES of the next install, while WHO installs stays the caller's decision.
    //
    // Java hooks (JCA capture and the trust-manager bypass) are also not armed here. LSPlant
    // rewrites ART, and installing it while the process is still linking classes faults
    // ClassLinker::LinkCode. A session asks for them with java_hook action crypto or bypass.
    pthread_t t;
    if (pthread_create(&t, NULL, agent_thread, NULL) == 0) pthread_detach(t);
    else LOGE("pthread_create failed");
}

__attribute__((visibility("default")))
void adh_agent_set_package(const char *pkg) {
    if (pkg && pkg[0]) {
        strncpy(g_package, pkg, sizeof(g_package) - 1);
        g_package[sizeof(g_package) - 1] = 0;
    }
}

// Per-package hook policy, handed over at load time by the Zygisk companion (its `policy` verb;
// see injector/zygisk/jni/main.cpp). One line: "d=1,h=0,s=1,a=0,t=1,e=0". Anything missing or
// unparseable keeps that family ON, so a truncated line can only ever mean "hook more".
// Absent crypto keys default ON; absent `y` (system detection) defaults OFF.
static int policy_flag(const char *flags, char key, int dflt) {
    for (const char *p = flags; (p = strchr(p, key)) != NULL; p++) {
        int at_token_start = (p == flags) || (p[-1] == ',');
        if (at_token_start && p[1] == '=') return (p[2] == '0') ? 0 : 1;
    }
    return dflt;
}

__attribute__((visibility("default")))
void adh_agent_set_policy(const char *flags) {
    if (!flags || !flags[0]) return;
    strncpy(g_policy, flags, sizeof(g_policy) - 1);
    g_policy[sizeof(g_policy) - 1] = 0;
    adh_capture_set_families(
        policy_flag(g_policy, 'd', 1), policy_flag(g_policy, 'h', 1), policy_flag(g_policy, 's', 1),
        policy_flag(g_policy, 'a', 1), policy_flag(g_policy, 't', 1), policy_flag(g_policy, 'e', 1),
        policy_flag(g_policy, 'y', 0));
    LOGI("hook policy: %s", g_policy);
}

// QBDI delivery: the Zygisk companion opens the tracer from the module directory before the
// uid/domain switch and hands the fd over here. The agent keeps it and copies it into a memfd the
// first time a trace actually runs (see trace/qbdi_trace.c). No fd = feature off for this target:
// nothing is loaded and nothing is mapped, so "not using it" really costs nothing.
__attribute__((visibility("default")))
void adh_agent_set_qbdi_fd(int fd) {
    adh_qbdi_set_source_fd(fd);
    LOGI("qbdi delivery fd=%d", fd);
}

// More than one backend can load this .so into one process (Zygisk + self-load + Frida Gadget).
// Each copy has its own pthread_once; only the first copy in link-map order may bootstrap.
struct AgentCopyCtx {
    unsigned char own_id[64];   // GNU build ID: identifies "another copy of this exact file"
    size_t own_id_len;
    unsigned long long own_span;  // fallback when either copy has no build ID
    void *first_base;
};

static int find_first_agent_copy(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct AgentCopyCtx *ctx = (struct AgentCopyCtx *)data;
    // Never match by name: a memfd copy has no stable name (both copies would read "jit-cache") and
    // dlpi_name may differ from the path dladdr reports. Identity is the GNU build ID - exact for two
    // copies of the same file - falling back to the image span only when a build ID is unavailable.
    // The span is computed inline (a nested dl_iterate_phdr from this callback is undocumented and
    // quadratic). dl_iterate_phdr walks in load order, so the FIRST match - ourselves included - owns
    // the process-global bootstrap; later copies stay inert. Excluding our own base instead would
    // make every copy decide it is not first, i.e. the agent would never start.
    const void *base = (const void *)(uintptr_t)info->dlpi_addr;
    unsigned char id[64];
    size_t id_len = 0;
    int has_id = adh_build_id_from_phdr(base, info->dlpi_phdr, (int)info->dlpi_phnum, id, sizeof(id), &id_len);
    if (ctx->own_id_len && has_id) {
        if (id_len != ctx->own_id_len || memcmp(id, ctx->own_id, id_len) != 0) return 0;
    } else {
        unsigned long long lo = ~0ULL, hi = 0;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
            if (ph->p_type != PT_LOAD || !ph->p_memsz) continue;
            unsigned long long s = (unsigned long long)ph->p_vaddr;
            unsigned long long e = s + (unsigned long long)ph->p_memsz;
            if (s < lo) lo = s;
            if (e > hi) hi = e;
        }
        if (!hi || lo == ~0ULL || hi - lo != ctx->own_span) return 0;
    }
    ctx->first_base = (void *)(uintptr_t)info->dlpi_addr;
    return 1;   // stop at the first copy of our image
}

static int current_agent_copy_is_owner(void) {
    Dl_info self;
    if (!dladdr((void *)(uintptr_t)current_agent_copy_is_owner, &self) || !self.dli_fbase) {
        LOGI("single-instance guard unavailable (dladdr) — continuing");
        return 1;
    }
    struct AgentCopyCtx ctx = {0};
    adh_self_build_id(ctx.own_id, sizeof(ctx.own_id), &ctx.own_id_len);
    unsigned long long self_start = 0, self_end = 0;
    if (adh_image_bounds_of(self.dli_fbase, &self_start, &self_end)) ctx.own_span = self_end - self_start;
    if (!ctx.own_id_len && !ctx.own_span) {
        LOGI("single-instance guard unavailable (no build ID, no PT_LOAD span) — continuing");
        return 1;
    }
    // A build ID only proves "same file": two DIFFERENT builds of the agent loaded together both
    // consider themselves first. That is a deployment error (stale module + fresh sandbox); the span
    // is logged so the duplicate sessions in the daemon can be traced back to it.
    LOGI("single-instance check: id=%s span=%llu", ctx.own_id_len ? "build-id" : "span",
         (unsigned long long)ctx.own_span);
    dl_iterate_phdr(find_first_agent_copy, &ctx);
    if (!ctx.first_base) {
        LOGI("single-instance guard: agent not found in link map — continuing");
        return 1;
    }
    if (ctx.first_base != self.dli_fbase) {
        LOGI("another agent copy was loaded first — skipping bootstrap");
        return 0;
    }
    return 1;
}

static void start_reporter_watch(void);   // defined below
int adh_agent_copy_owner(void) { return current_agent_copy_is_owner(); }

__attribute__((visibility("default")))
void adh_agent_start(void) {
    // Same single-instance rule as JNI_OnLoad: a second copy in this process must stay inert.
    if (!current_agent_copy_is_owner()) return;
    adh_footprint_capture_baseline();
    strncpy(g_entry, "start", sizeof(g_entry) - 1);
    start_reporter_watch();
    pthread_once(&g_once, do_start);
}

// If the target published its Java rich-capture reporter class via the "adh.reporter.class"
// system property, bind adh_nreport_impl onto its nReport method (RegisterNatives). Target-
// agnostic: the agent knows no class name.
static int bind_reporter_from_prop(JNIEnv *env) {
    jclass sysCls = (*env)->FindClass(env, "java/lang/System");
    jmethodID getProp = sysCls ? (*env)->GetStaticMethodID(env, sysCls, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    if (!getProp) { if (adh_jni_exception_check(env)) adh_jni_exception_clear(env); return 0; }
    jstring jkey = (*env)->NewStringUTF(env, "adh.reporter.class");
    jstring jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
    if (!jval) {
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return 0;
    }
    const char *cls = (*env)->GetStringUTFChars(env, jval, NULL);
    int ok = 0;
    if (cls && cls[0]) {
        ok = adh_capture_register_reporter(env, cls);
        LOGI("rich-capture reporter '%s' bind %s", cls, ok ? "ok" : "FAILED");
    }
    if (cls) (*env)->ReleaseStringUTFChars(env, jval, cls);
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    return ok;
}

// Zygisk starts before the app sets adh.reporter.class; poll briefly from the winning copy so the
// reporter still binds without opening a second agent copy/session.
#define ADH_REPORTER_WATCH_STEP_MS 50
#define ADH_REPORTER_WATCH_TOTAL_MS 10000
static void *reporter_watch_thread(void *arg) {
    (void)arg;
    for (int waited = 0; waited < ADH_REPORTER_WATCH_TOTAL_MS; waited += ADH_REPORTER_WATCH_STEP_MS) {
        int did = 0;
        JNIEnv *env = adh_jni_attach(&did);
        if (env) {
            int ok = bind_reporter_from_prop(env);
            if (did) adh_jni_detach(did);
            if (ok) return NULL;
        }
        usleep(ADH_REPORTER_WATCH_STEP_MS * 1000);
    }
    return NULL;
}

static void start_reporter_watch(void) {
    static int started = 0;
    if (__atomic_exchange_n(&started, 1, __ATOMIC_SEQ_CST)) return;
    pthread_t th;
    if (pthread_create(&th, NULL, reporter_watch_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        __atomic_store_n(&started, 0, __ATOMIC_SEQ_CST);
        LOGI("reporter watcher thread create failed");
    }
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    if (!current_agent_copy_is_owner()) return JNI_VERSION_1_6;
    adh_footprint_capture_baseline();
    adh_jni_set_vm(vm);
    strncpy(g_entry, "jni_onload", sizeof(g_entry) - 1);
    LOGI("JNI_OnLoad — agent " AGENT_VER " starting");
    // Bind the Java rich-capture reporter (if the target opted in via adh.reporter.class) HERE —
    // before the target installs its JCE provider — so the binding is in place before any report
    // fires. If the target sets the property later, the winning copy's watcher binds it.
    JNIEnv *env = NULL;
    int have_env = ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env);
    if (have_env && !bind_reporter_from_prop(env)) start_reporter_watch();
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}

// Handed the JavaVM by the loader that already has one.
//
// Zygisk's ModuleBase::onLoad(api, env) receives a live JNIEnv, so the loader can give us the VM
// before adh_agent_start() runs. That removes the agent's only reason to call
// JNI_GetCreatedJavaVMs at all: resolving it out of the already-mapped libart.so and CALLING it
// crashed the target process at startup (SIGSEGV/SEGV_ACCERR at libart's
// JNI_GetCreatedJavaVMs+0) because the call happens from a freshly-loaded memfd DSO on a thread
// ART has not set up for it. Preferring the handed-over VM is therefore both cheaper and safer;
// the in-memory lookup stays as the fallback for loaders that cannot provide one.
JNIEXPORT void adh_agent_set_vm(void *vm) {
    if (!vm) return;
    if (!current_agent_copy_is_owner()) return;
    adh_jni_set_vm((JavaVM *)vm);
    LOGI("JavaVM handed over by loader (no symbol lookup needed)");
}

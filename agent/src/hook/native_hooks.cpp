// Unified native hook manager: GOT or arm64 inline hook, with a fixed register-capture
// stub per slot. The recorder only formats a bounded JSON event and pushes it into the
// existing capture ring; no allocation or blocking happens on the target thread.
#include "native_hooks.h"
#include "got.h"
#include "native_inline.h"
#include "../capture/capture.h"

#include <android/log.h>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <string>

#define TAG "ADH_NATIVE_HOOK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define ADH_NATIVE_MAX_HOOKS 16

struct NativeHookContext {
    int id;
    int active;              // 0 free, 1 active, 2 reserved
    int used;                // slots are never reused after unhook (race safety)
    int mode;                // 0 got, 1 inline
    void *target;
    void *original;
    void *replacement;
    char module[128];
    char symbol[128];
    uintptr_t address;
};

static NativeHookContext g_native_hooks[ADH_NATIVE_MAX_HOOKS];
static pthread_mutex_t g_native_hooks_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_next_native_hook_id = 1;
static std::atomic<unsigned long long> g_native_hook_hits[ADH_NATIVE_MAX_HOOKS];
static std::atomic<int> g_native_hook_slot_ids[ADH_NATIVE_MAX_HOOKS];

// Referenced directly by the fixed arm64 stubs below.
extern "C" void *g_native_hook_originals[ADH_NATIVE_MAX_HOOKS] = {};

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
}

extern "C" void adh_native_hook_record(uint64_t *regs, int hook_id) {
    if (!regs || hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return;
    int hook_uid = g_native_hook_slot_ids[hook_id].load(std::memory_order_relaxed);
    if (hook_uid <= 0) hook_uid = hook_id + 1;
    g_native_hook_hits[hook_id].fetch_add(1, std::memory_order_relaxed);
    char json[640];
    snprintf(json, sizeof(json),
             "{\"hookId\":%d,\"x0\":\"0x%llx\",\"x1\":\"0x%llx\",\"x2\":\"0x%llx\","
             "\"x3\":\"0x%llx\",\"x4\":\"0x%llx\",\"x5\":\"0x%llx\",\"x6\":\"0x%llx\","
             "\"x7\":\"0x%llx\",\"x8\":\"0x%llx\",\"x18\":\"0x%llx\"}",
             hook_uid,
             (unsigned long long)regs[0], (unsigned long long)regs[1],
             (unsigned long long)regs[2], (unsigned long long)regs[3],
             (unsigned long long)regs[4], (unsigned long long)regs[5],
             (unsigned long long)regs[6], (unsigned long long)regs[7],
             (unsigned long long)regs[8], (unsigned long long)regs[12]);
    adh_capture_push_text("NATIVE_HOOK", json);
}

#define ADH_NATIVE_STUB(N, OFF) \
extern "C" void adh_native_stub_##N(void) __attribute__((naked)); \
extern "C" void adh_native_stub_##N(void) { \
    __asm__ volatile( \
        "sub sp, sp, #256\n" \
        "stp x0, x1, [sp, #0]\n" \
        "stp x2, x3, [sp, #16]\n" \
        "stp x4, x5, [sp, #32]\n" \
        "stp x6, x7, [sp, #48]\n" \
        "stp x8, x9, [sp, #64]\n" \
        "stp x29, x30, [sp, #80]\n" \
        "str x18, [sp, #96]\n" \
        "stp q0, q1, [sp, #128]\n" \
        "stp q2, q3, [sp, #160]\n" \
        "stp q4, q5, [sp, #192]\n" \
        "stp q6, q7, [sp, #224]\n" \
        "mov x0, sp\n" \
        "mov x1, #" #N "\n" \
        "bl adh_native_hook_record\n" \
        "ldp x0, x1, [sp, #0]\n" \
        "ldp x2, x3, [sp, #16]\n" \
        "ldp x4, x5, [sp, #32]\n" \
        "ldp x6, x7, [sp, #48]\n" \
        "ldp x8, x9, [sp, #64]\n" \
        "ldp x29, x30, [sp, #80]\n" \
        "ldr x18, [sp, #96]\n" \
        "ldp q0, q1, [sp, #128]\n" \
        "ldp q2, q3, [sp, #160]\n" \
        "ldp q4, q5, [sp, #192]\n" \
        "ldp q6, q7, [sp, #224]\n" \
        "add sp, sp, #256\n" \
        "adrp x16, g_native_hook_originals+" #OFF "\n" \
        "add x16, x16, :lo12:g_native_hook_originals+" #OFF "\n" \
        "ldr x16, [x16]\n" \
        "br x16\n" \
    ); \
}

ADH_NATIVE_STUB(0, 0)
ADH_NATIVE_STUB(1, 8)
ADH_NATIVE_STUB(2, 16)
ADH_NATIVE_STUB(3, 24)
ADH_NATIVE_STUB(4, 32)
ADH_NATIVE_STUB(5, 40)
ADH_NATIVE_STUB(6, 48)
ADH_NATIVE_STUB(7, 56)
ADH_NATIVE_STUB(8, 64)
ADH_NATIVE_STUB(9, 72)
ADH_NATIVE_STUB(10, 80)
ADH_NATIVE_STUB(11, 88)
ADH_NATIVE_STUB(12, 96)
ADH_NATIVE_STUB(13, 104)
ADH_NATIVE_STUB(14, 112)
ADH_NATIVE_STUB(15, 120)

static void *stub_for_id(int id) {
    switch (id) {
        case 0: return (void *)adh_native_stub_0;
        case 1: return (void *)adh_native_stub_1;
        case 2: return (void *)adh_native_stub_2;
        case 3: return (void *)adh_native_stub_3;
        case 4: return (void *)adh_native_stub_4;
        case 5: return (void *)adh_native_stub_5;
        case 6: return (void *)adh_native_stub_6;
        case 7: return (void *)adh_native_stub_7;
        case 8: return (void *)adh_native_stub_8;
        case 9: return (void *)adh_native_stub_9;
        case 10: return (void *)adh_native_stub_10;
        case 11: return (void *)adh_native_stub_11;
        case 12: return (void *)adh_native_stub_12;
        case 13: return (void *)adh_native_stub_13;
        case 14: return (void *)adh_native_stub_14;
        case 15: return (void *)adh_native_stub_15;
        default: return nullptr;
    }
}

static int find_free_slot_locked() {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (g_native_hooks[i].active == 0 && !g_native_hooks[i].used) return i;
    }
    return -1;
}

static NativeHookContext *find_hook_locked(int id) {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (g_native_hooks[i].active == 1 && g_native_hooks[i].id == id) return &g_native_hooks[i];
    }
    return nullptr;
}

static void reset_context(NativeHookContext &ctx) {
    ctx.id = 0;
    ctx.active = 0;
    ctx.mode = 0;
    ctx.target = nullptr;
    ctx.original = nullptr;
    ctx.replacement = nullptr;
    ctx.module[0] = 0;
    ctx.symbol[0] = 0;
    ctx.address = 0;
}

static void copy_cstr(char *dst, size_t size, const char *src) {
    if (!dst || !size) return;
    if (!src) { dst[0] = 0; return; }
    strncpy(dst, src, size - 1);
    dst[size - 1] = 0;
}

extern "C" int adh_native_hook_install(const char *mode, const char *module, const char *symbol,
                                        const char *addr, int *hook_id_out,
                                        char *error, size_t error_size) {
    if (hook_id_out) *hook_id_out = 0;
    if (!mode) return (set_error(error, error_size, "need mode got|inline"), 0);
    pthread_mutex_lock(&g_native_hooks_lock);
    int slot = find_free_slot_locked();
    int id = g_next_native_hook_id++;
    if (id <= 0) { g_next_native_hook_id = 1; id = g_next_native_hook_id++; }
    if (slot >= 0) {
        g_native_hooks[slot].active = 2;
        g_native_hooks[slot].used = 1;
        g_native_hooks[slot].id = id;
        g_native_hook_slot_ids[slot].store(id, std::memory_order_relaxed);
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    if (slot < 0) return (set_error(error, error_size, "too many native hooks (max %d)", ADH_NATIVE_MAX_HOOKS), 0);

    auto fail = [&](const char *message) -> int {
        pthread_mutex_lock(&g_native_hooks_lock);
        if (g_native_hooks[slot].active == 2) reset_context(g_native_hooks[slot]);
        pthread_mutex_unlock(&g_native_hooks_lock);
        set_error(error, error_size, "%s", message);
        return 0;
    };

    void *stub = stub_for_id(slot);
    void *target = nullptr;
    void *original = nullptr;
    int hook_mode = -1;
    if (strcmp(mode, "got") == 0) {
        if (!module || !module[0] || !symbol || !symbol[0]) return fail("got hook needs module and symbol");
        // Prefer the relocation slot's current resolved value: imported calls (open/access/
        // ptrace/...) are not defined by the caller module, so adh_resolve_sym alone cannot
        // recover the original function pointer. Fall back to the module-defined symbol.
        void *slot_value = nullptr;
        if (!adh_got_slot_value(module, symbol, nullptr, &slot_value) || !slot_value) {
            slot_value = adh_resolve_sym(module, symbol);
        }
        target = slot_value;
        if (!target) return fail("GOT target symbol not found or slot unresolved");
        g_native_hook_originals[slot] = target;
        int replaced = adh_got_replace_by_name(module, symbol, stub);
        if (replaced <= 0) {
            g_native_hook_originals[slot] = nullptr;
            return fail("GOT replacement failed");
        }
        original = target;
        hook_mode = 0;
    } else if (strcmp(mode, "inline") == 0) {
        if (addr && addr[0]) {
            target = (void *)(uintptr_t)strtoull(addr, nullptr, 0);
        } else if (module && module[0] && symbol && symbol[0]) {
            target = adh_resolve_sym(module, symbol);
        }
        if (!target) return fail("inline hook needs address or module+symbol");
        if (!adh_inline_hook(target, stub, &original)) return fail("inline hook installation failed");
        g_native_hook_originals[slot] = original;
        hook_mode = 1;
    } else {
        return fail("mode must be got or inline");
    }

    pthread_mutex_lock(&g_native_hooks_lock);
    NativeHookContext &ctx = g_native_hooks[slot];
    ctx.id = id;
    ctx.active = 1;
    ctx.mode = hook_mode;
    ctx.target = target;
    ctx.original = original;
    ctx.replacement = stub;
    copy_cstr(ctx.module, sizeof(ctx.module), module);
    copy_cstr(ctx.symbol, sizeof(ctx.symbol), symbol);
    ctx.address = (uintptr_t)target;
    pthread_mutex_unlock(&g_native_hooks_lock);
    g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
    if (hook_id_out) *hook_id_out = id;
    LOGI("native_hook installed id=%d mode=%s target=%p original=%p", id, mode, target, original);
    return 1;
}

extern "C" int adh_native_hook_unhook(int hook_id, char *error, size_t error_size) {
    pthread_mutex_lock(&g_native_hooks_lock);
    NativeHookContext *ctx = find_hook_locked(hook_id);
    if (!ctx) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "no native hook with id %d", hook_id), 0);
    }
    int ok = 0;
    if (ctx->mode == 0) {
        int restored = adh_got_replace(ctx->module, ctx->replacement, ctx->original);
        ok = restored > 0;
    } else {
        ok = adh_inline_unhook(ctx->target) != 0;
    }
    if (!ok) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "native unhook failed id=%d", hook_id), 0);
    }
    int slot = (int)(ctx - g_native_hooks);
    g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
    reset_context(*ctx);
    pthread_mutex_unlock(&g_native_hooks_lock);
    LOGI("native_hook removed id=%d", hook_id);
    return 1;
}

extern "C" int adh_native_hook_status_json(char *out, size_t out_size) {
    if (!out || !out_size) return 0;
    std::string hooks = "[";
    int count = 0;
    pthread_mutex_lock(&g_native_hooks_lock);
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        NativeHookContext &ctx = g_native_hooks[i];
        if (ctx.active != 1) continue;
        if (count) hooks += ",";
        unsigned long long hits = g_native_hook_hits[i].load(std::memory_order_relaxed);
        char item[768];
        snprintf(item, sizeof(item),
                 "{\"id\":%d,\"mode\":\"%s\",\"module\":\"%s\",\"symbol\":\"%s\","
                 "\"address\":\"0x%llx\",\"target\":\"0x%llx\",\"original\":\"0x%llx\","
                 "\"replacement\":\"0x%llx\",\"hits\":%llu}",
                 ctx.id, ctx.mode == 0 ? "got" : "inline", ctx.module, ctx.symbol,
                 (unsigned long long)ctx.address, (unsigned long long)(uintptr_t)ctx.target,
                 (unsigned long long)(uintptr_t)ctx.original,
                 (unsigned long long)(uintptr_t)ctx.replacement, hits);
        hooks += item;
        count++;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    hooks += "]";
    std::string json = "{\"count\":" + std::to_string(count) + ",\"hooks\":" + hooks + "}";
    snprintf(out, out_size, "%s", json.c_str());
    out[out_size - 1] = 0;
    return 1;
}
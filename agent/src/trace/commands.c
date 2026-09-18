#include "commands.h"

#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "../runtime/jni.h"
#include "qbdi_trace.h"

struct TraceRecord {
    long a0, a1, a2, a3;
    int tid;
    long long timestamp_ns;
    char a0_preview[48];
};

static struct TraceRecord g_trace[256];
static int g_trace_count = 0;
static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;
typedef long (*fn4_t)(long, long, long, long);
static fn4_t g_trace_original = NULL;
static int g_mem_fd = -1;

static int trace_mem_fd(void) {
    int fd = __atomic_load_n(&g_mem_fd, __ATOMIC_ACQUIRE);
    if (fd >= 0) return fd;
    int new_fd = open("/proc/self/mem", O_RDONLY);
    if (new_fd < 0) return -1;
    int expected = -1;
    if (!__atomic_compare_exchange_n(&g_mem_fd, &expected, new_fd, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        close(new_fd);
        return expected;
    }
    return new_fd;
}

static void trace_preview(long address, char *out, int size) {
    out[0] = 0;
    unsigned long long untagged = (unsigned long long)address & 0x00FFFFFFFFFFFFFFULL;
    if (untagged < 0x1000) return;
    int fd = trace_mem_fd();
    if (fd < 0) return;
    unsigned char buf[64];
    ssize_t read_size = pread(fd, buf, sizeof(buf), (off_t)untagged);
    if (read_size <= 0) return;
    int offset = 0;
    for (int i = 0; i < read_size && offset < size - 1; i++) {
        unsigned char c = buf[i];
        if (c == 0 || c < 0x20 || c >= 0x7f) break;
        out[offset++] = (char)c;
    }
    out[offset] = 0;
}

static long trace_wrapper(long a0, long a1, long a2, long a3) {
    int tid = (int)gettid();
    long long timestamp_ns = now_ns();
    char preview[48];
    trace_preview(a0, preview, sizeof(preview));
    pthread_mutex_lock(&g_trace_lock);
    if (g_trace_count < 256) {
        struct TraceRecord *record = &g_trace[g_trace_count++];
        record->a0 = a0;
        record->a1 = a1;
        record->a2 = a2;
        record->a3 = a3;
        record->tid = tid;
        record->timestamp_ns = timestamp_ns;
        strncpy(record->a0_preview, preview, sizeof(record->a0_preview) - 1);
        record->a0_preview[sizeof(record->a0_preview) - 1] = 0;
    }
    pthread_mutex_unlock(&g_trace_lock);
    return g_trace_original ? g_trace_original(a0, a1, a2, a3) : 0;
}

void adh_cmd_trace_run(int fd, const char *id, const char *symbol_library,
                       const char *symbol, const char *hook_module,
                       const char *class_name) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    void *original = adh_resolve_sym(symbol_library, symbol);
    g_trace_original = (fn4_t)original;
    int replaced = original ? adh_got_replace(hook_module, original, (void *)trace_wrapper) : -1;
    pthread_mutex_lock(&g_trace_lock);
    g_trace_count = 0;
    pthread_mutex_unlock(&g_trace_lock);

    int did_attach = 0, triggered = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass target = class_name[0] ? adh_jni_load_app_class(env, class_name) : NULL;
        if (target) {
            jmethodID run = (*env)->GetStaticMethodID(env, target, "run", "()I");
            if (run) {
                (*env)->CallStaticIntMethod(env, target, run);
                triggered = 1;
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did_attach);
    }
    if (replaced > 0 && original) {
        adh_got_replace(hook_module, (void *)trace_wrapper, original);
    }

    char symbolj[80];
    json_escape(symbol, symbolj, sizeof(symbolj));
    // 256 fixed records with fully escaped 47-byte previews fit below 128 KiB.
    size_t capacity = 1 << 17, length = 0;
    char *out = malloc(capacity);
    if (!out) {
        send_oom(fd, idj, "trace_run");
        return;
    }
    length += snprintf(
        out + length, capacity - length,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"trace_run\",\"ok\":true,"
        "\"symbol\":\"%s\",\"replaced\":%d,\"triggered\":%s,\"calls\":[",
        idj, symbolj, replaced, triggered ? "true" : "false");
    pthread_mutex_lock(&g_trace_lock);
    for (int i = 0; i < g_trace_count; i++) {
        struct TraceRecord *record = &g_trace[i];
        char previewj[100];
        json_escape(record->a0_preview, previewj, sizeof(previewj));
        length += snprintf(
            out + length, capacity - length,
            "%s{\"a0\":\"%lx\",\"a0str\":\"%s\",\"a1\":\"%lx\",\"a2\":\"%lx\","
            "\"a3\":\"%lx\",\"tid\":%d,\"tsNs\":%lld}",
            i ? "," : "", (unsigned long)record->a0, previewj,
            (unsigned long)record->a1, (unsigned long)record->a2,
            (unsigned long)record->a3, record->tid, record->timestamp_ns);
    }
    int count = g_trace_count;
    pthread_mutex_unlock(&g_trace_lock);
    snprintf(out + length, capacity - length, "],\"count\":%d}\n", count);
    send_line(fd, out);
    free(out);
    LOGI("trace_run: sym=%s replaced=%d triggered=%d calls=%d", symbol, replaced,
         triggered, count);
}

void adh_cmd_qbdi_trace(int fd, const char *id, const char *symbol_library,
                        const char *symbol, const char *args_csv) {
    // The caller names both the library and the symbol. A fixture name must never be baked in
    // here: the agent runs in arbitrary targets, so a hardcoded module/symbol is a coupling bug
    // AND a signature the target can read straight out of our own memory. Fail loud instead of
    // silently tracing whatever fixture happened to be loaded.
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    if (!symbol_library[0] || !symbol[0]) {
        char err[192];
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\","
                 "\"ok\":false,\"error\":\"qbdi_trace needs symLib and symbol\"}\n",
                 idj);
        send_line(fd, err);
        return;
    }
    const char *library = symbol_library;
    const char *target_symbol = symbol;
    void *function = adh_resolve_sym(library, target_symbol);
    if (!function) {
        char error[160];
        snprintf(error, sizeof(error),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\","
                 "\"ok\":false,\"error\":\"symbol not found\"}\n",
                 idj);
        send_line(fd, error);
        return;
    }

    unsigned long long args[8] = {0};
    int argc = 0;
    char arg_error[256] = "";
    if (!adh_parse_u64_csv(args_csv ? args_csv : "", args, 8, &argc, arg_error, sizeof(arg_error))) {
        char errorj[320];
        json_escape(arg_error, errorj, sizeof(errorj));
        char *error_out = malloc(520);
        if (!error_out) { send_oom(fd, idj, "qbdi_trace"); return; }
        snprintf(error_out, 520,
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",\"ok\":false,"
                 "\"error\":\"%s\"}\n", idj, errorj);
        send_line(fd, error_out);
        free(error_out);
        return;
    }

    char *trace = malloc(1 << 18);
    if (!trace) {
        send_oom(fd, idj, "qbdi_trace");
        return;
    }
    trace[0] = 0;
    adh_qbdi_trace(function, args, argc, trace, (1 << 18) - 64);
    char *message = malloc((1 << 18) + 128);
    if (!message) {
        free(trace);
        send_oom(fd, idj, "qbdi_trace");
        return;
    }
    snprintf(message, (1 << 18) + 128,
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",%s}\n",
             idj, trace);
    send_line(fd, message);
    free(message);
    free(trace);
    LOGI("qbdi_trace %s -> done", target_symbol);
}

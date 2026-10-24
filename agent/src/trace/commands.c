#include "commands.h"

#include <fcntl.h>
#include <jni.h>
#include <stdint.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"

#include "qbdi_trace.h"

void adh_cmd_qbdi_trace(int fd, const char *id, const char *symbol_library,
                        const char *symbol, const char *args_csv, const char *addr_hex,
                        int paged, int budget, int time_ms, int capacity) {
    // The caller names either a library+symbol, or an absolute ADDRESS. A fixture name must never
    // be baked in here: the agent runs in arbitrary targets, so a hardcoded module/symbol is a
    // coupling bug AND a signature the target can read straight out of our own memory. The address
    // form exists because the interesting functions in a stripped, obfuscated library are not
    // exported at all (`main` in libjdg is registered through RegisterNatives, so its address only
    // comes from the static method table) — symbol-only tracing could not reach them.
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    void *function = NULL;
    char target_label[96] = "";
    unsigned long long addr = 0;
    if (addr_hex && addr_hex[0]) {
        char *end = NULL;
        addr = strtoull(addr_hex, &end, 0);
        if (!addr) {
            char errline[192];
            snprintf(errline, sizeof(errline),
                     "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",\"ok\":false,"
                     "\"error\":\"addr did not parse (expected 0x…)\"}\n", idj);
            send_line(fd, errline);
            return;
        }
        function = (void *)(uintptr_t)addr;
        snprintf(target_label, sizeof(target_label), "addr:%s", addr_hex);
    } else if (symbol_library[0] && symbol[0]) {
        function = adh_resolve_sym(symbol_library, symbol);
        snprintf(target_label, sizeof(target_label), "%s!%s", symbol_library, symbol);
    } else {
        char err[224];
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\","
                 "\"ok\":false,\"error\":\"qbdi_trace needs symLib+symbol or addr\"}\n",
                 idj);
        send_line(fd, err);
        return;
    }
    const char *target_symbol = target_label;
    if (!function) {
        char error[192];
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
    char *message = malloc((1 << 18) + 128);
    if (!message) {
        free(trace);
        send_oom(fd, idj, "qbdi_trace");
        return;
    }
    trace[0] = 0;
    if (paged) adh_qbdi_trace_paged(function, args, argc, budget, time_ms, capacity, trace, (1 << 18) - 64);
    else adh_qbdi_trace(function, args, argc, trace, (1 << 18) - 64);
    snprintf(message, (1 << 18) + 128,
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",%s}\n",
             idj, trace);
    send_line(fd, message);
    free(message);
    free(trace);
    LOGI("qbdi_trace %s -> done", target_symbol);
}

void adh_cmd_qbdi_read(int fd, const char *id, unsigned long long trace_id, int offset, int limit, int release) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char *body = malloc(24576), *message = malloc(24832);
    if (!body || !message) { free(body); free(message); send_oom(fd, idj, "qbdi_read"); return; }
    adh_qbdi_read(trace_id, offset, limit, release, body, 24576);
    snprintf(message, 24832, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_read\",%s}\n", idj, body);
    send_line(fd, message); free(message); free(body);
}

#include "commands.h"

#include <fcntl.h>
#include <jni.h>
#include <stdint.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"

#include "qbdi_trace.h"

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

#ifndef ADH_PROCESS_IDENTITY_H
#define ADH_PROCESS_IDENTITY_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Linux stat comm (field 2) can contain spaces, ')' and even newlines. Only
// fields AFTER the final ')' may be tokenized. Keep field 22 as decimal text.
static inline int adh_parse_starttime_ticks(const char *stat, char *out, size_t cap) {
    if (!out || !cap) return 0;
    out[0] = 0;
    if (!stat) return 0;
    const char *p = strrchr(stat, ')');
    if (!p || p[1] != ' ') return 0;
    p++;
    for (int field = 3; field <= 22; field++) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        size_t n = (size_t)(p - start);
        if (!n) return 0;
        if (field == 22) {
            if (n > 20 || n >= cap) return 0;
            for (size_t i = 0; i < n; i++) if (start[i] < '0' || start[i] > '9') return 0;
            memcpy(out, start, n); out[n] = 0;
            return 1;
        }
    }
    return 0;
}

static inline int adh_self_starttime_ticks(char *out, size_t cap) {
    if (!out || !cap) return 0;
    out[0] = 0;
    FILE *file = fopen("/proc/self/stat", "r");
    if (!file) return 0;
    char stat[4096];
    size_t n = fread(stat, 1, sizeof(stat) - 1, file);
    int failed = ferror(file);
    fclose(file);
    stat[n] = 0;
    return !failed && adh_parse_starttime_ticks(stat, out, cap);
}

#endif

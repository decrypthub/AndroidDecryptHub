// JNIEnv hooks: core state, shared helpers, layout self-check, slot
// lookup/dispatch, filters and the jni_env_hook command handler.
// Wrapper families live in jni_env_{fixed,calls,fields,string,misc,objects}.c.

#include "jni_env_hooks_internal.h"

 struct EnvHookSlot g_env_hooks[] = {
    ADH_FIXED_SLOT_LIST(ADH_FIXED_INIT)
    ADH_CALL_VALUE_FAMILIES(ADH_CALL_INITS)
    ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_INITS)
    ADH_CALLNV_VALUE_FAMILIES(ADH_CALLNV_INITS)
    ADH_CALLNV_VOID_FAMILIES(ADH_CALLNV_VOID_INITS)
    ADH_FIELD_SLOT_LIST(ADH_FIELD_NAME_ENTRY)
};
// The table is indexed by the ENV_SLOT_* enumerators, so its size must be exactly the enum
// value that follows them: an unsized array plus this assert turns "the enum and the table
// drifted apart" into one clear compile error instead of silent truncation.
_Static_assert(sizeof(g_env_hooks) / sizeof(g_env_hooks[0]) == ENV_HOOK_MAX,
               "g_env_hooks must have exactly ENV_HOOK_MAX entries");
_Static_assert(ENV_SLOT_SetStaticDoubleField == ENV_HOOK_MAX - 1,
               "the field accessors are the last group in the table, so the last field slot must be the"
               " last enum value before ENV_HOOK_MAX (a drifting base would land on the wrong slot)");
// A total-size check alone cannot see a shifted layout: in the broken version the table and the enum
// agreed on the count while every field slot sat one index too high. These pin the group BASES to the
// positions the table actually has (fixed slots, then the Call families, then the field block).
_Static_assert(ENV_SLOT_CallObjectMethod == ENV_FIXED_SLOTS,
               "the Call families start right after the fixed slots");
_Static_assert(ENV_SLOT_CallNonvirtualObjectMethod == ENV_SLOT_CallStaticVoidMethod + 3,
               "the CallNonvirtual families start where the CallStaticVoid family ends");
_Static_assert(ENV_SLOT_GetObjectField == ENV_SLOT_CallNonvirtualVoidMethod + 3,
               "the field accessor block starts exactly where the last CallNonvirtual family ends");
_Static_assert(ENV_SLOT_SetStaticDoubleField == ENV_SLOT_GetObjectField + 35,
               "the field list must stay at 36 entries, one table entry each");

static pthread_mutex_t g_env_hook_lock = PTHREAD_MUTEX_INITIALIZER;
// Marks the current thread as running ADH instrumentation code (label resolution, class
// names, array-length reads). Only our own nested JNI calls are suppressed by it: the target's
// own call always runs with the flag clear, so Java->JNI callbacks made *inside* a hooked call
// are still observed. Setting it across the target call would silently hide that traffic.
 __thread int g_env_hook_in_ours = 0;

// ADH's own JNI work (class-name resolution, loader lookups, command paths) must not be recorded as
// target behaviour when the corresponding slots are hooked. Helpers that do such work set this flag
// around themselves; the enter/leave pair restores the previous value, so a helper called from inside
// a wrapper (where the flag is already set) behaves exactly like one called from a command path.
int adh_jni_ours_enter(void) {
    int previous = g_env_hook_in_ours;
    g_env_hook_in_ours = 1;
    return previous;
}

void adh_jni_ours_leave(int previous) {
    g_env_hook_in_ours = previous;
}
static unsigned long long g_env_hook_table = 0;


 void *slot_original(int index) {
    return __atomic_load_n(&g_env_hooks[index].original, __ATOMIC_ACQUIRE);
}
 int slot_active(int index) {
    return __atomic_load_n(&g_env_hooks[index].active, __ATOMIC_ACQUIRE);
}
// True while the slot may still emit a record - the gate for all expensive detail work.
 int env_budget_left(int index) {
    return __atomic_load_n(&g_env_hooks[index].hits, __ATOMIC_RELAXED) < ENV_EVENT_LIMIT;
}

// Count one intercepted call and, while under budget, push one bounded record. value may be
// NULL (over budget / no detail available) and ok reports whether the JNI call succeeded.
 void env_note(int index, const char *value, int ok) {
    unsigned long long hits = __atomic_add_fetch(&g_env_hooks[index].hits, 1, __ATOMIC_RELAXED);
    if (hits > ENV_EVENT_LIMIT) {
        __atomic_add_fetch(&g_env_hooks[index].dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    snprintf(g_env_hooks[index].last, sizeof(g_env_hooks[index].last), "%s", value ? value : "");
    char valuej[1024], json[1280];
    json_escape(value ? value : "", valuej, sizeof(valuej));
    snprintf(json, sizeof(json), "{\"function\":\"%s\",\"value\":\"%s\",\"ok\":%s}",
             g_env_hooks[index].name, valuej, ok ? "true" : "false");
    adh_capture_push_text("JNI_ENV", json);
}

// ADH's own exception checks must NOT go through the (possibly hooked) table entry. If the
// ExceptionCheck slot is installed, every ADH-side call would otherwise be recorded as target
// behaviour - wrong attribution - and re-entering the wrapper from instrumentation paths is pure
// noise. The saved original is used once the slot has been installed, the live entry otherwise;
// both are the real function. Shared with the rest of the agent (jni_env_hooks.h) so no module
// has to remember this rule.
jboolean adh_jni_exception_check(JNIEnv *env) {
    if (!env || !(*env)->ExceptionCheck) return 0;
    jboolean (*original)(JNIEnv *) = (jboolean (*)(JNIEnv *))slot_original(ENV_SLOT_ExceptionCheck);
    if (original) return original(env) ? 1 : 0;
    return (*env)->ExceptionCheck(env) ? 1 : 0;
}

// ExceptionClear is a hookable table entry too: ADH clearing an exception it caused (or parking one
// while it resolves a name) must not look like target behaviour either.
void adh_jni_exception_clear(JNIEnv *env) {
    if (!env || !(*env)->ExceptionClear) return;
    void (*original)(JNIEnv *) = (void (*)(JNIEnv *))slot_original(ENV_SLOT_ExceptionClear);
    if (original) { original(env); return; }
    (*env)->ExceptionClear(env);
}
// ---- member-ID / array detail --------------------------------------------
 void detail_method_plain(const char *name, const char *sig, char *out, size_t out_size) {
    snprintf(out, out_size, "?#%s%s", name ? name : "", sig ? sig : "");
}

 void detail_field_plain(const char *name, const char *sig, char *out, size_t out_size) {
    snprintf(out, out_size, "?#%s:%s", name ? name : "", sig ? sig : "");
}

 void detail_method(JNIEnv *env, jclass clazz, const char *name, const char *sig,
                          char *out, size_t out_size) {
    char cls[192];
    adh_jni_class_name(env, clazz, cls, sizeof(cls));
    snprintf(out, out_size, "%s#%s%s", cls[0] ? cls : "?", name ? name : "", sig ? sig : "");
}

 void detail_field(JNIEnv *env, jclass clazz, const char *name, const char *sig,
                         char *out, size_t out_size) {
    char cls[192];
    adh_jni_class_name(env, clazz, cls, sizeof(cls));
    snprintf(out, out_size, "%s#%s:%s", cls[0] ? cls : "?", name ? name : "", sig ? sig : "");
}

 void hex_preview(const jbyte *data, jsize len, char *out, size_t out_size) {
    size_t used = 0;
    jsize cap = len > ENV_HEX_PREVIEW ? ENV_HEX_PREVIEW : len;
    if (!out || out_size == 0) return;
    out[0] = 0;
    if (!data || cap <= 0) return;
    for (jsize i = 0; i < cap && used + 3 < out_size; i++) {
        used += (size_t)snprintf(out + used, out_size - used, "%02x", (unsigned char)data[i]);
    }
}

// ---- Call* argument rendering --------------------------------------------

static void append_quoted_string(JNIEnv *env, jobject obj, char *out, size_t out_size) {
    if (!obj) { snprintf(out, out_size, "null"); return; }
    const char *chars = (*env)->GetStringUTFChars(env, (jstring)obj, NULL);
    if (!chars) {
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        snprintf(out, out_size, "str?");
        return;
    }
    size_t w = 0;
    out[w++] = '"';
    for (size_t i = 0; chars[i] && w + 5 < out_size; i++) {
        unsigned char c = (unsigned char)chars[i];
        if (c == '"' || c == '\\') { out[w++] = '\\'; out[w++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) out[w++] = (char)c;
        else w += (size_t)snprintf(out + w, out_size - w, "\\x%02x", c);
    }
    out[w++] = '"';
    out[w] = 0;
    (*env)->ReleaseStringUTFChars(env, (jstring)obj, chars);
}

// Walk a JNI method signature and render up to ENV_ARG_PARAMS argument values. Either the
// va_list form (varargs promotion rules: sub-int -> int, float -> double) or the jvalue array
// form is used. Callers guarantee no exception is pending.
static void render_signature_args(JNIEnv *env, const char *sig, char *out, size_t out_size,
                                  int from_va, const jvalue *jargs, va_list ap) {
    size_t w = 0;
    out[0] = 0;
    if (!sig || sig[0] != '(') return;
    const char *p = sig + 1;
    int index = 0;
    int first = 1;
    while (*p && *p != ')' && index < ENV_ARG_PARAMS) {
        char desc[96];
        size_t dl = 0;
        if (*p == '[') {
            while (*p == '[' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
            if (*p == 'L') {
                while (*p && *p != ';' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
                if (*p == ';') desc[dl++] = *p++;
            } else if (*p) {
                desc[dl++] = *p++;
            }
        } else if (*p == 'L') {
            while (*p && *p != ';' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
            if (*p == ';') desc[dl++] = *p++;
        } else if (*p) {
            desc[dl++] = *p++;
        }
        desc[dl] = 0;
        char one[ENV_ARG_CHARS + 8] = "";
        char type = desc[0];
        if (type == 'L' && strcmp(desc, "Ljava/lang/String;") == 0) {
            jobject o = from_va ? va_arg(ap, jobject) : jargs[index].l;
            append_quoted_string(env, o, one, sizeof(one));
        } else if (type == 'L' || type == '[') {
            jobject o = from_va ? va_arg(ap, jobject) : jargs[index].l;
            snprintf(one, sizeof(one), "@0x%llx", (unsigned long long)(uintptr_t)o);
        } else {
            switch (type) {
                case 'Z': case 'B': case 'C': case 'S': case 'I': {
                    jint v = from_va ? va_arg(ap, jint) : jargs[index].i;
                    if (type == 'Z') snprintf(one, sizeof(one), "%s", v ? "true" : "false");
                    else snprintf(one, sizeof(one), "%d", (int)v);
                    break;
                }
                case 'J': {
                    jlong v = from_va ? va_arg(ap, jlong) : jargs[index].j;
                    snprintf(one, sizeof(one), "%lld", (long long)v);
                    break;
                }
                case 'F': case 'D': {
                    double v = from_va ? va_arg(ap, double)
                                       : (type == 'F' ? (double)jargs[index].f : jargs[index].d);
                    snprintf(one, sizeof(one), "%g", v);
                    break;
                }
                default: snprintf(one, sizeof(one), "?"); break;
            }
        }
        int written = snprintf(out + w, out_size > w ? out_size - w : 0, "%s%s",
                               first ? "" : ",", one);
        if (written < 0) break;
        w += (size_t)written;
        first = 0;
        index++;
        if (w + 8 >= out_size) break;
    }
    if (*p != ')' && index >= ENV_ARG_PARAMS) {
        size_t cur = strlen(out);
        if (cur + 5 < out_size) snprintf(out + cur, out_size - cur, ",...");
    }
}

static void call_detail_common(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                               struct AdhCallDetail *d, int from_va, const jvalue *jargs, va_list ap) {
    d->text[0] = 0;
    d->ok = 0;
    if (!env_budget_left(slot)) return;
    struct AdhMethodInfo info;
    adh_jni_method_info(env, target, kind, mid, &info);
    if (!info.ok) {
        snprintf(d->text, sizeof(d->text), "%s", info.label);
        return;
    }
    char args[360];
    render_signature_args(env, info.sig, args, sizeof(args), from_va, jargs, ap);
    snprintf(d->text, sizeof(d->text), "%s args(%s)", info.label, args);
    d->ok = 1;
}

 void call_detail_va(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                           va_list ap, struct AdhCallDetail *d) {
    va_list copy;
    va_copy(copy, ap);
    call_detail_common(env, slot, target, kind, mid, d, 1, NULL, copy);
    va_end(copy);
}

 void call_detail_a(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                          const jvalue *args, struct AdhCallDetail *d) {
    va_list empty;
    memset(&empty, 0, sizeof(empty));
    call_detail_common(env, slot, target, kind, mid, d, 0, args, empty);
}

 void call_emit(int slot, struct AdhCallDetail *d) {
    env_note(slot, d->text[0] ? d->text : NULL, d->ok);
}
#define ADH_CALL_ASSERT_3(name)                                                                 \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name), \
                   __typeof__(&name##_wrapper)), "family wrapper signature mismatch");          \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name##V), \
                   __typeof__(&name##V_wrapper)), "family V wrapper signature mismatch");       \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name##A), \
                   __typeof__(&name##A_wrapper)), "family A wrapper signature mismatch");

// Every Call* / CallNonvirtual* family gets the same compile-time proof the fixed slots, the field
// accessors and the array families already have: the wrappers are cast to void* at install time, so a
// signature mismatch would only surface when the target calls the entry.
#define ADH_CALL_ASSERT_VALUE(name, ret, tgt, kind, base, spec) ADH_CALL_ASSERT_3(name)
#define ADH_CALL_ASSERT_VOID(name, tgt, kind, base, spec) ADH_CALL_ASSERT_3(name)
ADH_CALL_VALUE_FAMILIES(ADH_CALL_ASSERT_VALUE)
ADH_CALL_VOID_FAMILIES(ADH_CALL_ASSERT_VOID)
ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_ASSERT_VALUE)
ADH_CALLNV_VOID_FAMILIES(ADH_CALL_ASSERT_VOID)

// ---- layout self-check ----------------------------------------------------
// The enum values ARE the table indices (name lookup returns a table position and every switch is
// keyed by the enum), so a drift between the two installs the NEIGHBOURING entry while the reply
// still shows the requested name - exactly how the field family looked installed for months. This
// mapping is generated from the same lists that build the enum and the table; comparing the two
// turns any such drift into a refusal instead of a hook on the wrong function.
#define ADH_ENUM_NAME_CASE(name) case ENV_SLOT_##name: return #name;
#define ADH_FAMILY_NAME_CASES(name, ret, tgt, kind, base, spec) \
    case base: return #name; case base + 1: return #name "V"; case base + 2: return #name "A";
#define ADH_FAMILY_VOID_NAME_CASES(name, tgt, kind, base, spec) \
    ADH_FAMILY_NAME_CASES(name, void, tgt, kind, base, spec)

static const char *env_slot_name(int index) {
    switch (index) {
        ADH_FIXED_SLOT_LIST(ADH_ENUM_NAME_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_FAMILY_NAME_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_FAMILY_VOID_NAME_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_FAMILY_NAME_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_FAMILY_VOID_NAME_CASES)
        ADH_FIELD_SLOT_LIST(ADH_ENUM_NAME_CASE)
        default: return NULL;
    }
}

static int env_hook_layout_ok(char *error, size_t error_size) {
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        const char *expect = env_slot_name(i);
        if (!expect || strcmp(expect, g_env_hooks[i].name) != 0) {
            snprintf(error, error_size,
                     "JNIEnv slot table layout mismatch at %d: the enum names it %s, the table has %s - refusing to patch anything",
                     i, expect ? expect : "(none)", g_env_hooks[i].name);
            return 0;
        }
    }
    return 1;
}

static int g_env_layout_state = 0;              // 0 = unchecked, 1 = ok, -1 = mismatch
static char g_env_layout_error[224];

static int env_hook_layout_ready(char *error, size_t error_size) {
    int state = __atomic_load_n(&g_env_layout_state, __ATOMIC_ACQUIRE);
    if (state == 0) {
        int ok = env_hook_layout_ok(g_env_layout_error, sizeof(g_env_layout_error));
        __atomic_store_n(&g_env_layout_state, ok ? 1 : -1, __ATOMIC_RELEASE);
        state = ok ? 1 : -1;
    }
    if (state < 0) { snprintf(error, error_size, "%s", g_env_layout_error); return 0; }
    return 1;
}


// ---- slot lookup ----------------------------------------------------------
static int env_hook_index(const char *name) {
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (strcmp(g_env_hooks[i].name, name) == 0) return i;
    }
    return -1;
}

#define ADH_CALL_SLOT_CASES(name, ret, tgt, kind, base, spec) \
    case base: return (void **)(uintptr_t)&table->name; \
    case base + 1: return (void **)(uintptr_t)&table->name##V; \
    case base + 2: return (void **)(uintptr_t)&table->name##A;
#define ADH_CALL_VOID_SLOT_CASES(name, tgt, kind, base, spec) ADH_CALL_SLOT_CASES(name, void, tgt, kind, base, spec)

static void **env_hook_slot(struct JNINativeInterface *table, int index) {
    switch (index) {
        ADH_FIXED_SLOT_LIST(ADH_FIXED_SLOT_CASE)
        ADH_FIELD_SLOT_LIST(ADH_FIELD_SLOT_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
        default: return NULL;
    }
}

#define ADH_CALL_WRAPPER_CASES(name, ret, tgt, kind, base, spec) \
    case base: return (void *)&name##_wrapper; \
    case base + 1: return (void *)&name##V_wrapper; \
    case base + 2: return (void *)&name##A_wrapper;
#define ADH_CALL_VOID_WRAPPER_CASES(name, tgt, kind, base, spec) ADH_CALL_WRAPPER_CASES(name, void, tgt, kind, base, spec)

static void *env_hook_wrapper(int index) {
    switch (index) {
        ADH_FIXED_SLOT_LIST(ADH_FIXED_WRAPPER_CASE)
        ADH_FIELD_SLOT_LIST(ADH_FIELD_WRAPPER_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)
        default: return NULL;
    }
}

// ---- command handling -----------------------------------------------------

// ---- slot filters ---------------------------------------------------------
// `function` doubles as a pattern for action:status, with the same language the install path uses
// (exact name, prefix, "*suffix", "*contains*", "all"/"*") plus the keyword "installed" for the
// slots that are hooked right now. One parser for both paths, so they cannot drift apart.
struct EnvNameFilter {
    const char *pat;
    size_t pat_len;
    int wildcard;
    int suffix_only;
    int contains;
    int installed_only;
};

static void env_filter_parse(const char *function, struct EnvNameFilter *f) {
    memset(f, 0, sizeof(*f));
    f->pat = function ? function : "";
    f->pat_len = strlen(f->pat);
    if (f->pat_len && strcmp(f->pat, "installed") == 0) {
        f->wildcard = 1;
        f->installed_only = 1;
        f->pat = "";
        f->pat_len = 0;
        return;
    }
    if (f->pat_len == 0 || strcmp(f->pat, "all") == 0 || strcmp(f->pat, "*") == 0) {
        f->wildcard = 1;
        f->pat = "";
        f->pat_len = 0;
        return;
    }
    if (f->pat[0] == '*') {
        f->wildcard = 1;
        f->pat++;
        f->pat_len--;
        if (f->pat_len && f->pat[f->pat_len - 1] == '*') { f->contains = 1; f->pat_len--; }
        else f->suffix_only = 1;
    } else if (f->pat[f->pat_len - 1] == '*') {
        f->wildcard = 1;
        f->pat_len--;
    }
}

static int env_filter_match(const struct EnvNameFilter *f, const char *name) {
    if (!f->wildcard) return strcmp(name, f->pat) == 0;
    if (f->pat_len == 0) return 1;                                  // all / * / installed
    size_t nlen = strlen(name);
    if (f->suffix_only) return nlen >= f->pat_len && strncmp(name + nlen - f->pat_len, f->pat, f->pat_len) == 0;
    if (f->contains) {
        for (size_t o = 0; o + f->pat_len <= nlen; o++) {
            if (strncmp(name + o, f->pat, f->pat_len) == 0) return 1;
        }
        return 0;
    }
    return strncmp(name, f->pat, f->pat_len) == 0;                   // prefix
}
// Every slot is reported, hooked or not. slotValue is the LIVE table entry read at reply time:
// installing must make it differ from original, uninstalling must make them equal again - that
// is what lets a verifier prove the table (not just a flag) was patched and restored.
static void send_env_result(int fd, const char *id, const char *action, const char *function,
                            int ok, int applied, int failed, const char *error) {
    char idj[64], actionj[32], functionj[96], errorj[384];
    json_escape(id, idj, sizeof(idj));
    json_escape(action ? action : "", actionj, sizeof(actionj));
    json_escape(function ? function : "", functionj, sizeof(functionj));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char table_perms[8] = "";
    if (g_env_hook_table) adh_perms_of_addr((void *)(uintptr_t)g_env_hook_table, table_perms, sizeof(table_perms));
    // Same 128 KB buffer as action:status, and the same honesty rule: a slot list that does not fit
    // must say so (total/emitted/truncated) instead of looking like the whole table. The old 32 KB
    // buffer silently dropped 69 of the 228 slots, so a caller counting installed entries saw 159.
    static char out[128 * 1024];              // command handling is serial; agent frames carry up to FRAME_MAX
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":%s,"
        "\"action\":\"%s\",\"function\":\"%s\",\"applied\":%d,\"failed\":%d,"
        "\"table\":\"0x%llx\",\"tablePerms\":\"%s\",\"error\":\"%s\",\"hooks\":[",
        idj, ok ? "true" : "false", actionj, functionj, applied, failed,
        g_env_hook_table, table_perms, errorj);
    int first = 1, emitted = 0;
    pthread_mutex_lock(&g_env_hook_lock);
    for (int i = 0; i < ENV_HOOK_MAX && len + 900 < sizeof(out); i++) {
        char slot_perms[8] = "";
        char lastj[512];
        json_escape(g_env_hooks[i].last, lastj, sizeof(lastj));
        // A running write override must be visible in status - otherwise the operator cannot tell
        // whether a Set<Type>Field hook is still rewriting values.
        char ovbuf[48] = "";
        if (g_env_hooks[i].override_active) {
            if ((double)g_env_hooks[i].override_i == g_env_hooks[i].override_d) snprintf(ovbuf, sizeof(ovbuf), "%lld", g_env_hooks[i].override_i);
            else snprintf(ovbuf, sizeof(ovbuf), "%g", g_env_hooks[i].override_d);
        }
        const char *ovjson = g_env_hooks[i].override_active ? ovbuf : "null";
        void *live = NULL;
        if (g_env_hooks[i].slot) {
            adh_perms_of_addr((void *)(uintptr_t)g_env_hooks[i].slot, slot_perms, sizeof(slot_perms));
            live = __atomic_load_n(g_env_hooks[i].slot, __ATOMIC_ACQUIRE);
        }
        len += snprintf(out + len, sizeof(out) - len,
                        "%s{\"function\":\"%s\",\"installed\":%s,\"active\":%s,"
                        "\"hits\":%llu,\"dropped\":%llu,\"entry\":\"0x%llx\",\"perms\":\"%s\","
                        "\"slotValue\":\"0x%llx\",\"original\":\"0x%llx\",\"override\":%s,\"last\":\"%s\"}",
                        first ? "" : ",", g_env_hooks[i].name,
                        g_env_hooks[i].installed ? "true" : "false",
                        slot_active(i) ? "true" : "false",
                        g_env_hooks[i].hits, g_env_hooks[i].dropped,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].slot, slot_perms,
                        (unsigned long long)(uintptr_t)live,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].original,
                        g_env_hooks[i].override_active ? ovjson : "null", lastj);
        first = 0;
        emitted++;
    }
    pthread_mutex_unlock(&g_env_hook_lock);
    snprintf(out + len, sizeof(out) - len, "],\"total\":%d,\"emitted\":%d,\"truncated\":%s}\n",
             ENV_HOOK_MAX, emitted, emitted < ENV_HOOK_MAX ? "true" : "false");
    send_line(fd, out);
}

// The status reply says how much of the table it is showing. The list is filtered by `function`
// and, if it still does not fit the frame buffer, clipped - and both facts are in the reply
// (total/matched/emitted/truncated), because a partial slot list that claims to be complete is
// worse than no list at all: a verifier would read "not installed" out of a missing entry.
static void send_env_status(int fd, const char *id, const char *function, const struct EnvNameFilter *filter) {
    static char out[128 * 1024];              // command handling is serial; agent frames carry up to FRAME_MAX
    char idj[64], functionj[96];
    json_escape(id, idj, sizeof(idj));
    json_escape(function ? function : "", functionj, sizeof(functionj));
    char table_perms[8] = "";
    if (g_env_hook_table) adh_perms_of_addr((void *)(uintptr_t)g_env_hook_table, table_perms, sizeof(table_perms));

    // Pass 1: count what matches, so the header can state it even when the list is clipped.
    int matched = 0;
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (filter->installed_only && !g_env_hooks[i].installed) continue;
        if (env_filter_match(filter, g_env_hooks[i].name)) matched++;
    }

    // Status stays available even when the layout is broken - that is exactly when an operator
    // needs to see the table - but it has to SAY so instead of looking healthy.
    char layout_error[224] = "";
    int layout_ok = env_hook_layout_ready(layout_error, sizeof(layout_error));
    char layout_errorj[256] = "";
    if (!layout_ok) json_escape(layout_error, layout_errorj, sizeof(layout_errorj));
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":true,"
        "\"action\":\"status\",\"function\":\"%s\",\"applied\":0,\"failed\":0,"
        "\"total\":%d,\"matched\":%d,\"layout\":\"%s\",\"layoutError\":\"%s\","
        "\"table\":\"0x%llx\",\"tablePerms\":\"%s\",\"error\":\"\",\"hooks\":[",
        idj, functionj, ENV_HOOK_MAX, matched, layout_ok ? "ok" : "mismatch", layout_errorj,
        g_env_hook_table, table_perms);

    // Pass 2: emit what fits. A slot that does not fit is NOT reported as absent - the header
    // carries matched vs emitted so the caller knows the list was clipped.
    int emitted = 0, first = 1;
    pthread_mutex_lock(&g_env_hook_lock);
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (filter->installed_only && !g_env_hooks[i].installed) continue;
        if (!env_filter_match(filter, g_env_hooks[i].name)) continue;
        if (len + 900 >= sizeof(out)) continue;
        char slot_perms[8] = "";
        char lastj[512];
        json_escape(g_env_hooks[i].last, lastj, sizeof(lastj));
        char ovbuf[48] = "";
        if (g_env_hooks[i].override_active) {
            if ((double)g_env_hooks[i].override_i == g_env_hooks[i].override_d) snprintf(ovbuf, sizeof(ovbuf), "%lld", g_env_hooks[i].override_i);
            else snprintf(ovbuf, sizeof(ovbuf), "%g", g_env_hooks[i].override_d);
        }
        const char *ovjson = g_env_hooks[i].override_active ? ovbuf : "null";
        void *live = NULL;
        if (g_env_hooks[i].slot) {
            adh_perms_of_addr((void *)(uintptr_t)g_env_hooks[i].slot, slot_perms, sizeof(slot_perms));
            live = __atomic_load_n(g_env_hooks[i].slot, __ATOMIC_ACQUIRE);
        }
        len += snprintf(out + len, sizeof(out) - len,
                        "%s{\"function\":\"%s\",\"installed\":%s,\"active\":%s,"
                        "\"hits\":%llu,\"dropped\":%llu,\"entry\":\"0x%llx\",\"perms\":\"%s\","
                        "\"slotValue\":\"0x%llx\",\"original\":\"0x%llx\",\"override\":%s,\"last\":\"%s\"}",
                        first ? "" : ",", g_env_hooks[i].name,
                        g_env_hooks[i].installed ? "true" : "false",
                        slot_active(i) ? "true" : "false",
                        g_env_hooks[i].hits, g_env_hooks[i].dropped,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].slot, slot_perms,
                        (unsigned long long)(uintptr_t)live,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].original,
                        g_env_hooks[i].override_active ? ovjson : "null", lastj);
        first = 0;
        emitted++;
    }
    pthread_mutex_unlock(&g_env_hook_lock);
    // emitted/truncated are only known now, so they travel after the list instead of forcing a
    // rewrite of the header (the header states total+matched, which are known up front).
    snprintf(out + len, sizeof(out) - len, "],\"emitted\":%d,\"truncated\":%s}\n",
             emitted, (emitted == matched) ? "false" : "true");
    send_line(fd, out);
}

// Restore one slot's original entry. Fail-loud: refuse if the entry no longer points at our
// wrapper (somebody else patched it), and stay active if the page cannot be made writable.
static int env_hook_uninstall_index(int index, char *error, size_t error_size) {
    pthread_mutex_lock(&g_env_hook_lock);
    if (!g_env_hooks[index].installed || !g_env_hooks[index].slot) {
        pthread_mutex_unlock(&g_env_hook_lock);
        snprintf(error, error_size, "%s is not hooked", g_env_hooks[index].name);
        return 0;
    }
    void **saved_slot = g_env_hooks[index].slot;
    void *saved_original = g_env_hooks[index].original;
    pthread_mutex_unlock(&g_env_hook_lock);

    // Deactivate first: a call already inside the wrapper then still reaches the real
    // implementation (saved_original is a stable pointer) but stops emitting events.
    __atomic_store_n(&g_env_hooks[index].active, 0, __ATOMIC_RELEASE);
    void *current = __atomic_load_n(saved_slot, __ATOMIC_ACQUIRE);
    if (current != env_hook_wrapper(index)) {
        snprintf(error, error_size, "%s: table entry changed underneath the hook wrapper; left untouched",
                 g_env_hooks[index].name);
        return 0;
    }
    if (!adh_swap_pointer_in_ro_page(saved_slot, saved_original)) {
        __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
        snprintf(error, error_size, "%s: table page could not be made writable", g_env_hooks[index].name);
        return 0;
    }
    pthread_mutex_lock(&g_env_hook_lock);
    g_env_hooks[index].installed = 0;
    __atomic_store_n(&g_env_hooks[index].override_active, 0, __ATOMIC_RELEASE);   // a removed hook must not keep rewriting writes
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

// Patch one slot. The JNIEnv table lives in libart's RELRO segment, so the swap goes through
// adh_swap_pointer_in_ro_page() and the ABI guard below refuses to touch a drifted offset.
#define ADH_CALL_GUARD_CASES(name, ret, tgt, kind, base, spec) \
    case base: return spec; \
    case base + 1: return spec + 1; \
    case base + 2: return spec + 2;
#define ADH_CALL_VOID_GUARD_CASES(name, tgt, kind, base, spec) ADH_CALL_GUARD_CASES(name, void, tgt, kind, base, spec)

static int env_hook_spec_index(int index) {
    switch (index) {
        // field accessors (v4.55): indices verified against jni.h by tools/verify_v90_jni_table_abi.sh
        case ENV_SLOT_GetObjectField: return 95;
        case ENV_SLOT_GetBooleanField: return 96;
        case ENV_SLOT_GetByteField: return 97;
        case ENV_SLOT_GetCharField: return 98;
        case ENV_SLOT_GetShortField: return 99;
        case ENV_SLOT_GetIntField: return 100;
        case ENV_SLOT_GetLongField: return 101;
        case ENV_SLOT_GetFloatField: return 102;
        case ENV_SLOT_GetDoubleField: return 103;
        case ENV_SLOT_SetObjectField: return 104;
        case ENV_SLOT_SetBooleanField: return 105;
        case ENV_SLOT_SetByteField: return 106;
        case ENV_SLOT_SetCharField: return 107;
        case ENV_SLOT_SetShortField: return 108;
        case ENV_SLOT_SetIntField: return 109;
        case ENV_SLOT_SetLongField: return 110;
        case ENV_SLOT_SetFloatField: return 111;
        case ENV_SLOT_SetDoubleField: return 112;
        case ENV_SLOT_GetStaticObjectField: return 145;
        case ENV_SLOT_GetStaticBooleanField: return 146;
        case ENV_SLOT_GetStaticByteField: return 147;
        case ENV_SLOT_GetStaticCharField: return 148;
        case ENV_SLOT_GetStaticShortField: return 149;
        case ENV_SLOT_GetStaticIntField: return 150;
        case ENV_SLOT_GetStaticLongField: return 151;
        case ENV_SLOT_GetStaticFloatField: return 152;
        case ENV_SLOT_GetStaticDoubleField: return 153;
        case ENV_SLOT_SetStaticObjectField: return 154;
        case ENV_SLOT_SetStaticBooleanField: return 155;
        case ENV_SLOT_SetStaticByteField: return 156;
        case ENV_SLOT_SetStaticCharField: return 157;
        case ENV_SLOT_SetStaticShortField: return 158;
        case ENV_SLOT_SetStaticIntField: return 159;
        case ENV_SLOT_SetStaticLongField: return 160;
        case ENV_SLOT_SetStaticFloatField: return 161;
        case ENV_SLOT_SetStaticDoubleField: return 162;
        case ENV_SLOT_FindClass: return 6;
        case ENV_SLOT_GetMethodID: return 33;
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_GUARD_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_GUARD_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_GUARD_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_GUARD_CASES)
        case ENV_SLOT_GetFieldID: return 94;
        case ENV_SLOT_GetStaticMethodID: return 113;
        case ENV_SLOT_GetStaticFieldID: return 144;
        case ENV_SLOT_NewStringUTF: return 167;
        case ENV_SLOT_GetStringUTFChars: return 169;
        case ENV_SLOT_GetByteArrayElements: return 184;
        case ENV_SLOT_ReleaseByteArrayElements: return 192;
        // v4.72: the rest of the elements family.
        case ENV_SLOT_GetBooleanArrayElements: return 183;
        case ENV_SLOT_ReleaseBooleanArrayElements: return 191;
        case ENV_SLOT_GetCharArrayElements: return 185;
        case ENV_SLOT_ReleaseCharArrayElements: return 193;
        case ENV_SLOT_GetShortArrayElements: return 186;
        case ENV_SLOT_ReleaseShortArrayElements: return 194;
        case ENV_SLOT_GetIntArrayElements: return 187;
        case ENV_SLOT_ReleaseIntArrayElements: return 195;
        case ENV_SLOT_GetLongArrayElements: return 188;
        case ENV_SLOT_ReleaseLongArrayElements: return 196;
        case ENV_SLOT_GetFloatArrayElements: return 189;
        case ENV_SLOT_ReleaseFloatArrayElements: return 197;
        case ENV_SLOT_GetDoubleArrayElements: return 190;
        case ENV_SLOT_ReleaseDoubleArrayElements: return 198;
        // v4.75: creation / length / object arrays / AllocObject.
        case ENV_SLOT_AllocObject: return 27;
        case ENV_SLOT_GetArrayLength: return 171;
        case ENV_SLOT_NewObjectArray: return 172;
        case ENV_SLOT_GetObjectArrayElement: return 173;
        case ENV_SLOT_SetObjectArrayElement: return 174;
        case ENV_SLOT_NewBooleanArray: return 175;
        case ENV_SLOT_NewByteArray: return 176;
        case ENV_SLOT_NewCharArray: return 177;
        case ENV_SLOT_NewShortArray: return 178;
        case ENV_SLOT_NewIntArray: return 179;
        case ENV_SLOT_NewLongArray: return 180;
        case ENV_SLOT_NewFloatArray: return 181;
        case ENV_SLOT_NewDoubleArray: return 182;
        case ENV_SLOT_GetByteArrayRegion: return 200;
        case ENV_SLOT_SetByteArrayRegion: return 208;
        case ENV_SLOT_GetPrimitiveArrayCritical: return 222;
        case ENV_SLOT_GetStringRegion: return 220;
        case ENV_SLOT_GetBooleanArrayRegion: return 199;
        case ENV_SLOT_SetBooleanArrayRegion: return 207;
        case ENV_SLOT_GetCharArrayRegion: return 201;
        case ENV_SLOT_SetCharArrayRegion: return 209;
        case ENV_SLOT_GetShortArrayRegion: return 202;
        case ENV_SLOT_SetShortArrayRegion: return 210;
        case ENV_SLOT_GetIntArrayRegion: return 203;
        case ENV_SLOT_SetIntArrayRegion: return 211;
        case ENV_SLOT_GetLongArrayRegion: return 204;
        case ENV_SLOT_SetLongArrayRegion: return 212;
        case ENV_SLOT_GetFloatArrayRegion: return 205;
        case ENV_SLOT_SetFloatArrayRegion: return 213;
        case ENV_SLOT_GetDoubleArrayRegion: return 206;
        case ENV_SLOT_SetDoubleArrayRegion: return 214;
        case ENV_SLOT_GetVersion: return 4;
        case ENV_SLOT_DefineClass: return 5;
        case ENV_SLOT_GetSuperclass: return 10;
        case ENV_SLOT_IsAssignableFrom: return 11;
        case ENV_SLOT_GetObjectClass: return 31;
        case ENV_SLOT_IsInstanceOf: return 32;
        case ENV_SLOT_MonitorEnter: return 217;
        case ENV_SLOT_MonitorExit: return 218;
        case ENV_SLOT_NewWeakGlobalRef: return 226;
        case ENV_SLOT_DeleteWeakGlobalRef: return 227;
        case ENV_SLOT_GetObjectRefType: return 232;
        case ENV_SLOT_PushLocalFrame: return 19;
        case ENV_SLOT_PopLocalFrame: return 20;
        case ENV_SLOT_NewLocalRef: return 25;
        case ENV_SLOT_DeleteLocalRef: return 23;
        case ENV_SLOT_NewGlobalRef: return 21;
        case ENV_SLOT_DeleteGlobalRef: return 22;
        case ENV_SLOT_IsSameObject: return 24;
        case ENV_SLOT_EnsureLocalCapacity: return 26;
        case ENV_SLOT_Throw: return 13;
        case ENV_SLOT_ThrowNew: return 14;
        case ENV_SLOT_ExceptionOccurred: return 15;
        case ENV_SLOT_ExceptionDescribe: return 16;
        case ENV_SLOT_ExceptionClear: return 17;
        case ENV_SLOT_GetJavaVM: return 219;
        case ENV_SLOT_GetStringChars: return 165;
        case ENV_SLOT_ReleaseStringChars: return 166;
        // v4.77: the rest of the string family.
        case ENV_SLOT_NewString: return 163;
        case ENV_SLOT_GetStringLength: return 164;
        case ENV_SLOT_GetStringUTFLength: return 168;
        case ENV_SLOT_ReleaseStringUTFChars: return 170;
        case ENV_SLOT_GetStringCritical: return 224;
        case ENV_SLOT_ReleaseStringCritical: return 225;
        // v4.78: reflection bridge + UnregisterNatives.
        case ENV_SLOT_FromReflectedMethod: return 7;
        case ENV_SLOT_FromReflectedField: return 8;
        case ENV_SLOT_ToReflectedMethod: return 9;
        case ENV_SLOT_ToReflectedField: return 12;
        case ENV_SLOT_UnregisterNatives: return 216;
        // v4.79: the last two.
        case ENV_SLOT_FatalError: return 18;
        case ENV_SLOT_ExceptionCheck: return 228;
        case ENV_SLOT_GetStringUTFRegion: return 221;
        case ENV_SLOT_NewDirectByteBuffer: return 229;
        case ENV_SLOT_GetDirectBufferAddress: return 230;
        case ENV_SLOT_GetDirectBufferCapacity: return 231;
        case ENV_SLOT_ReleasePrimitiveArrayCritical: return 223;
        default: return -1;
    }
}


static int env_hook_install_index(int index, int override_active, long long override_i, double override_d,
                                  char *error, size_t error_size) {
    // Validate the override BEFORE touching the table: it only makes sense for one Set*Field slot.
    if (override_active) {
        const char *name = g_env_hooks[index].name;
        int is_set_field = strncmp(name, "Set", 3) == 0 && strstr(name, "Field") != NULL;
        if (!is_set_field) {
            snprintf(error, error_size, "setValue applies to a Set<Type>Field slot, not %s", name);
            return 0;
        }
        if (strstr(name, "Object") != NULL) {
            snprintf(error, error_size, "setValue cannot override %s: an object value would need a reference the agent does not hold", name);
            return 0;
        }
        // Range-check against the TARGET type: silently writing (jboolean)300 == 0 would be exactly
        // the kind of "it said ok but the field did not get what I asked for" this tool must not do.
        const char *type = (strncmp(name, "SetStatic", 9) == 0) ? name + 9
                         : (strncmp(name, "Set", 3) == 0) ? name + 3 : NULL;
        int in_range = 0;
        const char *range = "";
        if (type && strcmp(type, "BooleanField") == 0) { in_range = (override_i == 0 || override_i == 1); range = "0 or 1"; }
        else if (type && strcmp(type, "ByteField") == 0) { in_range = (override_i >= -128 && override_i <= 127); range = "-128..127"; }
        else if (type && strcmp(type, "CharField") == 0) { in_range = (override_i >= 0 && override_i <= 65535); range = "0..65535"; }
        else if (type && strcmp(type, "ShortField") == 0) { in_range = (override_i >= -32768 && override_i <= 32767); range = "-32768..32767"; }
        else if (type && strcmp(type, "IntField") == 0) { in_range = (override_i >= INT_MIN && override_i <= INT_MAX); range = "the int range"; }
        else if (type && strcmp(type, "LongField") == 0) { in_range = 1; }
        else if (type && (strcmp(type, "FloatField") == 0 || strcmp(type, "DoubleField") == 0)) { in_range = isfinite(override_d) ? 1 : 0; range = "a finite number"; }
        else { in_range = 0; range = "(unknown field type)"; }
        if (!in_range) {
            snprintf(error, error_size, "setValue for %s must be %s (got %lld / %g)", name, range, override_i, override_d);
            return 0;
        }
    }
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        snprintf(error, error_size, "no JavaVM/JNIEnv");
        return 0;
    }
    struct JNINativeInterface *table = (struct JNINativeInterface *)(*env);
    adh_jni_detach(did_attach);
    if (!table) {
        snprintf(error, error_size, "JNIEnv function table unavailable");
        return 0;
    }
    g_env_hook_table = (unsigned long long)(uintptr_t)table;
    void **slot = env_hook_slot(table, index);
    if (!slot) {
        snprintf(error, error_size, "%s: table entry unavailable", g_env_hooks[index].name);
        return 0;
    }
    // A slot whose wrapper is missing must never be installed: adh_swap_pointer_in_ro_page()
    // accepts a NULL replacement, and a NULL in ART's JNIEnv table is a jump through NULL on the
    // target's next call to that entry - a crash, not a fail-loud refusal.
    void *wrapper = env_hook_wrapper(index);
    if (!wrapper) {
        snprintf(error, error_size, "%s: no wrapper for this slot - refusing to patch", g_env_hooks[index].name);
        return 0;
    }
    int spec = env_hook_spec_index(index);
    unsigned long long slot_offset = (unsigned long long)((char *)slot - (char *)table);
    if (spec < 0 || slot_offset != (unsigned long long)spec * sizeof(void *)) {
        snprintf(error, error_size, "%s: JNIEnv table layout mismatch (offset %llu, spec %d) - refusing to patch",
                 g_env_hooks[index].name, slot_offset, spec);
        LOGE("jni_env_hook: %s", error);
        return 0;
    }

    pthread_mutex_lock(&g_env_hook_lock);
    if (g_env_hooks[index].installed && g_env_hooks[index].slot == slot) {
        // Same entry: re-activate the existing hook instead of patching twice - but only while the
        // entry still points at OUR wrapper. If something else replaced it, flipping the flag would
        // make the reply claim a hook that is no longer in the table.
        if (__atomic_load_n(slot, __ATOMIC_ACQUIRE) != wrapper) {
            pthread_mutex_unlock(&g_env_hook_lock);
            snprintf(error, error_size, "%s: table entry no longer points at the hook wrapper; refusing to re-activate",
                     g_env_hooks[index].name);
            return 0;
        }
        g_env_hooks[index].hits = 0;
        g_env_hooks[index].dropped = 0;
        g_env_hooks[index].override_i = override_i;
        g_env_hooks[index].override_d = override_d;
        // Release AFTER the values so a wrapper that sees the flag with an acquire load also sees them.
        __atomic_store_n(&g_env_hooks[index].override_active, override_active ? 1 : 0, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_env_hook_lock);
        __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (g_env_hooks[index].installed) {
        pthread_mutex_unlock(&g_env_hook_lock);
        snprintf(error, error_size, "%s is already hooked at a different table entry", g_env_hooks[index].name);
        return 0;
    }
    pthread_mutex_unlock(&g_env_hook_lock);

    void *original = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (!original) {
        snprintf(error, error_size, "%s: table entry is null", g_env_hooks[index].name);
        return 0;
    }
    if (original == wrapper) {
        snprintf(error, error_size, "%s: entry already points at the hook wrapper", g_env_hooks[index].name);
        return 0;
    }
    // Publish the real entry before the swap: a call that lands in the wrapper during the
    // swap window then still reaches the original implementation.
    __atomic_store_n(&g_env_hooks[index].original, original, __ATOMIC_RELEASE);
    if (!adh_swap_pointer_in_ro_page(slot, wrapper)) {
        __atomic_store_n(&g_env_hooks[index].original, NULL, __ATOMIC_RELEASE);
        snprintf(error, error_size, "%s: table page could not be made writable", g_env_hooks[index].name);
        return 0;
    }
    __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
    pthread_mutex_lock(&g_env_hook_lock);
    g_env_hooks[index].slot = slot;
    g_env_hooks[index].installed = 1;
    g_env_hooks[index].override_i = override_i;
    g_env_hooks[index].override_d = override_d;
    __atomic_store_n(&g_env_hooks[index].override_active, override_active ? 1 : 0, __ATOMIC_RELEASE);
    g_env_hooks[index].hits = 0;
    g_env_hooks[index].dropped = 0;
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function,
                          int override_active, long long override_i, double override_d) {
    if (!action || !action[0]) {
        send_env_result(fd, id, action, function, 0, 0, 0,
                        "jni_env_hook requires action: install | uninstall | status");
        return;
    }
    if (strcmp(action, "status") == 0) {
        int did_attach = 0;
        JNIEnv *env = adh_jni_attach(&did_attach);
        if (!env) {
            send_env_result(fd, id, action, function, 0, 0, 0, "no JavaVM/JNIEnv");
            return;
        }
        g_env_hook_table = (unsigned long long)(uintptr_t)(*env);
        adh_jni_detach(did_attach);
        struct EnvNameFilter status_filter;
        env_filter_parse(function, &status_filter);
        send_env_status(fd, id, function, &status_filter);
        return;
    }
    if (strcmp(action, "install") != 0 && strcmp(action, "uninstall") != 0) {
        send_env_result(fd, id, action, function, 0, 0, 0, "action must be install|uninstall|status");
        return;
    }
    // Never patch a table whose enum/name layout does not line up: the patch would land on the
    // neighbouring entry while the reply still named the requested one.
    {
        char layout_error[224];
        if (!env_hook_layout_ready(layout_error, sizeof(layout_error))) {
            send_env_result(fd, id, action, function, 0, 0, 0, layout_error);
            return;
        }
    }
    if (!function || !function[0]) {
        send_env_result(fd, id, action, function, 0, 0, 0, "jni_env_hook requires function");
        return;
    }

    // Wildcards so dozens of table entries stay operable in one call:
    //   "*" / "all"   every slot
    //   "Call*"       prefix   (all three forms of a Call family)
    //   "*Field"      suffix   (the 36 field accessors in one call)
    //   "*Field*"     contains (the field ID lookups AND the accessors - what the field digest needs)
    // Reports how many were applied and the first failure, never a silent skip.
    struct EnvNameFilter filter;
    env_filter_parse(function, &filter);
    int wildcard = filter.wildcard;
    if (filter.installed_only) {
        send_env_result(fd, id, action, function, 0, 0, 0,
                        "\"installed\" is a status filter; install/uninstall need a slot name or pattern");
        return;
    }

    if (override_active && wildcard) {
        send_env_result(fd, id, action, function, 0, 0, 0, "setValue needs a single Set<Type>Field slot (no wildcard pattern)");
        return;
    }
    int applying = strcmp(action, "install") == 0;
    int applied = 0, failed = 0, matched = 0;
    char first_error[320] = "";
    if (!wildcard) {
        int index = env_hook_index(function);
        if (index < 0) {
            send_env_result(fd, id, action, function, 0, 0, 0, "unsupported JNIEnv function");
            return;
        }
        matched = 1;
        char error[320] = "";
        int ok = applying ? env_hook_install_index(index, override_active, override_i, override_d, error, sizeof(error))
                          : env_hook_uninstall_index(index, error, sizeof(error));
        if (ok) applied = 1; else { failed = 1; snprintf(first_error, sizeof(first_error), "%s", error); }
    } else {
        for (int i = 0; i < ENV_HOOK_MAX; i++) {
            const char *n = g_env_hooks[i].name;
            if (!env_filter_match(&filter, n)) continue;
            matched++;
            char error[320] = "";
            int ok = applying ? env_hook_install_index(i, 0, 0, 0, error, sizeof(error))
                              : env_hook_uninstall_index(i, error, sizeof(error));
            if (ok) applied++;
            else {
                failed++;
                if (!first_error[0]) snprintf(first_error, sizeof(first_error), "%s", error);
            }
        }
        if (matched == 0) {
            send_env_result(fd, id, action, function, 0, 0, 0, "no JNIEnv function matches that pattern");
            return;
        }
    }
    send_env_result(fd, id, action, function, (failed == 0) ? 1 : 0, applied, failed, first_error);
}
// Runtime capture policy, wrappers, bounded buffers, and focused probe commands.

#include "capture.h"
#include "capture_methods.h"
#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "../runtime/jni.h"

#include "../runtime/jni_env_hooks.h"
#include "../hook/java_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>

// ---- crypto plaintext capture (thread-safe; wrapper runs on the app's crypto thread) ----
// v2.0 WS-C: bounded ring buffer with HONEST accounting. The old fixed g_caps[64] silently
// dropped everything past 64 records — forensic completeness collapsed under load. The
// producer path (capture(), on the target's own crypto/TLS thread) is NON-BLOCKING: it never
// sleeps and never waits on the lock (pthread_mutex_trylock) — a full ring or a busy lock
// just increments g_cap_dropped. Nothing vanishes silently: g_cap_seq counts every capture()
// attempt (atomic), so the invariant
//   g_cap_seq == (records ever drained) + (records still in ring) + g_cap_dropped
// always holds, and adhd surfaces dropped>0 as complete:false.
#define CAP_BYTES 16384
#define CAP_RING  128           // 128 * 16 KiB = 2 MiB; one record fits a TLS plaintext write.
                                // The sender drains while the producer stays non-blocking.
// Symmetric key/IV ride along with the plaintext record they belong to. The key exists only at
// EVP_CipherInit_ex; the payload exists only at EVP_CipherUpdate. The two are joined by
// key_store()/key_lookup() below — without that a native AES capture carries the plaintext and no
// key at all (measured on a real target: the AES plaintext was captured while crypto_identify
// reported "0 algorithms with a key", because the only key-carrying path was the Java reporter
// that a real app does not install).
#define CAP_KEY 64
#define CAP_IV  32
struct CapRec {
    char func[24]; int inl; int n; int tid; long long ts_ns;
    unsigned long long conn;   // SSL* for SSL_read/SSL_write; 0 for every other capture
    char path[240];            // absolute path for open/read/write; empty otherwise
    int nkey; int niv; unsigned char key[CAP_KEY]; unsigned char iv[CAP_IV];
    unsigned char data[CAP_BYTES];
};
#define JCAP_MAX 1024
#define JCAP_KEY 64
#define JCAP_IV 32
#define JCAP_DATA 1024
#define JCAP_ORIGIN 256
#define JCAP_RECORD_RESERVE 9000
#if (2 * (2 * JCAP_DATA + JCAP_KEY + JCAP_IV) + 6 * JCAP_ORIGIN + 1024) > JCAP_RECORD_RESERVE
#error "Java record serializer reserve must cover all bounded fields"
#endif
struct JCapRec {
    char algo[56], op[16]; int tid; long long ts_ns;
    int nkey, niv, nin, nout;
    int key_total, iv_total, in_total, out_total;
    int origin_hook_id, origin_truncated, input_known, input_present;
    char origin[JCAP_ORIGIN];
    unsigned char key[JCAP_KEY], iv[JCAP_IV], in[JCAP_DATA], out[JCAP_DATA];
};
static struct JCapRec g_jcaps[JCAP_MAX];
static int g_jcap_head = 0, g_jcap_tail = 0, g_njcaps = 0;
static unsigned long long g_jcap_dropped = 0;   // WS-C: honest drop accounting (Java rich path)
static volatile int g_java_active = 0;
static struct CapRec g_ring[CAP_RING];
static int g_ring_head = 0, g_ring_tail = 0, g_ring_count = 0;   // ring: head=write, tail=read (under g_cap_lock)
static unsigned long long g_cap_seq = 0;       // total capture() attempts — ATOMIC (read/written off-lock)
// Records the drain has POPPED out of the ring, cumulative. Reported so the identity
//   seq == drained + backlog + dropped
// can be checked from the agent's own accounting: without it, a daemon that loses a drain
// response (the records are already popped, the bytes die with the socket) is indistinguishable
// from the agent silently dropping records - and verify_v22 cannot tell which one it is.
static unsigned long long g_cap_drained = 0;
static unsigned long long g_cap_dropped = 0;   // total dropped (ring full or lock busy) — ATOMIC
// Records the sender has popped into its in-flight batch but has not yet put on the wire.
// They are no longer in the ring, so backlog accounting must include this queue.
static unsigned long long g_cap_queued = 0;    // sender in-flight native records — ATOMIC
static unsigned long long g_jcap_queued = 0;   // sender in-flight Java records — ATOMIC
static unsigned long long g_cap_queued_seq = 0; // frame id of the one in-flight sender batch
// Monotonic per-pop frame id under g_cap_lock. A push batch serializes off-lock, so a later
// compatibility drain can legitimately reach the host first; the host uses this to ignore
// stale health snapshots while still ingesting that batch's records.
static unsigned long long g_cap_frame_seq = 0;
static long long g_cap_first_drop_ns = 0, g_cap_last_drop_ns = 0;   // best-effort diagnostic ts
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cap_cond = PTHREAD_COND_INITIALIZER;
static void capture_keyed(const char *func, const unsigned char *in, int inl,
                          const unsigned char *key, int nkey, const unsigned char *iv, int niv,
                          unsigned long long conn, const char *path) {
    if (inl <= 0 || !in) return;
    // Runs on the target's own crypto/TLS thread — must NEVER block or sleep here (any
    // injected latency is an ANR risk and a timing-based anti-debug surface). Count every
    // attempt atomically, then TRY the lock without waiting: if a sender batch or another
    // producer holds it, account a drop and return immediately instead of stalling the target.
    __atomic_add_fetch(&g_cap_seq, 1, __ATOMIC_RELAXED);
    long long ts = now_ns();
    if (pthread_mutex_trylock(&g_cap_lock) != 0) {
        __atomic_add_fetch(&g_cap_dropped, 1, __ATOMIC_RELAXED);
        if (!g_cap_first_drop_ns) g_cap_first_drop_ns = ts;   // best-effort diagnostic ts
        g_cap_last_drop_ns = ts;
        return;
    }
    if (g_ring_count < CAP_RING) {
        struct CapRec *r = &g_ring[g_ring_head];
        strncpy(r->func, func, sizeof(r->func) - 1); r->func[sizeof(r->func)-1]=0;
        r->inl = inl; r->n = inl < CAP_BYTES ? inl : CAP_BYTES;
        r->tid = (int)gettid(); r->ts_ns = ts; r->conn = conn;
        r->path[0] = 0;
        if (path && path[0]) {
            snprintf(r->path, sizeof(r->path), "%s", path);
            for (char *s = r->path; *s; s++) if (*s == '\t' || *s == '\n' || *s == '\r') *s = ' ';
        }
        r->nkey = 0; r->niv = 0;
        if (key && nkey > 0) { r->nkey = nkey < CAP_KEY ? nkey : CAP_KEY; memcpy(r->key, key, r->nkey); }
        if (iv && niv > 0)   { r->niv  = niv  < CAP_IV  ? niv  : CAP_IV;  memcpy(r->iv,  iv,  r->niv); }
        memcpy(r->data, in, r->n);
        g_ring_head = (g_ring_head + 1) % CAP_RING;
        g_ring_count++;
        if (g_ring_count == 1) pthread_cond_signal(&g_cap_cond);
    } else {
        __atomic_add_fetch(&g_cap_dropped, 1, __ATOMIC_RELAXED);
        if (!g_cap_first_drop_ns) g_cap_first_drop_ns = ts;
        g_cap_last_drop_ns = ts;
    }
    pthread_mutex_unlock(&g_cap_lock);
}

// Keyless form — every pre-existing caller (digest/TLS/file/sys wrappers, push_text) keeps using it.
static void capture(const char *func, const unsigned char *in, int inl) {
    capture_keyed(func, in, inl, NULL, 0, NULL, 0, 0, NULL);
}
// TLS records carry the SSL* so the host can concatenate one connection's plaintext.
// The pointer is the same value Conscrypt passes into SSL_read / SSL_write (socket and
// SSLEngine direct paths both end there). It is not a stable id across process restart.
static void capture_conn(const char *func, const unsigned char *in, int inl, const void *ssl) {
    capture_keyed(func, in, inl, NULL, 0, NULL, 0, (unsigned long long)(uintptr_t)ssl, NULL);
}

// Empty the ring (used by the one-shot probes in place of the old `g_ncaps = 0`). Discarded
// in-ring records are rolled into g_cap_dropped (see below); cumulative seq is never touched.
void adh_capture_push_text(const char *func, const char *text) {
    if (!func || !text) return;
    capture(func, (const unsigned char *)text, (int)strlen(text));
}
static void cap_reset(void) {
    pthread_mutex_lock(&g_cap_lock);
    // Records still in the ring are being discarded (a one-shot probe / capture_stop clears
    // stale captures before re-arming). They were counted in g_cap_seq but will never be
    // emitted — account them as dropped so the invariant emitted+backlog+dropped==seq holds
    // (WS-C: nothing vanishes silently). Without this, each reset-with-backlog leaks the
    // in-ring count from the accounting permanently (verify_v22 caught a stable off-by-N).
    if (g_ring_count > 0) __atomic_add_fetch(&g_cap_dropped, (unsigned long long)g_ring_count, __ATOMIC_RELAXED);
    if (g_njcaps > 0) __atomic_add_fetch(&g_jcap_dropped, (unsigned long long)g_njcaps, __ATOMIC_RELAXED);
    g_ring_head = g_ring_tail = g_ring_count = 0;
    g_jcap_head = g_jcap_tail = g_njcaps = 0;
    pthread_mutex_unlock(&g_cap_lock);
}
// Append hex without one snprintf per byte. TLS records are up to 16 KiB, so the old
// per-byte snprintf loop dominated drain time and kept the producer-visible lock/window hot.
static size_t emit_hex(char *out, size_t len, size_t cap, const unsigned char *data, int n) {
    static const char h[] = "0123456789abcdef";
    for (int b = 0; b < n && len + 2 <= cap; b++) {
        out[len++] = h[(data[b] >> 4) & 15];
        out[len++] = h[data[b] & 15];
    }
    return len;
}
// Emit one record as a JSON object into (out,len,cap); returns new len. Underflow-safe
// (cap>len?cap-len:0 guards snprintf's would-be-length return that the old loops mishandled).
static size_t emit_caprec(char *out, size_t len, size_t cap, const struct CapRec *r, int first) {
    len += snprintf(out + len, cap > len ? cap - len : 0,
        "%s{\"func\":\"%s\",\"inl\":%d,\"tid\":%d,\"tsNs\":%lld,\"hex\":\"", first ? "" : ",", r->func, r->inl, r->tid, r->ts_ns);
    len = emit_hex(out, len, cap, r->data, r->n);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\"");
    // key/iv are optional and only present for symmetric records whose key was seen at init.
    if (r->nkey > 0) {
        len += snprintf(out + len, cap > len ? cap - len : 0, ",\"key\":\"");
        len = emit_hex(out, len, cap, r->key, r->nkey);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\"");
    }
    if (r->niv > 0) {
        len += snprintf(out + len, cap > len ? cap - len : 0, ",\"iv\":\"");
        len = emit_hex(out, len, cap, r->iv, r->niv);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\"");
    }
    if (r->conn)
        len += snprintf(out + len, cap > len ? cap - len : 0, ",\"conn\":\"0x%llx\"", r->conn);
    if (r->path[0]) {
        char esc[480];
        json_escape(r->path, esc, sizeof(esc));
        len += snprintf(out + len, cap > len ? cap - len : 0, ",\"path\":\"%s\"", esc);
    }
    len += snprintf(out + len, cap > len ? cap - len : 0, "}");
    return len;
}
static size_t emit_jcaprec(char *out, size_t len, size_t cap, const struct JCapRec *r, int first) {
    char algoj[128], opj[64], originj[JCAP_ORIGIN * 6 + 1];
    json_escape(r->algo, algoj, sizeof(algoj));
    json_escape(r->op, opj, sizeof(opj));
    json_escape(r->origin, originj, sizeof(originj));
    len += snprintf(out + len, cap > len ? cap - len : 0,
        "%s{\"recordSchema\":\"java-rich/2\",\"algo\":\"%s\",\"op\":\"%s\",\"tid\":%d,\"tsNs\":%lld", first ? "" : ",", algoj, opj, r->tid, r->ts_ns);
    if (r->input_known) len += snprintf(out + len, cap > len ? cap - len : 0,
        ",\"inputBytesPresent\":%s,\"inputScope\":\"call-argument-snapshot-after-return\"", r->input_present ? "true" : "false");
    if (r->origin[0] || r->origin_truncated) len += snprintf(out + len, cap > len ? cap - len : 0,
        ",\"javaTarget\":\"%s\",\"javaHookId\":%d,\"javaTargetTruncated\":%s", originj, r->origin_hook_id, r->origin_truncated ? "true" : "false");
    len += snprintf(out + len, cap > len ? cap - len : 0, ",\"key\":\"");
    len = emit_hex(out, len, cap, r->key, r->nkey);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"iv\":\"");
    len = emit_hex(out, len, cap, r->iv, r->niv);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"in\":\"");
    len = emit_hex(out, len, cap, r->in, r->nin);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"out\":\"");
    len = emit_hex(out, len, cap, r->out, r->nout);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"inl\":%d,\"outl\":%d,\"keyl\":%d,\"ivl\":%d}", r->in_total, r->out_total, r->key_total, r->iv_total);
    return len;
}
// ---- symmetric key/IV join -------------------------------------------------------------------
// Conscrypt calls EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc) once per Cipher.init(), then
// EVP_CipherUpdate(ctx, …) per doFinal(); the key exists only in the first call. This table joins
// the two by ctx pointer so the plaintext record carries its key. Lengths come from libcrypto's
// own accessors and NEVER from EVP_CIPHER_CTX struct layout (same reason as the EVP_MD_CTX note
// above, plus: reading past the real key would be a memory-safety bug inside the target), so an
// unresolved accessor stores nothing rather than something wrong.
#define KEY_SLOTS 64
struct KeySlot { void *ctx; int nkey; int niv; unsigned char key[CAP_KEY]; unsigned char iv[CAP_IV]; };
struct KeyBlob { int nkey; int niv; unsigned char key[CAP_KEY]; unsigned char iv[CAP_IV]; };
static struct KeySlot g_keys[KEY_SLOTS];
static int g_key_next = 0;                                     // round-robin eviction once full
static pthread_mutex_t g_key_lock = PTHREAD_MUTEX_INITIALIZER;
typedef int (*cipher_ctx_len_t)(const void *);
static cipher_ctx_len_t g_cipher_key_len = NULL, g_cipher_iv_len = NULL;

// find-or-claim one slot; caller holds g_key_lock.
static struct KeySlot *key_slot(void *ctx, int create) {
    struct KeySlot *spare = NULL;
    for (int i = 0; i < KEY_SLOTS; i++) {
        if (g_keys[i].ctx == ctx) return &g_keys[i];
        if (!g_keys[i].ctx && !spare) spare = &g_keys[i];
    }
    if (!create) return NULL;
    if (spare) return spare;
    struct KeySlot *victim = &g_keys[g_key_next];
    g_key_next = (g_key_next + 1) % KEY_SLOTS;
    return victim;
}

static void key_store(void *ctx, const unsigned char *key, int klen, const unsigned char *iv, int vlen) {
    if (!ctx || (!key && !iv)) return;
    if (klen > CAP_KEY) klen = CAP_KEY;
    if (vlen > CAP_IV)  vlen = CAP_IV;
    if (klen <= 0 && vlen <= 0) return;
    // Never wait for the lock: this runs on the target's own crypto thread (same rule as capture()).
    if (pthread_mutex_trylock(&g_key_lock) != 0) return;
    struct KeySlot *s = key_slot(ctx, 1);
    s->ctx = ctx; s->nkey = klen; s->niv = vlen;
    if (klen > 0) memcpy(s->key, key, klen);
    if (vlen > 0) memcpy(s->iv, iv, vlen);
    pthread_mutex_unlock(&g_key_lock);
}

static int key_lookup(void *ctx, struct KeyBlob *out) {
    if (!ctx) return 0;
    if (pthread_mutex_trylock(&g_key_lock) != 0) return 0;
    struct KeySlot *s = key_slot(ctx, 0);
    int hit = 0;
    if (s && (s->nkey > 0 || s->niv > 0)) {
        out->nkey = s->nkey; out->niv = s->niv;
        memcpy(out->key, s->key, CAP_KEY); memcpy(out->iv, s->iv, CAP_IV);
        hit = 1;
    }
    pthread_mutex_unlock(&g_key_lock);
    return hit;
}

static void key_forget(void *ctx) {
    if (!ctx) return;
    if (pthread_mutex_trylock(&g_key_lock) != 0) return;
    struct KeySlot *s = key_slot(ctx, 0);
    if (s) { s->ctx = NULL; s->nkey = 0; s->niv = 0; }
    pthread_mutex_unlock(&g_key_lock);
}

typedef int (*EVP_CipherUpdate_t)(void *, unsigned char *, int *, const unsigned char *, int);
static EVP_CipherUpdate_t g_evp_cipher_orig = NULL;
// The key was seen at init, the payload is here: emit them on ONE record.
static int my_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    struct KeyBlob blob;
    if (key_lookup(ctx, &blob)) capture_keyed("EVP_CipherUpdate", in, inl, blob.key, blob.nkey, blob.iv, blob.niv, 0, NULL);
    else capture("EVP_CipherUpdate", in, inl);
    return g_evp_cipher_orig(ctx, out, outl, in, inl);
}

typedef int (*EVP_CipherInit_ex_t)(void *, const void *, void *, const unsigned char *, const unsigned char *, int);
static EVP_CipherInit_ex_t g_evp_cipher_init_orig = NULL;
// key != NULL is the call that installs the key material (Conscrypt calls this twice: once with the
// cipher only, then again with key/iv). key == NULL with iv != NULL re-seeds the IV and keeps the key.
static int my_EVP_CipherInit_ex(void *ctx, const void *type, void *impl,
                                const unsigned char *key, const unsigned char *iv, int enc) {
    int rc = g_evp_cipher_init_orig(ctx, type, impl, key, iv, enc);
    if (rc == 1 && ctx) {
        int klen = (key && g_cipher_key_len) ? g_cipher_key_len(ctx) : 0;
        int vlen = (iv  && g_cipher_iv_len)  ? g_cipher_iv_len(ctx)  : 0;
        if (klen < 0) klen = 0;   // an accessor returning nonsense must not become a length
        if (vlen < 0) vlen = 0;
        if (klen > 0 || vlen > 0) key_store(ctx, key, klen, iv, vlen);
    }
    return rc;
}

typedef void (*EVP_CIPHER_CTX_free_t)(void *);
static EVP_CIPHER_CTX_free_t g_evp_cipher_ctx_free_orig = NULL;
// The next Cipher can reuse the freed address, so forget the key before that can happen.
static void my_EVP_CIPHER_CTX_free(void *ctx) {
    key_forget(ctx);
    g_evp_cipher_ctx_free_orig(ctx);
}

// Digest (MD5/SHA-1/SHA-256/SHA-512 via MessageDigest) and HMAC (via Mac) both route
// through BoringSSL update functions with the same (ctx, data, len) shape — the message
// being hashed/authenticated is the forensic payload.
typedef int (*update3_t)(void *, const void *, size_t);
static update3_t g_orig_evp_digest = NULL, g_orig_hmac = NULL, g_orig_digest_sign = NULL;
static int my_EVP_DigestUpdate(void *ctx, const void *data, size_t len) {
    capture("EVP_DigestUpdate", (const unsigned char *)data, (int)len);
    return g_orig_evp_digest(ctx, data, len);
}
static int my_HMAC_Update(void *ctx, const void *data, size_t len) {
    capture("HMAC_Update", (const unsigned char *)data, (int)len);
    return g_orig_hmac(ctx, data, len);
}
// Conscrypt's SHA256withECDSA/RSA Signature.sign/verify route through BoringSSL's generic
// EVP_DigestSign*/EVP_DigestVerify* API (NOT the raw ECDSA_sign/ECDSA_verify entry points
// hooked above — confirmed via capture_drain showing only EVP_DigestSignUpdate firing for
// sigDemo() on this device). But EVP_DigestSignUpdate/Final ALSO serve the JCA Mac (HMAC)
// provider on the same BoringSSL build, so a bare Update/Final hook can't tell "HMAC message"
// apart from "data to be signed". Disambiguate at Init time via the long-exported, ABI-stable
// EVP_PKEY_id() accessor (NID of the bound key: HMAC vs RSA/EC) rather than reverse-engineering
// EVP_MD_CTX/EVP_PKEY internal struct layout, which is fragile and version-specific — see
// CLAUDE.md's broad cross-device compatibility mandate. Result is cached in a small bounded
// ctx-pointer table (same round-robin-eviction convention as CAP_RING); a lookup miss just
// falls back to the pre-existing generic HMAC label, never blocks capture().
#define ADH_NID_HMAC 855   // OpenSSL/BoringSSL NID_hmac — stable OID-registry constant, not a struct offset
#define DSIGN_CTX_MAX 32
typedef struct { void *ctx; int is_asym; } dsign_ctx_ent_t;
static dsign_ctx_ent_t g_dsign_ctx[DSIGN_CTX_MAX];
static int g_dsign_ctx_next = 0;
static pthread_mutex_t g_dsign_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static void dsign_ctx_set(void *ctx, int is_asym) {
    if (pthread_mutex_trylock(&g_dsign_ctx_lock) != 0) return;
    for (int i = 0; i < DSIGN_CTX_MAX; i++) {
        if (g_dsign_ctx[i].ctx == ctx) { g_dsign_ctx[i].is_asym = is_asym; pthread_mutex_unlock(&g_dsign_ctx_lock); return; }
    }
    g_dsign_ctx[g_dsign_ctx_next].ctx = ctx;
    g_dsign_ctx[g_dsign_ctx_next].is_asym = is_asym;
    g_dsign_ctx_next = (g_dsign_ctx_next + 1) % DSIGN_CTX_MAX;
    pthread_mutex_unlock(&g_dsign_ctx_lock);
}
static int dsign_ctx_get(void *ctx) {
    int r = 0;
    if (pthread_mutex_trylock(&g_dsign_ctx_lock) != 0) return 0;
    for (int i = 0; i < DSIGN_CTX_MAX; i++) if (g_dsign_ctx[i].ctx == ctx) { r = g_dsign_ctx[i].is_asym; break; }
    pthread_mutex_unlock(&g_dsign_ctx_lock);
    return r;
}

typedef int (*EVP_PKEY_id_t)(const void *pkey);
static EVP_PKEY_id_t g_evp_pkey_id_fn = NULL;   // resolved but never hooked — just a direct accessor call

typedef int (*digest_sign_init_t)(void *ctx, void **pctx, const void *type, void *e, void *pkey);
static digest_sign_init_t g_orig_dsign_init = NULL, g_orig_dverify_init = NULL;
static int my_EVP_DigestSignInit(void *ctx, void **pctx, const void *type, void *e, void *pkey) {
    int rc = g_orig_dsign_init(ctx, pctx, type, e, pkey);
    if (rc == 1 && pkey && g_evp_pkey_id_fn) dsign_ctx_set(ctx, g_evp_pkey_id_fn(pkey) != ADH_NID_HMAC);
    return rc;
}
static int my_EVP_DigestVerifyInit(void *ctx, void **pctx, const void *type, void *e, void *pkey) {
    int rc = g_orig_dverify_init(ctx, pctx, type, e, pkey);
    if (rc == 1 && pkey && g_evp_pkey_id_fn) dsign_ctx_set(ctx, g_evp_pkey_id_fn(pkey) != ADH_NID_HMAC);
    return rc;
}

// DigestSign imports are shared by two families; installed does not imply both may emit.
static int dsign_capture_allowed(int asymmetric);
static int my_EVP_DigestSignUpdate(void *ctx, const void *data, size_t len) {
    int asymmetric = dsign_ctx_get(ctx);
    if (dsign_capture_allowed(asymmetric)) capture(asymmetric ? "EVP_DSignUpdate_asym" : "EVP_DigestSignUpdate", (const unsigned char *)data, (int)len);
    return g_orig_digest_sign(ctx, data, len);
}

typedef int (*digest_sign_final_t)(void *ctx, unsigned char *sig, size_t *sig_len);
static digest_sign_final_t g_orig_dsign_final = NULL;
static int my_EVP_DigestSignFinal(void *ctx, unsigned char *sig, size_t *sig_len) {
    int rc = g_orig_dsign_final(ctx, sig, sig_len);
    if (rc == 1 && sig && sig_len && dsign_ctx_get(ctx) && dsign_capture_allowed(1)) capture("EVP_DSignFinal_sig", sig, (int)*sig_len);  // skip the sig==NULL length-query call
    return rc;
}

static update3_t g_orig_digest_verify = NULL;
static int my_EVP_DigestVerifyUpdate(void *ctx, const void *data, size_t len) {
    int asymmetric = dsign_ctx_get(ctx);
    if (dsign_capture_allowed(asymmetric)) capture(asymmetric ? "EVP_DVerifyUpdate_asym" : "EVP_DigestVerifyUpdate", (const unsigned char *)data, (int)len);
    return g_orig_digest_verify(ctx, data, len);
}

typedef int (*digest_verify_final_t)(void *ctx, const unsigned char *sig, size_t sig_len);
static digest_verify_final_t g_orig_dverify_final = NULL;
static int my_EVP_DigestVerifyFinal(void *ctx, const unsigned char *sig, size_t sig_len) {
    if (dsign_ctx_get(ctx) && sig && dsign_capture_allowed(1)) capture("EVP_DVerifyFinal_sig", sig, (int)sig_len);   // presented signature, captured regardless of pass/fail
    return g_orig_dverify_final(ctx, sig, sig_len);
}

// ---- Signature (RSA/ECDSA) + AEAD (GCM/ChaCha20-Poly1305) ----
// 原生 GOT hook，标准 BoringSSL 导出符号；这些是当前能跨设备工作的原生可 hook 子集。

// EVP_PKEY_sign/verify are NOT imported by the JCE provider's native library at all
// (confirmed via `llvm-readelf --dyn-syms` against the on-device Conscrypt native lib) —
// Android's
// Signature.sign/verify for both RSA and ECDSA route through the legacy one-shot
// RSA_sign/RSA_verify and ECDSA_sign/ECDSA_verify entry points instead. Hooking
// ECDSA_sign/verify here (the ones our sigDemo/SHA256withECDSA path actually calls).
typedef int (*ECDSA_sign_t)(int type, const unsigned char *digest, size_t digest_len, unsigned char *sig, unsigned int *sig_len, const void *eckey);
static ECDSA_sign_t g_ecdsa_sign_orig = NULL;
static int my_ECDSA_sign(int type, const unsigned char *digest, size_t digest_len, unsigned char *sig, unsigned int *sig_len, const void *eckey) {
    capture("ECDSA_sign_digest", digest, (int)digest_len);
    int rc = g_ecdsa_sign_orig(type, digest, digest_len, sig, sig_len, eckey);
    if (rc == 1 && sig && sig_len) capture("ECDSA_sign_sig", sig, (int)*sig_len);
    return rc;
}

typedef int (*ECDSA_verify_t)(int type, const unsigned char *digest, size_t digest_len, const unsigned char *sig, size_t sig_len, const void *eckey);
static ECDSA_verify_t g_ecdsa_verify_orig = NULL;
static int my_ECDSA_verify(int type, const unsigned char *digest, size_t digest_len, const unsigned char *sig, size_t sig_len, const void *eckey) {
    capture("ECDSA_verify_digest", digest, (int)digest_len);
    capture("ECDSA_verify_sig", sig, (int)sig_len);
    return g_ecdsa_verify_orig(type, digest, digest_len, sig, sig_len, eckey);
}

typedef int (*EVP_PKEY_crypt_t)(void *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
static EVP_PKEY_crypt_t g_pkey_encrypt_orig = NULL, g_pkey_decrypt_orig = NULL;
static int my_EVP_PKEY_encrypt(void *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
    capture("EVP_PKEY_encrypt_in", in, (int)inlen);
    int rc = g_pkey_encrypt_orig(ctx, out, outlen, in, inlen);
    if (rc == 1 && out && outlen) capture("EVP_PKEY_encrypt_out", out, (int)*outlen);
    return rc;
}
static int my_EVP_PKEY_decrypt(void *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen) {
    capture("EVP_PKEY_decrypt_in", in, (int)inlen);
    int rc = g_pkey_decrypt_orig(ctx, out, outlen, in, inlen);
    if (rc == 1 && out && outlen) capture("EVP_PKEY_decrypt_out", out, (int)*outlen);
    return rc;
}

typedef int (*aead_crypt_t)(const void *ctx, unsigned char *out, size_t *out_len, size_t max_out_len,
                             const unsigned char *nonce, size_t nonce_len, const unsigned char *in, size_t in_len,
                             const unsigned char *ad, size_t ad_len);
static aead_crypt_t g_aead_seal_orig = NULL, g_aead_open_orig = NULL;
static int my_EVP_AEAD_CTX_seal(const void *ctx, unsigned char *out, size_t *out_len, size_t max_out_len,
                                 const unsigned char *nonce, size_t nonce_len, const unsigned char *in, size_t in_len,
                                 const unsigned char *ad, size_t ad_len) {
    if (in && in_len) capture("EVP_AEAD_seal_pt", in, (int)in_len);
    int rc = g_aead_seal_orig(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    if (rc == 1 && out && out_len) capture("EVP_AEAD_seal_ct", out, (int)*out_len);
    return rc;
}
static int my_EVP_AEAD_CTX_open(const void *ctx, unsigned char *out, size_t *out_len, size_t max_out_len,
                                 const unsigned char *nonce, size_t nonce_len, const unsigned char *in, size_t in_len,
                                 const unsigned char *ad, size_t ad_len) {
    if (in && in_len) capture("EVP_AEAD_open_ct", in, (int)in_len);
    int rc = g_aead_open_orig(ctx, out, out_len, max_out_len, nonce, nonce_len, in, in_len, ad, ad_len);
    if (rc == 1 && out && out_len) capture("EVP_AEAD_open_pt", out, (int)*out_len);
    return rc;
}

// Generic GOT recon: scan every readable non-exec .so region for pointers matching the given
// resolved symbol addresses, report per-module hit counts (candidate hook sites). Shared by the
// crypto and file probes — they differ only in which symbols/libs they resolve. `opname` labels
// the reply. (Replaces two ~95%-identical copies.)
#define GOT_PROBE_MAXFN 8
static void got_probe(int fd, const char *id, const char *opname, const char *names[], void *addrs[], int NF) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    struct Mod { char name[128]; int cnt[GOT_PROBE_MAXFN]; };
    struct Mod mods[96]; int nmods = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512];
    while (m && fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6 || perms[0] != 'r' || strstr(perms, "x")) continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (!strstr(pp, ".so")) continue;
        const char *base = strrchr(pp, '/'); base = base ? base + 1 : pp;
        unsigned long long s = strtoull(sa, NULL, 16), e = strtoull(ea, NULL, 16);
        if (e <= s || e - s > (64u << 20)) continue;
        int hit[GOT_PROBE_MAXFN] = {0}, any = 0;
        for (unsigned long long a = s; a + 8 <= e; a += 8) {
            void *v = *(void **)a;
            for (int i = 0; i < NF; i++) if (addrs[i] && v == addrs[i]) { hit[i]++; any = 1; }
        }
        if (!any) continue;
        int mi = -1;
        for (int k = 0; k < nmods; k++) if (strcmp(mods[k].name, base) == 0) { mi = k; break; }
        if (mi < 0 && nmods < 96) { mi = nmods++; strncpy(mods[mi].name, base, sizeof(mods[mi].name) - 1); mods[mi].name[sizeof(mods[mi].name)-1]=0; for (int i=0;i<NF;i++) mods[mi].cnt[i]=0; }
        if (mi >= 0) for (int i = 0; i < NF; i++) mods[mi].cnt[i] += hit[i];
    }
    if (m) fclose(m);

    size_t cap = 1 << 14, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, opname); return; }
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"%s\",\"ok\":true,\"fns\":{", idj, opname);
    // 0x-prefixed like every other address the agent reports (the bare form made the device-side
    // probe check in verify_v87 read a resolved symbol as "not an address").
    for (int i = 0; i < NF; i++) len += snprintf(out + len, cap - len, "%s\"%s\":\"0x%llx\"", i?",":"", names[i], (unsigned long long)addrs[i]);
    len += snprintf(out + len, cap - len, "},\"modules\":[");
    for (int k = 0; k < nmods; k++) {
        len += snprintf(out + len, cap - len, "%s{\"name\":\"%s\"", k?",":"", mods[k].name);
        for (int i = 0; i < NF; i++) if (mods[k].cnt[i]) len += snprintf(out + len, cap - len, ",\"%s\":%d", names[i], mods[k].cnt[i]);
        len += snprintf(out + len, cap - len, "}");
    }
    snprintf(out + len, cap - len, "]}\n");
    send_line(fd, out);
    free(out);
    LOGI("%s: %d modules with GOT refs", opname, nmods);
}

// ---- network TLS-plaintext capture (SSL_read/SSL_write in the JCE provider library) ----
typedef int (*SSL_rw_t)(void *, void *, int);
static SSL_rw_t g_orig_ssl_write = NULL, g_orig_ssl_read = NULL;

// HTTP/2 connection frames that carry no request or response: SETTINGS, PING, GOAWAY,
// WINDOW_UPDATE, PRIORITY, RST_STREAM. A record is skipped only when every byte is one or
// more of these frames. HEADERS, DATA, the client preface, and anything that does not
// parse as a whole frame still get captured.
static int tls_control_only(const unsigned char *p, int n) {
    int off = 0;
    if (n < 9) return 0;
    if (n >= 24 && memcmp(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0) return 0;
    while (off + 9 <= n) {
        int len = ((int)p[off] << 16) | ((int)p[off + 1] << 8) | (int)p[off + 2];
        int type = p[off + 3];
        if (len < 0 || len > 16384 || off + 9 + len > n) return 0;
        if (type != 0x2 && type != 0x3 && type != 0x4 && type != 0x6 && type != 0x7 && type != 0x8) return 0;
        off += 9 + len;
    }
    return off == n;
}
static int my_SSL_write(void *ssl, void *buf, int num) {
    if (num > 0 && buf && !tls_control_only((const unsigned char *)buf, num))
        capture_conn("SSL_write", (const unsigned char *)buf, num, ssl);
    return g_orig_ssl_write(ssl, buf, num);
}
static int my_SSL_read(void *ssl, void *buf, int num) {
    int ret = g_orig_ssl_read(ssl, buf, num);
    if (ret > 0 && buf && !tls_control_only((const unsigned char *)buf, ret))
        capture_conn("SSL_read", (const unsigned char *)buf, ret, ssl);
    return ret;
}

// ---- file I/O capture (open/openat/read/write/close via a caller module's GOT) ----
// Which module's GOT actually holds these libc pointers for Java FileInputStream/
// FileOutputStream varies by ART/API level (libopenjdk.so on modern Android) — use
// adh_cmd_file_probe to discover it empirically rather than hardcoding a guess.
typedef int (*open_t)(const char *, int, mode_t);
typedef int (*openat_t)(int, const char *, int, mode_t);
typedef ssize_t (*rw_t)(int, void *, size_t);
static open_t g_orig_open = NULL;
static openat_t g_orig_openat = NULL;
static rw_t g_orig_read = NULL;
static rw_t g_orig_fwrite_sys = NULL;

// arm64 ABI always passes a 3rd arg in a register even when the call site omits it
// (open()/openat() only read it when O_CREAT/O_TMPFILE is set) — always read+forward it.
static void io_path(int fd, const char *fallback, char *out, size_t n) {
    char link[32];
    ssize_t got = -1;
    if (n) out[0] = 0;
    if (fd >= 0) {
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        got = readlink(link, out, n - 1);
    }
    if (got > 0) { out[got] = 0; return; }
    if (fallback && fallback[0]) snprintf(out, n, "%s", fallback);
    else if (fd >= 0) snprintf(out, n, "fd %d", fd);
}
static void capture_io(const char *func, int fd, const char *fallback, const unsigned char *bytes, int n) {
    char path[240];
    if (n <= 0 || !bytes) return;
    io_path(fd, fallback, path, sizeof(path));
    if (strncmp(path, "socket:", 7) == 0) return;
    capture_keyed(func, bytes, n, NULL, 0, NULL, 0, 0, path);
}
static int my_open(const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    int fd = g_orig_open(pathname, flags, mode);
    if (fd >= 0 && pathname) capture_io("open", fd, pathname, (const unsigned char *)pathname, (int)strlen(pathname));
    return fd;
}
static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    int fd = g_orig_openat(dirfd, pathname, flags, mode);
    if (fd >= 0 && pathname) capture_io("openat", fd, pathname, (const unsigned char *)pathname, (int)strlen(pathname));
    return fd;
}
static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret = g_orig_read(fd, buf, count);
    if (ret > 0) capture_io("read", fd, NULL, (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (count > 0) capture_io("write", fd, NULL, (const unsigned char *)buf, (int)count);
    return g_orig_fwrite_sys(fd, (void *)buf, count);
}

// libopenjdk.so imports open/openat/read/write/close (confirmed via dynsym), but Android
// libcore's IoBridge/Posix native layer (the actual path behind java.io.FileInputStream/
// FileOutputStream) issues raw syscall(2) directly instead of calling those named symbols
// — verified empirically (named hooks install cleanly but capture nothing) and statically
// (libopenjdk.so also imports "syscall"). Hook syscall() itself and decode the syscall
// number/args to catch what the named-symbol hooks above structurally cannot.
typedef long (*syscall_t)(long, long, long, long, long, long, long);
static syscall_t g_orig_syscall = NULL;
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_write
#define __NR_write 64
#endif

static long my_syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
    va_end(ap);
    long ret = g_orig_syscall(number, a1, a2, a3, a4, a5, a6);
    if (number == __NR_openat) {
        const char *path = (const char *)a2;
        if (ret >= 0 && path) capture_io("openat", (int)ret, path, (const unsigned char *)path, (int)strlen(path));
    } else if (number == __NR_write) {
        if (a3 > 0) capture_io("write", (int)a1, NULL, (const unsigned char *)a2, (int)a3);
    } else if (number == __NR_read && ret > 0) {
        capture_io("read", (int)a1, NULL, (const unsigned char *)a2, (int)ret);
    }
    return ret;
}

// The module that actually backs java.io.FileInputStream/FileOutputStream on this device
// is libjavacore.so (libcore's Linux.cpp JNI layer), NOT libopenjdk.so — confirmed via
// readelf --dyn-syms on the pulled libjavacore.so: it imports plain open/close (already
// hooked above, and "open" captures the real path when hooked here), but for read/write it
// imports bionic's FORTIFY_SOURCE-wrapped __read_chk(fd,buf,count,buflen) and
// __write_chk(fd,buf,count,buflen) (a differently-versioned symbol, LIBC_N vs read_chk's
// LIBC) instead of plain read()/write() — confirmed live: __read_chk captures real bytes,
// while plain write/writev (also imported, presumably for some other internal use) never
// fire for FileOutputStream.write().
typedef ssize_t (*read_chk_t)(int, void *, size_t, size_t);
typedef ssize_t (*write_chk_t)(int, const void *, size_t, size_t);
static read_chk_t g_orig_read_chk = NULL;
static write_chk_t g_orig_write_chk = NULL;

static ssize_t my_read_chk(int fd, void *buf, size_t count, size_t buflen) {
    ssize_t ret = g_orig_read_chk(fd, buf, count, buflen);
    if (ret > 0) capture_io("read", fd, NULL, (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write_chk(int fd, const void *buf, size_t count, size_t buflen) {
    if (count > 0) capture_io("write", fd, NULL, (const unsigned char *)buf, (int)count);
    return g_orig_write_chk(fd, buf, count, buflen);
}

// Recon: for open/openat/read/write/close (libc.so), report which loaded modules'
// GOT holds each pointer (candidate hook sites) — same recon shape as the crypto side,
// which the persistent capture path no longer needs (it scans all modules itself).
// Recon: which modules' GOT holds the libc file-I/O pointers (candidate file hook sites).
void adh_cmd_file_probe(int fd, const char *id) {
    const char *names[] = { "open", "openat", "read", "write", "close" };
    void *addrs[5];
    for (int i = 0; i < 5; i++) addrs[i] = adh_resolve_sym("libc.so", names[i]);
    got_probe(fd, id, "file_probe", names, addrs, 5);
}

// Correlation flow used to live here as a one-shot op (flow_watch). The agent no longer
// knows any target class or a "run()" trigger contract: the persistent capture set
// (capture_start) hooks EVP_CipherUpdate and SSL_write in every module that holds them, and
// the caller triggers the workload through java_call. The daemon joins the two streams by
// tid+ts (daemon/src/flow.ts).

// ---- Java-layer rich capture: an interposing JCE provider (installed by the target/self-test
//      app) reports every Cipher/Mac/MessageDigest op here with algorithm+op+key+iv+input+output.
//      Bound at capture_start via RegisterNatives to the reporter class adhd names (target-agnostic;
//      no sandbox-specific JNI symbol). ----------------------------------------------------------
static int copy_jba(JNIEnv *env, jbyteArray a, unsigned char *dst, int cap, int *total) {
    if (total) *total = 0;
    if (!a) return 0;
    jsize n = (*env)->GetArrayLength(env, a);
    if (n <= 0) return 0;
    if (total) *total = (int)n;
    if (n > cap) n = cap;
    (*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)dst);
    return (int)n;
}

// nReport implementation. Registered onto the target's reporter class at capture_start
// (adh_capture_register_reporter) — no hardcoded JNI symbol ties the agent to any package.
static void report_java_capture(
        JNIEnv *env, jstring jalgo, jstring jop, jbyteArray jkey, jbyteArray jiv,
        jbyteArray jin, jbyteArray jout, const char *origin, int hook_id, int metadata_known, int origin_truncated) {
    g_java_active = 1;
    // Build the bounded Java record off-lock: the JNI string/array copies can take far longer
    // than the queue append, and this callback runs on the target's crypto thread.
    struct JCapRec rec;
    memset(&rec, 0, sizeof(rec));
    rec.input_known = metadata_known;
    rec.input_present = jin != NULL;
    rec.origin_hook_id = hook_id > 0 ? hook_id : 0;
    rec.origin_truncated = origin_truncated || (origin && strlen(origin) >= sizeof(rec.origin));
    if (origin) snprintf(rec.origin, sizeof(rec.origin), "%s", origin);
    const char *a = jalgo ? (*env)->GetStringUTFChars(env, jalgo, NULL) : NULL;
    const char *o = jop ? (*env)->GetStringUTFChars(env, jop, NULL) : NULL;
    if (a) { strncpy(rec.algo, a, sizeof(rec.algo) - 1); (*env)->ReleaseStringUTFChars(env, jalgo, a); }
    if (o) { strncpy(rec.op, o, sizeof(rec.op) - 1); (*env)->ReleaseStringUTFChars(env, jop, o); }
    rec.tid = (int)gettid();
    rec.ts_ns = now_ns();
    rec.nkey = copy_jba(env, jkey, rec.key, JCAP_KEY, &rec.key_total);
    rec.niv  = copy_jba(env, jiv, rec.iv, JCAP_IV, &rec.iv_total);
    rec.nin  = copy_jba(env, jin, rec.in, JCAP_DATA, &rec.in_total);
    rec.nout = copy_jba(env, jout, rec.out, JCAP_DATA, &rec.out_total);
    if (pthread_mutex_trylock(&g_cap_lock) != 0) {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    if (g_njcaps < JCAP_MAX) {
        g_jcaps[g_jcap_head] = rec;
        g_jcap_head = (g_jcap_head + 1) % JCAP_MAX;
        g_njcaps++;
        if (g_njcaps == 1) pthread_cond_signal(&g_cap_cond);
    } else {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);   // fail-loud, reported via drain
    }
    pthread_mutex_unlock(&g_cap_lock);
}

static void adh_nreport_impl(JNIEnv *env, jclass cls, jstring algo, jstring op,
                              jbyteArray key, jbyteArray iv, jbyteArray in, jbyteArray out) {
    (void)cls;
    report_java_capture(env, algo, op, key, iv, in, out, NULL, 0, 0, 0);
}
void adh_capture_java_origin(JNIEnv *env, jstring algo, jstring op, jbyteArray key, jbyteArray iv,
                             jbyteArray in, jbyteArray out, const char *target, int hook_id, int target_truncated) {
    report_java_capture(env, algo, op, key, iv, in, out, target, hook_id, 1, target_truncated);
}

// Register adh_nreport_impl as the target reporter class's `nReport`. Called at capture_start
// with the class name adhd supplies (target-agnostic). Returns 1 on success, 0 if the class is
// absent or registration fails (fail-loud: reported in the capture_start reply, not silent).
int adh_capture_register_reporter(JNIEnv *env, const char *reportClass) {
    if (!reportClass || !reportClass[0]) return 0;
    jclass rc = adh_jni_load_app_class(env, reportClass);
    if (!rc) return 0;
    JNINativeMethod m = { (char *)"nReport", (char *)"(Ljava/lang/String;Ljava/lang/String;[B[B[B[B)V", (void *)adh_nreport_impl };
    int r = (*env)->RegisterNatives(env, rc, &m, 1);
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    return (r == 0) ? 1 : 0;
}

// ---- capture sender ---------------------------------------------------------
// Host polling cannot keep up with a burst because every round trip first lets the bounded ring
// fill. capture_start therefore arms this sender on the same framed socket: it pops a bounded
// batch under the ring lock, serializes off-lock, and pushes a captureBatch frame. A send failure
// means the byte stream is no longer trustworthy (send_all may have written a partial frame), so
// the sender stops and the still-queued records are accounted as dropped rather than replayed.
#define CAP_SEND_BATCH 128
#define JCAP_SEND_BATCH 128
static pthread_t g_sender_thread;
static int g_sender_started = 0;
static int g_sender_stop = 0;
static int g_sender_fd = -1;
static pthread_mutex_t g_sender_ctl = PTHREAD_MUTEX_INITIALIZER;

static char *build_capture_batch(const struct CapRec *caps, int ncaps,
                                 const struct JCapRec *jcaps, int njcaps,
                                 unsigned long long frame_seq, unsigned long long backlog,
                                 unsigned long long queued, unsigned long long drained,
                                 unsigned long long seq, unsigned long long dropped,
                                 unsigned long long jdropped, long long first_drop,
                                 long long last_drop) {
    size_t cap = 1 << 16, len = 0;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    len += snprintf(out + len, cap - len,
        "{\"t\":\"captureBatch\",\"captures\":[");
    for (int i = 0; i < ncaps; i++) {
        if (len + (size_t)CAP_BYTES * 2 + 1024 > cap) {
            size_t nc = cap * 2;
            while (len + (size_t)CAP_BYTES * 2 + 1024 > nc) nc *= 2;
            char *no = (char *)realloc(out, nc); if (!no) { free(out); return NULL; }
            out = no; cap = nc;
        }
        len = emit_caprec(out, len, cap, &caps[i], i == 0);
    }
    len += snprintf(out + len, cap > len ? cap - len : 0, "],\"jcaptures\":[");
    for (int i = 0; i < njcaps; i++) {
        if (len + JCAP_RECORD_RESERVE > cap) {
            size_t nc = cap * 2;
            char *no = (char *)realloc(out, nc); if (!no) { free(out); return NULL; }
            out = no; cap = nc;
        }
        len = emit_jcaprec(out, len, cap, &jcaps[i], i == 0);
    }
    snprintf(out + len, cap > len ? cap - len : 0,
        "],\"count\":%d,\"jcount\":%d,\"frameSeq\":%llu,\"backlog\":%llu,\"queued\":%llu,\"seq\":%llu,"
        "\"dropped\":%llu,\"jdropped\":%llu,\"drained\":%llu,\"residual\":%lld,"
        "\"firstDropNs\":%lld,\"lastDropNs\":%lld,\"ring\":%d,\"complete\":%s,\"javaActive\":%s}\n",
        ncaps, njcaps, frame_seq, backlog, queued, seq, dropped, jdropped, drained,
        (long long)seq - (long long)drained - (long long)backlog - (long long)dropped,
        first_drop, last_drop, CAP_RING,
        (dropped == 0 && jdropped == 0) ? "true" : "false", g_java_active ? "true" : "false");
    return out;
}

static void sender_account_unsent(void) {
    pthread_mutex_lock(&g_cap_lock);
    unsigned long long n = __atomic_exchange_n(&g_cap_queued, 0, __ATOMIC_RELAXED);
    unsigned long long j = __atomic_exchange_n(&g_jcap_queued, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_cap_queued_seq, 0, __ATOMIC_RELAXED);
    if (n) __atomic_add_fetch(&g_cap_dropped, n, __ATOMIC_RELAXED);
    if (j) __atomic_add_fetch(&g_jcap_dropped, j, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&g_cap_lock);
}

static void *capture_sender_thread(void *arg) {
    int fd = (int)(intptr_t)arg;
    struct CapRec *caps = (struct CapRec *)malloc(sizeof(*caps) * CAP_SEND_BATCH);
    struct JCapRec *jcaps = (struct JCapRec *)malloc(sizeof(*jcaps) * JCAP_SEND_BATCH);
    if (!caps || !jcaps) {
        free(caps); free(jcaps);
        LOGE("capture sender: allocation failed");
        return NULL;
    }
    while (!__atomic_load_n(&g_sender_stop, __ATOMIC_RELAXED)) {
        int ncaps = 0, njcaps = 0;
        unsigned long long frame_seq = 0, backlog = 0, queued = 0, drained_after = 0;
        unsigned long long seq = 0, dropped = 0, jdropped = 0;
        long long first_drop = 0, last_drop = 0;
        pthread_mutex_lock(&g_cap_lock);
        while (!__atomic_load_n(&g_sender_stop, __ATOMIC_RELAXED) && !g_ring_count && !g_njcaps)
            pthread_cond_wait(&g_cap_cond, &g_cap_lock);
        if (__atomic_load_n(&g_sender_stop, __ATOMIC_RELAXED)) {
            pthread_mutex_unlock(&g_cap_lock);
            break;
        }
        while (g_ring_count > 0 && ncaps < CAP_SEND_BATCH) {
            struct CapRec *src = &g_ring[g_ring_tail];
            struct CapRec *dst = &caps[ncaps++];
            memcpy(dst, src, offsetof(struct CapRec, data));
            memcpy(dst->data, src->data, (size_t)src->n);
            g_ring_tail = (g_ring_tail + 1) % CAP_RING;
            g_ring_count--;
        }
        if (ncaps) __atomic_add_fetch(&g_cap_queued, (unsigned long long)ncaps, __ATOMIC_RELAXED);
        while (g_njcaps > 0 && njcaps < JCAP_SEND_BATCH) {
            struct JCapRec *src = &g_jcaps[g_jcap_tail];
            struct JCapRec *dst = &jcaps[njcaps++];
            memcpy(dst, src, offsetof(struct JCapRec, in));
            memcpy(dst->in, src->in, (size_t)src->nin);
            memcpy(dst->out, src->out, (size_t)src->nout);
            g_jcap_tail = (g_jcap_tail + 1) % JCAP_MAX;
            g_njcaps--;
        }
        if (njcaps) __atomic_add_fetch(&g_jcap_queued, (unsigned long long)njcaps, __ATOMIC_RELAXED);
        frame_seq = ++g_cap_frame_seq;
        if (ncaps) __atomic_store_n(&g_cap_queued_seq, frame_seq, __ATOMIC_RELAXED);
        queued = __atomic_load_n(&g_cap_queued, __ATOMIC_RELAXED) - (unsigned long long)ncaps;
        backlog = (unsigned long long)g_ring_count + queued;
        drained_after = __atomic_load_n(&g_cap_drained, __ATOMIC_RELAXED) + (unsigned long long)ncaps;
        seq = __atomic_load_n(&g_cap_seq, __ATOMIC_RELAXED);
        dropped = __atomic_load_n(&g_cap_dropped, __ATOMIC_RELAXED);
        jdropped = __atomic_load_n(&g_jcap_dropped, __ATOMIC_RELAXED);
        first_drop = g_cap_first_drop_ns;
        last_drop = g_cap_last_drop_ns;
        pthread_mutex_unlock(&g_cap_lock);
        char *out = build_capture_batch(caps, ncaps, jcaps, njcaps,
                                        frame_seq, backlog, queued, drained_after, seq, dropped,
                                        jdropped, first_drop, last_drop);
        if (!out) break;
        if (send_line(fd, out) == 0) {
            pthread_mutex_lock(&g_cap_lock);
            __atomic_sub_fetch(&g_cap_queued, (unsigned long long)ncaps, __ATOMIC_RELAXED);
            __atomic_sub_fetch(&g_jcap_queued, (unsigned long long)njcaps, __ATOMIC_RELAXED);
            __atomic_store_n(&g_cap_queued_seq, 0, __ATOMIC_RELAXED);
            __atomic_add_fetch(&g_cap_drained, (unsigned long long)ncaps, __ATOMIC_RELAXED);
            pthread_mutex_unlock(&g_cap_lock);
        } else {
            shutdown(fd, SHUT_RDWR);
            break;
        }
        free(out);
    }
    sender_account_unsent();
    free(caps);
    free(jcaps);
    return NULL;
}

void adh_capture_sender_start(int fd) {
    adh_capture_sender_stop(0);
    if (fd < 0) return;
    pthread_mutex_lock(&g_sender_ctl);
    g_sender_stop = 0;
    g_sender_fd = fd;
    if (pthread_create(&g_sender_thread, NULL, capture_sender_thread, (void *)(intptr_t)fd) == 0) {
        g_sender_started = 1;
    } else {
        g_sender_fd = -1;
        LOGE("capture sender: pthread_create failed");
    }
    pthread_mutex_unlock(&g_sender_ctl);
}

void adh_capture_sender_stop(int terminate_io) {
    pthread_t thread;
    int fd;
    pthread_mutex_lock(&g_sender_ctl);
    if (!g_sender_started) {
        g_sender_fd = -1;
        pthread_mutex_unlock(&g_sender_ctl);
        return;
    }
    __atomic_store_n(&g_sender_stop, 1, __ATOMIC_RELAXED);
    thread = g_sender_thread;
    fd = g_sender_fd;
    pthread_mutex_lock(&g_cap_lock);
    pthread_cond_broadcast(&g_cap_cond);
    pthread_mutex_unlock(&g_cap_lock);
    if (terminate_io && fd >= 0) shutdown(fd, SHUT_RDWR);
    pthread_mutex_unlock(&g_sender_ctl);
    pthread_join(thread, NULL);
    pthread_mutex_lock(&g_sender_ctl);
    g_sender_started = 0;
    g_sender_fd = -1;
    g_sender_stop = 0;
    pthread_mutex_unlock(&g_sender_ctl);
}

// ---- anti-analysis / system-info hooks (module V) — defined here (above capture_start)
//      so the persistent capture path can install them. GOT-hook the target's own
//      detection / system-query calls and stream each event into the unified capture() ring.
//      Observe-only: record the call, then forward it. Classification (debug / root / prop)
//      happens on the host from the text below — a path substring check in here used to
//      mis-label ordinary paths and nothing ever read the result.
//      The line is tab-separated key=value. path / name / value are last and may contain
//      spaces; tabs and newlines inside them are flattened so the host can split on tabs.
//      lr is the caller's return address, read BEFORE the original call (that call clobbers LR).
//      TRACEME neutralization has no control surface. ----
static void scrub_field(char *s) {
    for (; s && *s; s++) if (*s == '\t' || *s == '\n' || *s == '\r') *s = ' ';
}
static void cap_text(const char *func, const char *line) {
    if (!func || !line || !line[0]) return;
    capture(func, (const unsigned char *)line, (int)strlen(line));
}

typedef long (*ptrace_t)(int, void *, void *, void *);
static ptrace_t g_orig_ptrace = NULL;
static long my_ptrace(int req, void *pid, void *addr, void *data) {
    unsigned long long lr = (unsigned long long)(uintptr_t)__builtin_return_address(0);
    long ret = g_orig_ptrace(req, pid, addr, data);
    char d[160];
    snprintf(d, sizeof(d), "request=%d\tpid=%lld\tret=%ld\tlr=0x%llx%s",
             req, (long long)(intptr_t)pid, ret, lr, req == 0 ? "\tnote=PTRACE_TRACEME" : "");
    cap_text("ptrace", d);
    return ret;
}
typedef int (*access_t)(const char *, int);
static access_t g_orig_access = NULL;
static int my_access(const char *p, int m) {
    unsigned long long lr = (unsigned long long)(uintptr_t)__builtin_return_address(0);
    int ret = g_orig_access(p, m);
    if (p) {
        char path[192];
        snprintf(path, sizeof(path), "%s", p);
        scrub_field(path);
        char d[280];
        snprintf(d, sizeof(d), "mode=%d\tret=%d\tlr=0x%llx\tpath=%s", m, ret, lr, path);
        cap_text("access", d);
    }
    return ret;
}
typedef int (*faccessat_t)(int, const char *, int, int);
static faccessat_t g_orig_faccessat = NULL;
static int my_faccessat(int dirfd, const char *p, int mode, int flags) {
    unsigned long long lr = (unsigned long long)(uintptr_t)__builtin_return_address(0);
    int ret = g_orig_faccessat(dirfd, p, mode, flags);
    if (p) {
        char path[192];
        snprintf(path, sizeof(path), "%s", p);
        scrub_field(path);
        char d[320];
        snprintf(d, sizeof(d), "dirfd=%d\tmode=%d\tflags=%d\tret=%d\tlr=0x%llx\tpath=%s",
                 dirfd, mode, flags, ret, lr, path);
        cap_text("faccessat", d);
    }
    return ret;
}
typedef int (*prop_t)(const char *, char *);
static prop_t g_orig_prop = NULL;
static int my_prop(const char *name, char *value) {
    unsigned long long lr = (unsigned long long)(uintptr_t)__builtin_return_address(0);
    int ret = g_orig_prop(name, value);
    char nb[96], vb[96], d[280];
    snprintf(nb, sizeof(nb), "%s", name ? name : "");
    snprintf(vb, sizeof(vb), "%s", (ret > 0 && value) ? value : "");
    scrub_field(nb);
    scrub_field(vb);
    snprintf(d, sizeof(d), "ret=%d\tlr=0x%llx\tname=%s\tvalue=%s", ret, lr, nb, vb);
    cap_text("sysprop", d);
    return ret;
}
// __system_property_read_callback delivers the name and value to a callback, synchronously,
// before it returns. The hop lives on this stack frame for that call only.
typedef void (*prop_cb_t)(void *, const char *, const char *, uint32_t);
typedef void (*prop_read_t)(const void *, prop_cb_t, void *);
static prop_read_t g_orig_prop_read = NULL;
struct PropHop { prop_cb_t cb; void *cookie; unsigned long long lr; };
static void my_prop_read_cb(void *cookie, const char *name, const char *value, uint32_t serial) {
    struct PropHop *hop = (struct PropHop *)cookie;
    char nb[96], vb[96], d[280];
    snprintf(nb, sizeof(nb), "%s", name ? name : "");
    snprintf(vb, sizeof(vb), "%s", value ? value : "");
    scrub_field(nb);
    scrub_field(vb);
    snprintf(d, sizeof(d), "lr=0x%llx\tname=%s\tvalue=%s", hop->lr, nb, vb);
    cap_text("propread", d);
    if (hop->cb) hop->cb(hop->cookie, name, value, serial);
}
static void my_prop_read(const void *pi, prop_cb_t cb, void *cookie) {
    unsigned long long lr = (unsigned long long)(uintptr_t)__builtin_return_address(0);
    struct PropHop hop;
    hop.cb = cb;
    hop.cookie = cookie;
    hop.lr = lr;
    g_orig_prop_read(pi, my_prop_read_cb, &hop);
}

// Persistent-hook target modules (from adhd's capture_start params) — remembered so
// capture_stop restores the exact GOT it patched. Empty = that category not installed.
static char g_file_mod[64] = "";
// sysModule is a comma-separated list. Eight is the cap a single capture_start will patch;
// more than that is reported as sysTruncated instead of being silently hooked halfway.
#define SYS_MOD_MAX 8
static char g_sys_mods[SYS_MOD_MAX][64];
static int g_sys_nmods = 0;

static void sys_restore(void) {
    adh_capture_got_restore((void *)my_ptrace);
    adh_capture_got_restore((void *)my_access);
    adh_capture_got_restore((void *)my_faccessat);
    adh_capture_got_restore((void *)my_prop);
    adh_capture_got_restore((void *)my_prop_read);
    g_sys_nmods = 0;
}

static int sys_mods_parse(const char *spec, int *truncated) {
    int extra = 0;
    g_sys_nmods = 0;
    if (truncated) *truncated = 0;
    if (!spec) return 0;
    const char *p = spec;
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ',') p++;
        int n = (int)(p - start);
        while (n > 0 && (start[n - 1] == ' ' || start[n - 1] == '\t')) n--;
        if (n <= 0) continue;
        if (g_sys_nmods >= SYS_MOD_MAX || n > 63) { extra++; if (g_sys_nmods >= SYS_MOD_MAX) continue; }
        if (n > 63) n = 63;
        memcpy(g_sys_mods[g_sys_nmods], start, (size_t)n);
        g_sys_mods[g_sys_nmods][n] = 0;
        g_sys_nmods++;
    }
    if (truncated) *truncated = extra > 0;
    return g_sys_nmods;
}

static int sys_sum(int acc, int n) {
    if (n > 0) return acc + n;
    return acc;
}
// crypto/TLS caller module whose GOT holds the EVP/SSL pointers. Empty = scan ALL file-backed
// modules (default): catches the JCE provider's Conscrypt AND non-Conscrypt BoringSSL callers
// (cronet's bundled copy, renamed/statically-linked libs). adhd may pass a specific module.
static char g_crypto_mod[64] = "";

// ---- continuous capture: install persistent EVP+SSL hooks, drain accumulated records
//      periodically from adhd (mirrors the ios-decrypt-helper log-store model: hooks
//      stay installed and events stream to the panel, instead of one-shot triggers) ----
static int g_capture_on = 0;

// Policy writes are command-thread-only. Observation callbacks never mutate this catalog.
static uint32_t g_method_selected = ADH_CM_ALL;
static uint32_t g_method_revision = 1;
static uint32_t g_method_effective = 0;
static int g_method_results[ADH_CM_COUNT];
static int g_method_results_initialized = 0;
static void capture_method_results_reset(void) {
    for (int i = 0; i < ADH_CM_COUNT; i++) g_method_results[i] = -2;
    g_method_results_initialized = 1;
}
static int capture_method_wanted(int index) { return !!(g_method_effective & (UINT32_C(1) << index)); }


// Per-package hook policy, delivered by the Zygisk companion (see injector/zygisk/jni/main.cpp's
// `policy` verb) and applied here. ALL ON is the default and reproduces the behaviour before the
// policy existed, so an absent policy changes nothing.
//
// Unchecked means the hooks are NOT INSTALLED, never "installed then filtered": the point is a
// smaller footprint inside the target (a hooked app can notice — measured 2026-10-11, a target
// killed itself with SIGSEGV while our GOT hooks were live).
struct CaptureFamilyFlags { int digest, hmac, symmetric, asymmetric, tls, aead, system; };
// Crypto defaults ON; system detection defaults OFF (Manager opt-in).
static struct CaptureFamilyFlags g_families = { 1, 1, 1, 1, 1, 1, 0 };
static int dsign_capture_allowed(int asymmetric) { return asymmetric ? g_families.asymmetric : g_families.hmac; }

void adh_capture_set_families(int digest, int hmac, int symmetric, int asymmetric, int tls, int aead, int system) {
    if ((!!digest != g_families.digest || !!hmac != g_families.hmac || !!symmetric != g_families.symmetric ||
         !!asymmetric != g_families.asymmetric || !!tls != g_families.tls || !!aead != g_families.aead ||
         !!system != g_families.system) && g_method_revision < UINT32_MAX) g_method_revision++;
    g_families.digest = digest ? 1 : 0;
    g_families.hmac = hmac ? 1 : 0;
    g_families.symmetric = symmetric ? 1 : 0;
    g_families.asymmetric = asymmetric ? 1 : 0;
    g_families.tls = tls ? 1 : 0;
    g_families.aead = aead ? 1 : 0;
    g_families.system = system ? 1 : 0;
#ifdef ADH_HAVE_LSPLANT
    adh_java_crypto_set_families((digest ? ADH_CF_DIGEST : 0) | (hmac ? ADH_CF_HMAC : 0) |
        (symmetric ? ADH_CF_SYMMETRIC : 0) | (asymmetric ? ADH_CF_ASYMMETRIC : 0) |
        (tls ? ADH_CF_TLS : 0) | (aead ? ADH_CF_AEAD : 0) | (system ? ADH_CF_SYSTEM : 0));
#endif
}

void adh_capture_get_families(int *digest, int *hmac, int *symmetric, int *asymmetric, int *tls, int *aead, int *system) {
    if (digest) *digest = g_families.digest;
    if (hmac) *hmac = g_families.hmac;
    if (symmetric) *symmetric = g_families.symmetric;
    if (asymmetric) *asymmetric = g_families.asymmetric;
    if (tls) *tls = g_families.tls;
    if (aead) *aead = g_families.aead;
    if (system) *system = g_families.system;
}


static void *capture_method_wrapper(int i) {
    static void *const wrappers[ADH_CM_COUNT] = {
        [ADH_CM_CIPHER_UPDATE] = (void *)my_EVP_CipherUpdate,
        [ADH_CM_DIGEST_UPDATE] = (void *)my_EVP_DigestUpdate,
        [ADH_CM_HMAC_UPDATE] = (void *)my_HMAC_Update,
        [ADH_CM_SIGN_UPDATE] = (void *)my_EVP_DigestSignUpdate,
        [ADH_CM_SSL_WRITE] = (void *)my_SSL_write,
        [ADH_CM_SSL_READ] = (void *)my_SSL_read,
        [ADH_CM_CIPHER_INIT] = (void *)my_EVP_CipherInit_ex,
        [ADH_CM_CIPHER_FREE] = (void *)my_EVP_CIPHER_CTX_free,
        [ADH_CM_ECDSA_SIGN] = (void *)my_ECDSA_sign,
        [ADH_CM_ECDSA_VERIFY] = (void *)my_ECDSA_verify,
        [ADH_CM_PKEY_ENCRYPT] = (void *)my_EVP_PKEY_encrypt,
        [ADH_CM_PKEY_DECRYPT] = (void *)my_EVP_PKEY_decrypt,
        [ADH_CM_AEAD_SEAL] = (void *)my_EVP_AEAD_CTX_seal,
        [ADH_CM_AEAD_OPEN] = (void *)my_EVP_AEAD_CTX_open,
        [ADH_CM_SIGN_INIT] = (void *)my_EVP_DigestSignInit,
        [ADH_CM_VERIFY_INIT] = (void *)my_EVP_DigestVerifyInit,
        [ADH_CM_SIGN_FINAL] = (void *)my_EVP_DigestSignFinal,
        [ADH_CM_VERIFY_UPDATE] = (void *)my_EVP_DigestVerifyUpdate,
        [ADH_CM_VERIFY_FINAL] = (void *)my_EVP_DigestVerifyFinal,
        [ADH_CM_OPEN] = (void *)my_open,
        [ADH_CM_OPENAT] = (void *)my_openat,
        [ADH_CM_READ] = (void *)my_read,
        [ADH_CM_WRITE] = (void *)my_write,
        [ADH_CM_SYSCALL] = (void *)my_syscall,
        [ADH_CM_READ_CHK] = (void *)my_read_chk,
        [ADH_CM_WRITE_CHK] = (void *)my_write_chk,
        [ADH_CM_PTRACE] = (void *)my_ptrace,
        [ADH_CM_ACCESS] = (void *)my_access,
        [ADH_CM_FACCESSAT] = (void *)my_faccessat,
        [ADH_CM_PROP_GET] = (void *)my_prop,
        [ADH_CM_PROP_READ] = (void *)my_prop_read,
    };
    return i >= 0 && i < ADH_CM_COUNT ? wrappers[i] : NULL;
}

static uint32_t capture_family_bits(void) {
    return (g_families.digest ? ADH_CF_DIGEST : 0) | (g_families.hmac ? ADH_CF_HMAC : 0) |
        (g_families.symmetric ? ADH_CF_SYMMETRIC : 0) | (g_families.asymmetric ? ADH_CF_ASYMMETRIC : 0) |
        (g_families.tls ? ADH_CF_TLS : 0) | (g_families.aead ? ADH_CF_AEAD : 0) |
        (g_families.system ? ADH_CF_SYSTEM : 0) | ADH_CF_FILE;
}

void adh_cmd_capture_methods(int fd, const char *id, const char *request) {
    char action[16] = "", catalog[32] = "", revision[16] = "", selection[ADH_CM_COUNT + 2] = "";
    const char *error = NULL;
    if (!adh_capture_string_field(request, "action", action, sizeof(action))) error = "INVALID_REQUEST";
    else if (!strcmp(action, "set")) {
        uint32_t bits = 0;
        if (!adh_capture_string_field(request, "catalog", catalog, sizeof(catalog)) ||
            !adh_capture_string_field(request, "revision", revision, sizeof(revision)) ||
            !adh_capture_string_field(request, "selection", selection, sizeof(selection))) error = "INVALID_REQUEST";
        else error = adh_capture_method_validate(catalog, revision, selection, g_method_revision, g_capture_on, &bits);
        if (!error && bits != g_method_selected) { g_method_selected = bits; g_method_revision++; capture_method_results_reset(); }
    } else if (strcmp(action, "status")) error = "INVALID_ACTION";
    if (!g_method_results_initialized) capture_method_results_reset();
    uint32_t effective = adh_capture_method_effective(g_method_selected, capture_family_bits());
    char idj[128]; json_escape(id, idj, sizeof(idj));
    char out[16384];
    int n = snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_methods\",\"ok\":%s,\"error\":%s%s%s,\"catalog\":\"%s\",\"revision\":\"%u\",\"on\":%s,\"installationEvidence\":\"live-slot-read\",\"methods\":[",
        idj, error ? "false" : "true", error ? "\"" : "", error ? error : "null", error ? "\"" : "",
        ADH_CAPTURE_CATALOG, g_method_revision, g_capture_on ? "true" : "false");
    for (int i = 0; i < ADH_CM_COUNT && n > 0 && (size_t)n < sizeof(out); i++) {
        const struct AdhCaptureMethod *m = &adh_capture_methods[i];
        struct AdhCaptureSlotState ownership; adh_capture_got_state(capture_method_wrapper(i), &ownership);
        int result = g_method_results[i];
        const char *state = ownership.unreadable ? "ownership-unknown" : ownership.changed ? "ownership-lost" :
            ownership.owned ? "installed" : (g_capture_on && result > 0) ? "not-owned" : result == -2 ? "not-armed" : result == -4 ? "no-module" : result == -1 ? "disabled" :
            result == -3 ? "install-error" : result == 0 ? "not-found" : "installed-at-last-attempt";
        int w = snprintf(out+n, sizeof(out)-(size_t)n, "%s{\"id\":\"native.%s\",\"symbol\":\"%s\",\"families\":%u,\"requested\":%s,\"effective\":%s,\"dependency\":%s,\"state\":\"%s\",\"lastAttemptSlots\":%d,\"ownedSlots\":%u,\"changedSlots\":%u,\"unreadableSlots\":%u,\"restoreConflicts\":%u,\"restoreFailures\":%u,\"capacityFailures\":%u,\"requires\":[",
            i ? "," : "", m->symbol, m->symbol, m->families,
            (g_method_selected & (UINT32_C(1)<<i)) ? "true" : "false", (effective & (UINT32_C(1)<<i)) ? "true" : "false",
            ((effective & ~g_method_selected) & (UINT32_C(1)<<i)) ? "true" : "false", state, result > 0 ? result : 0, ownership.owned, ownership.changed, ownership.unreadable, ownership.restoreConflicts, ownership.restoreFailures, ownership.capacityFailures);
        if (w < 0 || (size_t)w >= sizeof(out)-(size_t)n) { n = -1; break; } n += w;
        int first = 1;
        for (int j = 0; j < ADH_CM_COUNT; j++) if (m->dependencies & (UINT32_C(1)<<j)) {
            w = snprintf(out+n, sizeof(out)-(size_t)n, "%s\"native.%s\"", first ? "" : ",", adh_capture_methods[j].symbol);
            if (w < 0 || (size_t)w >= sizeof(out)-(size_t)n) { n = -1; break; } n += w; first = 0;
        }
        if (n < 0) break;
        w = snprintf(out+n, sizeof(out)-(size_t)n, "]}");
        if (w < 0 || (size_t)w >= sizeof(out)-(size_t)n) { n = -1; break; } n += w;
    }
    if (n < 0 || (size_t)n + 4 >= sizeof(out)) {
        snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_methods\",\"ok\":false,\"error\":\"CATALOG_OVERFLOW\"}", idj);
    } else snprintf(out+n, sizeof(out)-(size_t)n, "]}\n");
    send_line(fd, out);
}

static void copy_jstring(JNIEnv *env, jstring value, char *buf, size_t cap) {
    buf[0] = 0;
    if (!env || !value || cap == 0) return;
    const char *chars = (*env)->GetStringUTFChars(env, value, NULL);
    if (!chars) return;
    snprintf(buf, cap, "%s", chars);
    (*env)->ReleaseStringUTFChars(env, value, chars);
}

void adh_capture_java(JNIEnv *env, jstring algo, jstring op, jbyteArray key, jbyteArray iv, jbyteArray in, jbyteArray out) {
    static int logged = 0;
    if (!__atomic_exchange_n(&logged, 1, __ATOMIC_RELAXED)) {
        char algo_buf[96];
        char op_buf[32];
        copy_jstring(env, algo, algo_buf, sizeof(algo_buf));
        copy_jstring(env, op, op_buf, sizeof(op_buf));
        LOGI("java crypto hit %s %s", algo_buf[0] ? algo_buf : "?", op_buf[0] ? op_buf : "?");
    }
    adh_nreport_impl(env, NULL, algo, op, key, iv, in, out);
}

static void skip_add(char *buf, size_t cap, const char *names) {
    if (strstr(buf, names)) return;
    size_t len = strlen(buf);
    snprintf(buf + len, cap > len ? cap - len : 0, "%s%s", len ? "," : "", names);
}

// There is deliberately NO self-arm here. The per-package policy decides WHICH FAMILIES get
// installed; WHO INSTALLS is still the caller, because the GOT patch target is a module name and
// the agent must not carry one (see the WS-B red line in tools/verify_v87_mcp_operability.sh: the
// name of the app-level JCE/TLS provider module must not appear anywhere under agent/src — it is a
// plain substring scan, so it would catch even a comment that spells it out). The only module we
// could name without a caller is "every file-backed module" — which the settings contract
// explicitly warns against as a default (it hooks framework crypto on the main thread during
// init). So the policy rides the companion → agent hop (adh_agent_set_policy) and is applied by
// whatever install comes next; with no host there is no install, which is the documented honest
// boundary, not an oversight.

static void capture_native_restore(int *results) {
    int e = 0, w = 0, r = 0, dg = 0, hm = 0, ds = 0;
    int pks = 0, pkv = 0, pke = 0, pkd = 0, aes = 0, aeo = 0;
    int dsi = 0, dvi = 0, dsf = 0, dvu = 0, dvf = 0;
    if (g_evp_cipher_orig) e  = adh_capture_got_restore((void *)my_EVP_CipherUpdate);
    if (g_orig_evp_digest) dg = adh_capture_got_restore((void *)my_EVP_DigestUpdate);
    if (g_orig_hmac)       hm = adh_capture_got_restore((void *)my_HMAC_Update);
    if (g_orig_digest_sign)ds = adh_capture_got_restore((void *)my_EVP_DigestSignUpdate);
    if (g_orig_ssl_write)  w  = adh_capture_got_restore((void *)my_SSL_write);
    if (g_orig_ssl_read)   r  = adh_capture_got_restore((void *)my_SSL_read);
    if (g_evp_cipher_init_orig)     adh_capture_got_restore((void *)my_EVP_CipherInit_ex);
    if (g_evp_cipher_ctx_free_orig) adh_capture_got_restore((void *)my_EVP_CIPHER_CTX_free);
    if (g_ecdsa_sign_orig)   pks = adh_capture_got_restore((void *)my_ECDSA_sign);
    if (g_ecdsa_verify_orig) pkv = adh_capture_got_restore((void *)my_ECDSA_verify);
    if (g_pkey_encrypt_orig) pke = adh_capture_got_restore((void *)my_EVP_PKEY_encrypt);
    if (g_pkey_decrypt_orig) pkd = adh_capture_got_restore((void *)my_EVP_PKEY_decrypt);
    if (g_aead_seal_orig)    aes = adh_capture_got_restore((void *)my_EVP_AEAD_CTX_seal);
    if (g_aead_open_orig)    aeo = adh_capture_got_restore((void *)my_EVP_AEAD_CTX_open);
    if (g_orig_dsign_init)   dsi = adh_capture_got_restore((void *)my_EVP_DigestSignInit);
    if (g_orig_dverify_init) dvi = adh_capture_got_restore((void *)my_EVP_DigestVerifyInit);
    if (g_orig_dsign_final)  dsf = adh_capture_got_restore((void *)my_EVP_DigestSignFinal);
    if (g_orig_digest_verify)dvu = adh_capture_got_restore((void *)my_EVP_DigestVerifyUpdate);
    if (g_orig_dverify_final)dvf = adh_capture_got_restore((void *)my_EVP_DigestVerifyFinal);
    // Retry pending slot restoration even after a previous stop cleared its module label.
    adh_capture_got_restore((void *)my_open);
    adh_capture_got_restore((void *)my_openat);
    adh_capture_got_restore((void *)my_read);
    adh_capture_got_restore((void *)my_write);
    adh_capture_got_restore((void *)my_syscall);
    adh_capture_got_restore((void *)my_read_chk);
    adh_capture_got_restore((void *)my_write_chk);
    g_file_mod[0] = 0;
    // restore persistent system/detection hooks
    sys_restore();
    results[0] = e;
    results[1] = w;
    results[2] = r;
    results[3] = dg;
    results[4] = hm;
    results[5] = ds;
    results[6] = pks;
    results[7] = pkv;
    results[8] = pke;
    results[9] = pkd;
    results[10] = aes;
    results[11] = aeo;
    results[12] = dsi;
    results[13] = dvi;
    results[14] = dsf;
    results[15] = dvu;
    results[16] = dvf;
}

void adh_cmd_capture_start(int fd, const char *id, const char *cryptoModule, const char *fileModule, const char *sysModule) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    if (g_capture_on) { int previous[17]; capture_native_restore(previous); }
    if (adh_capture_got_pending()) {
        char failed[256]; snprintf(failed, sizeof(failed), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_start\",\"ok\":false,\"error\":\"RESTORE_INCOMPLETE\",\"pendingSlots\":%u}", idj, adh_capture_got_pending());
        send_line(fd, failed); return;
    }
    capture_method_results_reset();
    g_method_effective = adh_capture_method_effective(g_method_selected, capture_family_bits());
    void *evp = adh_resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    void *dig = adh_resolve_sym("libcrypto.so", "EVP_DigestUpdate");
    void *hm  = adh_resolve_sym("libcrypto.so", "HMAC_Update");
    void *dsu = adh_resolve_sym("libcrypto.so", "EVP_DigestSignUpdate");
    void *ow  = adh_resolve_sym("libssl.so", "SSL_write");
    void *orr = adh_resolve_sym("libssl.so", "SSL_read");
    // Symmetric key/IV: the init call carries the key, the update call carries the payload, so both
    // ends of the pair must be hooked for a native AES capture to name its key.
    void *cin = adh_resolve_sym("libcrypto.so", "EVP_CipherInit_ex");
    void *cfr = adh_resolve_sym("libcrypto.so", "EVP_CIPHER_CTX_free");
    // Length accessors: resolved and called directly, never hooked (same pattern as EVP_PKEY_id).
    void *ckl = adh_resolve_sym("libcrypto.so", "EVP_CIPHER_CTX_key_length");
    void *cvl = adh_resolve_sym("libcrypto.so", "EVP_CIPHER_CTX_iv_length");
    if (cin) g_evp_cipher_init_orig = (EVP_CipherInit_ex_t)cin;
    if (cfr) g_evp_cipher_ctx_free_orig = (EVP_CIPHER_CTX_free_t)cfr;
    if (ckl) g_cipher_key_len = (cipher_ctx_len_t)ckl;
    if (cvl) g_cipher_iv_len  = (cipher_ctx_len_t)cvl;
    if (evp) g_evp_cipher_orig = (EVP_CipherUpdate_t)evp;
    if (dig) g_orig_evp_digest = (update3_t)dig;
    if (hm)  g_orig_hmac       = (update3_t)hm;
    if (dsu) g_orig_digest_sign= (update3_t)dsu;
    if (ow)  g_orig_ssl_write  = (SSL_rw_t)ow;
    if (orr) g_orig_ssl_read   = (SSL_rw_t)orr;
    // Signature/AEAD native GOT hooks (WS-A P0 coverage)
    void *pks = adh_resolve_sym("libcrypto.so", "ECDSA_sign");
    void *pkv = adh_resolve_sym("libcrypto.so", "ECDSA_verify");
    void *pke = adh_resolve_sym("libcrypto.so", "EVP_PKEY_encrypt");
    void *pkd = adh_resolve_sym("libcrypto.so", "EVP_PKEY_decrypt");
    void *aes = adh_resolve_sym("libcrypto.so", "EVP_AEAD_CTX_seal");
    void *aeo = adh_resolve_sym("libcrypto.so", "EVP_AEAD_CTX_open");
    // EVP_DigestSign/VerifyInit+Final (the actual Conscrypt SHA256withECDSA/RSA call path on
    // this device — see the dsign_ctx_* comment above); EVP_PKEY_id is a plain accessor, never hooked.
    void *dsi = adh_resolve_sym("libcrypto.so", "EVP_DigestSignInit");
    void *dvi = adh_resolve_sym("libcrypto.so", "EVP_DigestVerifyInit");
    void *dsf = adh_resolve_sym("libcrypto.so", "EVP_DigestSignFinal");
    void *dvu = adh_resolve_sym("libcrypto.so", "EVP_DigestVerifyUpdate");
    void *dvf = adh_resolve_sym("libcrypto.so", "EVP_DigestVerifyFinal");
    void *pid = adh_resolve_sym("libcrypto.so", "EVP_PKEY_id");
    if (pks) g_ecdsa_sign_orig   = (ECDSA_sign_t)pks;
    if (pkv) g_ecdsa_verify_orig = (ECDSA_verify_t)pkv;
    if (pke) g_pkey_encrypt_orig = (EVP_PKEY_crypt_t)pke;
    if (pkd) g_pkey_decrypt_orig = (EVP_PKEY_crypt_t)pkd;
    if (aes) g_aead_seal_orig = (aead_crypt_t)aes;
    if (aeo) g_aead_open_orig = (aead_crypt_t)aeo;
    if (dsi) g_orig_dsign_init   = (digest_sign_init_t)dsi;
    if (dvi) g_orig_dverify_init = (digest_sign_init_t)dvi;
    if (dsf) g_orig_dsign_final  = (digest_sign_final_t)dsf;
    if (dvu) g_orig_digest_verify= (update3_t)dvu;
    if (dvf) g_orig_dverify_final= (digest_verify_final_t)dvf;
    if (pid) g_evp_pkey_id_fn    = (EVP_PKEY_id_t)pid;
    // Persistent hooks in the crypto/TLS caller module's GOT (not restored — that's what makes
    // it "live"). g_crypto_mod from adhd; empty = scan ALL file-backed modules so we catch
    // whatever routes crypto (Conscrypt, cronet's BoringSSL, renamed libs), not just one.
    // Covers symmetric (EVP_CipherUpdate), digest (EVP_DigestUpdate), HMAC (HMAC_Update
    // and the EVP_PKEY HMAC path EVP_DigestSignUpdate), and TLS (SSL_read/write).
    strncpy(g_crypto_mod, (cryptoModule && cryptoModule[0]) ? cryptoModule : "", sizeof(g_crypto_mod)-1);
    g_crypto_mod[sizeof(g_crypto_mod)-1]=0;
    // Family gate (per-package policy). A group the policy turned off is never installed, and is
    // named in `skipped` so the daemon can keep installed/attempted meaning "what was asked for".
    // EVP_DigestSign* serves BOTH the JCA Mac (HMAC) and the PKEY signing path, so it belongs to
    // either family — it is installed when at least one of them is on.
    const int on_dig = g_families.digest, on_mac = g_families.hmac, on_sym = g_families.symmetric;
    const int on_asym = g_families.asymmetric, on_tls = g_families.tls, on_aead = g_families.aead;
    const int on_sys = g_families.system;
    const int on_dsign = (on_mac || on_asym) ? 1 : 0;
    char skipped[160]; skipped[0] = 0;
    if (!on_sym)   skip_add(skipped, sizeof(skipped), "evp,cipherInit,cipherCtxFree");
    if (!on_dig)   skip_add(skipped, sizeof(skipped), "digest");
    if (!on_mac)   skip_add(skipped, sizeof(skipped), "hmac");
    if (!on_dsign) skip_add(skipped, sizeof(skipped), "digestSign,digestSignVerify");
    if (!on_asym)  skip_add(skipped, sizeof(skipped), "pkey");
    if (!on_tls)   skip_add(skipped, sizeof(skipped), "sslWrite,sslRead");
    if (!on_aead)  skip_add(skipped, sizeof(skipped), "aead");
    if (!on_sys)   skip_add(skipped, sizeof(skipped), "sys");
    int re = (evp && capture_method_wanted(ADH_CM_CIPHER_UPDATE))   ? adh_capture_got_replace(g_crypto_mod, evp, (void *)my_EVP_CipherUpdate) : -1;
    int rd = (dig && capture_method_wanted(ADH_CM_DIGEST_UPDATE))   ? adh_capture_got_replace(g_crypto_mod, dig, (void *)my_EVP_DigestUpdate) : -1;
    int rh = (hm  && capture_method_wanted(ADH_CM_HMAC_UPDATE))   ? adh_capture_got_replace(g_crypto_mod, hm,  (void *)my_HMAC_Update) : -1;
    int rs = (dsu && capture_method_wanted(ADH_CM_SIGN_UPDATE)) ? adh_capture_got_replace(g_crypto_mod, dsu, (void *)my_EVP_DigestSignUpdate) : -1;
    // A named module often imports SSL_write from its own BoringSSL, not from system
    // libssl.so. Value-match only sees the system address, so the slot looks missing.
    // Name-match and call the pointer that was already in that slot.
    int rw = -1, rr = -1;
    if (on_tls && g_crypto_mod[0]) {
        void *old_w = NULL, *old_r = NULL;
        int nw = capture_method_wanted(ADH_CM_SSL_WRITE) ? adh_capture_got_replace_by_name_ex(g_crypto_mod, "SSL_write", (void *)my_SSL_write, NULL, &old_w, NULL, 0) : -1;
        int nr = capture_method_wanted(ADH_CM_SSL_READ) ? adh_capture_got_replace_by_name_ex(g_crypto_mod, "SSL_read", (void *)my_SSL_read, NULL, &old_r, NULL, 0) : -1;
        int w_ok = nw == 1 && old_w && old_w != (void *)my_SSL_write;
        int r_ok = nr == 1 && old_r && old_r != (void *)my_SSL_read;
        if (!w_ok && nw > 0) adh_capture_got_restore((void *)my_SSL_write);
        if (!r_ok && nr > 0) adh_capture_got_restore((void *)my_SSL_read);
        if (w_ok) { g_orig_ssl_write = (SSL_rw_t)old_w; rw = nw; }
        else if (ow && capture_method_wanted(ADH_CM_SSL_WRITE)) rw = adh_capture_got_replace(g_crypto_mod, ow, (void *)my_SSL_write);
        if (r_ok) { g_orig_ssl_read = (SSL_rw_t)old_r; rr = nr; }
        else if (orr && capture_method_wanted(ADH_CM_SSL_READ)) rr = adh_capture_got_replace(g_crypto_mod, orr, (void *)my_SSL_read);
    } else {
        rw = (ow && capture_method_wanted(ADH_CM_SSL_WRITE)) ? adh_capture_got_replace(g_crypto_mod, ow, (void *)my_SSL_write) : -1;
        rr = (orr && capture_method_wanted(ADH_CM_SSL_READ)) ? adh_capture_got_replace(g_crypto_mod, orr, (void *)my_SSL_read) : -1;
    }
    // Name-based, like the one-shot APIs below: a Cipher.init()/free() the app has not reached yet
    // leaves the PLT slot unbound, so value-match would silently report 0 for a genuinely imported
    // symbol.
    int rci = (cin && capture_method_wanted(ADH_CM_CIPHER_INIT))  ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_CipherInit_ex", (void *)my_EVP_CipherInit_ex) : -1;
    int rcf = (cfr && capture_method_wanted(ADH_CM_CIPHER_FREE))  ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_CIPHER_CTX_free", (void *)my_EVP_CIPHER_CTX_free) : -1;
    // Name-based install (see adh_got_replace_by_name): these 7 are one-shot BoringSSL APIs the
    // app may never have called before capture_start runs, so their PLT slot is typically
    // still unbound — value-match (adh_got_replace) would silently find 0 matching slots even
    // though the symbol is genuinely imported. Matching by the reloc entry's own symbol name
    // works regardless of bind state.
    int rpks = (pks && capture_method_wanted(ADH_CM_ECDSA_SIGN)) ? adh_capture_got_replace_by_name(g_crypto_mod, "ECDSA_sign", (void*)my_ECDSA_sign) : -1;
    int rpkv = (pkv && capture_method_wanted(ADH_CM_ECDSA_VERIFY)) ? adh_capture_got_replace_by_name(g_crypto_mod, "ECDSA_verify", (void*)my_ECDSA_verify) : -1;
    int rpke = (pke && capture_method_wanted(ADH_CM_PKEY_ENCRYPT)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_PKEY_encrypt", (void*)my_EVP_PKEY_encrypt) : -1;
    int rpkd = (pkd && capture_method_wanted(ADH_CM_PKEY_DECRYPT)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_PKEY_decrypt", (void*)my_EVP_PKEY_decrypt) : -1;
    int raes = (aes && capture_method_wanted(ADH_CM_AEAD_SEAL)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_seal", (void*)my_EVP_AEAD_CTX_seal) : -1;
    int raeo = (aeo && capture_method_wanted(ADH_CM_AEAD_OPEN)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_open", (void*)my_EVP_AEAD_CTX_open) : -1;
    int rdsi = (dsi && capture_method_wanted(ADH_CM_SIGN_INIT)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_DigestSignInit", (void*)my_EVP_DigestSignInit) : -1;
    int rdvi = (dvi && capture_method_wanted(ADH_CM_VERIFY_INIT)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyInit", (void*)my_EVP_DigestVerifyInit) : -1;
    int rdsf = (dsf && capture_method_wanted(ADH_CM_SIGN_FINAL)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_DigestSignFinal", (void*)my_EVP_DigestSignFinal) : -1;
    int rdvu = (dvu && capture_method_wanted(ADH_CM_VERIFY_UPDATE)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyUpdate", (void*)my_EVP_DigestVerifyUpdate) : -1;
    int rdvf = (dvf && capture_method_wanted(ADH_CM_VERIFY_FINAL)) ? adh_capture_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyFinal", (void*)my_EVP_DigestVerifyFinal) : -1;
    // The per-family verdict travels in the reply below (and in `skipped`), which is where the
    // caller reads it: -1 = skipped by policy, 0 = asked for but absent from this module, 1 = installed.

    // -- 文件: persistent file-I/O hooks in the module backing java.io (fileModule, from adhd;
    //    empty = skip so the agent never hardcodes a target module). Streams openat paths +
    //    read/write bytes into the same capture() ring (category=file on adhd). --
    int fo=-1, foa=-1, frd=-1, fwr=-1, fsc=-1, frc=-1, fwc=-1;
    if (fileModule && fileModule[0]) {
        strncpy(g_file_mod, fileModule, sizeof(g_file_mod)-1); g_file_mod[sizeof(g_file_mod)-1]=0;
        void *oo=adh_resolve_sym("libc.so","open"),   *ooa=adh_resolve_sym("libc.so","openat");
        void *ord=adh_resolve_sym("libc.so","read"),  *owr=adh_resolve_sym("libc.so","write");
        void *osc=adh_resolve_sym("libc.so","syscall");
        void *orc=adh_resolve_sym("libc.so","__read_chk"), *owv=adh_resolve_sym("libc.so","__write_chk");
        if (oo)  g_orig_open       = (open_t)oo;    if (ooa) g_orig_openat = (openat_t)ooa;
        if (ord) g_orig_read       = (rw_t)ord;     if (owr) g_orig_fwrite_sys = (rw_t)owr;
        if (osc) g_orig_syscall    = (syscall_t)osc;
        if (orc) g_orig_read_chk   = (read_chk_t)orc; if (owv) g_orig_write_chk = (write_chk_t)owv;
        fo  = (oo && capture_method_wanted(ADH_CM_OPEN))  ? adh_capture_got_replace(g_file_mod, oo,  (void *)my_open)     : -1;
        foa = (ooa && capture_method_wanted(ADH_CM_OPENAT)) ? adh_capture_got_replace(g_file_mod, ooa, (void *)my_openat)   : -1;
        frd = (ord && capture_method_wanted(ADH_CM_READ)) ? adh_capture_got_replace(g_file_mod, ord, (void *)my_read)     : -1;
        fwr = (owr && capture_method_wanted(ADH_CM_WRITE)) ? adh_capture_got_replace(g_file_mod, owr, (void *)my_write)    : -1;
        fsc = (osc && capture_method_wanted(ADH_CM_SYSCALL)) ? adh_capture_got_replace(g_file_mod, osc, (void *)my_syscall)  : -1;
        frc = (orc && capture_method_wanted(ADH_CM_READ_CHK)) ? adh_capture_got_replace(g_file_mod, orc, (void *)my_read_chk) : -1;
        fwc = (owv && capture_method_wanted(ADH_CM_WRITE_CHK)) ? adh_capture_got_replace(g_file_mod, owv, (void *)my_write_chk): -1;
    }
    // -- 系统: persistent detection/system-query hooks in each module named by sysModule
    //    (comma-separated, up to SYS_MOD_MAX). Observe-only. A repeat start restores the
    //    previous list first so a changed module list cannot leave a slot patched.
    //    Name-based install: these are exactly the calls a target may not have made yet, so
    //    the PLT slot can still be unbound and value-match finds nothing. --
    int sp=-1, sa=-1, sf=-1, sg=-1, sr=-1;
    int sys_truncated = 0;
    sys_restore();
    // Policy gate: Manager "系统检测" off → never patch, even if Host named a sysModule.
    const char *sys_mod_use = (on_sys && sysModule) ? sysModule : "";
    if (sys_mod_use[0]) {
        sys_mods_parse(sys_mod_use, &sys_truncated);
        void *op=adh_resolve_sym("libc.so","ptrace"), *oa=adh_resolve_sym("libc.so","access");
        void *ofa=adh_resolve_sym("libc.so","faccessat");
        void *og=adh_resolve_sym("libc.so","__system_property_get");
        void *ogr=adh_resolve_sym("libc.so","__system_property_read_callback");
        if (op) g_orig_ptrace = (ptrace_t)op;
        if (oa) g_orig_access = (access_t)oa;
        if (ofa) g_orig_faccessat = (faccessat_t)ofa;
        if (og) g_orig_prop = (prop_t)og;
        if (ogr) g_orig_prop_read = (prop_read_t)ogr;
        sp = op ? 0 : -1; sa = oa ? 0 : -1; sf = ofa ? 0 : -1; sg = og ? 0 : -1; sr = ogr ? 0 : -1;
        for (int i = 0; i < g_sys_nmods; i++) {
            const char *m = g_sys_mods[i];
            if (op && capture_method_wanted(ADH_CM_PTRACE)) sp = sys_sum(sp, adh_capture_got_replace_by_name(m, "ptrace", (void *)my_ptrace));
            if (oa && capture_method_wanted(ADH_CM_ACCESS)) sa = sys_sum(sa, adh_capture_got_replace_by_name(m, "access", (void *)my_access));
            if (ofa && capture_method_wanted(ADH_CM_FACCESSAT)) sf = sys_sum(sf, adh_capture_got_replace_by_name(m, "faccessat", (void *)my_faccessat));
            if (og && capture_method_wanted(ADH_CM_PROP_GET)) sg = sys_sum(sg, adh_capture_got_replace_by_name(m, "__system_property_get", (void *)my_prop));
            if (ogr && capture_method_wanted(ADH_CM_PROP_READ)) sr = sys_sum(sr, adh_capture_got_replace_by_name(m, "__system_property_read_callback", (void *)my_prop_read));
        }
    }
    g_method_results[ADH_CM_CIPHER_UPDATE] = !capture_method_wanted(ADH_CM_CIPHER_UPDATE) ? -1 : re < 0 ? -3 : re;
    g_method_results[ADH_CM_DIGEST_UPDATE] = !capture_method_wanted(ADH_CM_DIGEST_UPDATE) ? -1 : rd < 0 ? -3 : rd;
    g_method_results[ADH_CM_HMAC_UPDATE] = !capture_method_wanted(ADH_CM_HMAC_UPDATE) ? -1 : rh < 0 ? -3 : rh;
    g_method_results[ADH_CM_SIGN_UPDATE] = !capture_method_wanted(ADH_CM_SIGN_UPDATE) ? -1 : rs < 0 ? -3 : rs;
    g_method_results[ADH_CM_SSL_WRITE] = !capture_method_wanted(ADH_CM_SSL_WRITE) ? -1 : rw < 0 ? -3 : rw;
    g_method_results[ADH_CM_SSL_READ] = !capture_method_wanted(ADH_CM_SSL_READ) ? -1 : rr < 0 ? -3 : rr;
    g_method_results[ADH_CM_CIPHER_INIT] = !capture_method_wanted(ADH_CM_CIPHER_INIT) ? -1 : rci < 0 ? -3 : rci;
    g_method_results[ADH_CM_CIPHER_FREE] = !capture_method_wanted(ADH_CM_CIPHER_FREE) ? -1 : rcf < 0 ? -3 : rcf;
    g_method_results[ADH_CM_ECDSA_SIGN] = !capture_method_wanted(ADH_CM_ECDSA_SIGN) ? -1 : rpks < 0 ? -3 : rpks;
    g_method_results[ADH_CM_ECDSA_VERIFY] = !capture_method_wanted(ADH_CM_ECDSA_VERIFY) ? -1 : rpkv < 0 ? -3 : rpkv;
    g_method_results[ADH_CM_PKEY_ENCRYPT] = !capture_method_wanted(ADH_CM_PKEY_ENCRYPT) ? -1 : rpke < 0 ? -3 : rpke;
    g_method_results[ADH_CM_PKEY_DECRYPT] = !capture_method_wanted(ADH_CM_PKEY_DECRYPT) ? -1 : rpkd < 0 ? -3 : rpkd;
    g_method_results[ADH_CM_AEAD_SEAL] = !capture_method_wanted(ADH_CM_AEAD_SEAL) ? -1 : raes < 0 ? -3 : raes;
    g_method_results[ADH_CM_AEAD_OPEN] = !capture_method_wanted(ADH_CM_AEAD_OPEN) ? -1 : raeo < 0 ? -3 : raeo;
    g_method_results[ADH_CM_SIGN_INIT] = !capture_method_wanted(ADH_CM_SIGN_INIT) ? -1 : rdsi < 0 ? -3 : rdsi;
    g_method_results[ADH_CM_VERIFY_INIT] = !capture_method_wanted(ADH_CM_VERIFY_INIT) ? -1 : rdvi < 0 ? -3 : rdvi;
    g_method_results[ADH_CM_SIGN_FINAL] = !capture_method_wanted(ADH_CM_SIGN_FINAL) ? -1 : rdsf < 0 ? -3 : rdsf;
    g_method_results[ADH_CM_VERIFY_UPDATE] = !capture_method_wanted(ADH_CM_VERIFY_UPDATE) ? -1 : rdvu < 0 ? -3 : rdvu;
    g_method_results[ADH_CM_VERIFY_FINAL] = !capture_method_wanted(ADH_CM_VERIFY_FINAL) ? -1 : rdvf < 0 ? -3 : rdvf;
    g_method_results[ADH_CM_OPEN] = !capture_method_wanted(ADH_CM_OPEN) ? -1 : (!fileModule || !fileModule[0]) ? -4 : fo < 0 ? -3 : fo;
    g_method_results[ADH_CM_OPENAT] = !capture_method_wanted(ADH_CM_OPENAT) ? -1 : (!fileModule || !fileModule[0]) ? -4 : foa < 0 ? -3 : foa;
    g_method_results[ADH_CM_READ] = !capture_method_wanted(ADH_CM_READ) ? -1 : (!fileModule || !fileModule[0]) ? -4 : frd < 0 ? -3 : frd;
    g_method_results[ADH_CM_WRITE] = !capture_method_wanted(ADH_CM_WRITE) ? -1 : (!fileModule || !fileModule[0]) ? -4 : fwr < 0 ? -3 : fwr;
    g_method_results[ADH_CM_SYSCALL] = !capture_method_wanted(ADH_CM_SYSCALL) ? -1 : (!fileModule || !fileModule[0]) ? -4 : fsc < 0 ? -3 : fsc;
    g_method_results[ADH_CM_READ_CHK] = !capture_method_wanted(ADH_CM_READ_CHK) ? -1 : (!fileModule || !fileModule[0]) ? -4 : frc < 0 ? -3 : frc;
    g_method_results[ADH_CM_WRITE_CHK] = !capture_method_wanted(ADH_CM_WRITE_CHK) ? -1 : (!fileModule || !fileModule[0]) ? -4 : fwc < 0 ? -3 : fwc;
    g_method_results[ADH_CM_PTRACE] = !capture_method_wanted(ADH_CM_PTRACE) ? -1 : !g_sys_nmods ? -4 : sp < 0 ? -3 : sp;
    g_method_results[ADH_CM_ACCESS] = !capture_method_wanted(ADH_CM_ACCESS) ? -1 : !g_sys_nmods ? -4 : sa < 0 ? -3 : sa;
    g_method_results[ADH_CM_FACCESSAT] = !capture_method_wanted(ADH_CM_FACCESSAT) ? -1 : !g_sys_nmods ? -4 : sf < 0 ? -3 : sf;
    g_method_results[ADH_CM_PROP_GET] = !capture_method_wanted(ADH_CM_PROP_GET) ? -1 : !g_sys_nmods ? -4 : sg < 0 ? -3 : sg;
    g_method_results[ADH_CM_PROP_READ] = !capture_method_wanted(ADH_CM_PROP_READ) ? -1 : !g_sys_nmods ? -4 : sr < 0 ? -3 : sr;
    g_capture_on = 1;
    int fd_type = 0;
    socklen_t fd_type_len = sizeof(fd_type);
    if (fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &fd_type, &fd_type_len) == 0 && fd_type == SOCK_STREAM)
        adh_capture_sender_start(fd);
    char cmj[80], fmj[80], smj[640];
    json_escape(g_crypto_mod, cmj, sizeof(cmj));
    json_escape(fileModule ? fileModule : "", fmj, sizeof(fmj));
    json_escape(sys_mod_use, smj, sizeof(smj));
    char out[4096];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_start\",\"ok\":true,\"cryptoModule\":\"%s\",\"evp\":%d,\"cipherInit\":%d,\"cipherCtxFree\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d,"
        "\"pkey\":{\"sign\":%d,\"verify\":%d,\"encrypt\":%d,\"decrypt\":%d},"
        "\"aead\":{\"seal\":%d,\"open\":%d},"
        "\"digestSignVerify\":{\"signInit\":%d,\"verifyInit\":%d,\"signFinal\":%d,\"verifyUpdate\":%d,\"verifyFinal\":%d},"
        "\"fileModule\":\"%s\",\"file\":{\"open\":%d,\"openat\":%d,\"read\":%d,\"write\":%d,\"syscall\":%d,\"readChk\":%d,\"writeChk\":%d},"
        "\"sysModule\":\"%s\",\"sysModules\":%d,\"sysTruncated\":%s,\"sys\":{\"ptrace\":%d,\"access\":%d,\"faccessat\":%d,\"prop\":%d,\"propread\":%d},"
        "\"skipped\":\"%s\",\"on\":true}\n",
        idj, cmj, re, rci, rcf, rd, rh, rs, rw, rr,
        rpks, rpkv, rpke, rpkd, raes, raeo,
        rdsi, rdvi, rdsf, rdvu, rdvf,
        fmj, fo, foa, frd, fwr, fsc, frc, fwc, smj, g_sys_nmods, sys_truncated ? "true" : "false", sp, sa, sf, sg, sr, skipped);
    // fd < 0 would mean a caller with nobody waiting for the answer; no such caller exists today
    // (the self-arm path that used it was removed — see the note above adh_cmd_capture_start).
    if (fd >= 0) send_line(fd, out);
    LOGI("capture_start: crypto[%s] evp=%d dig=%d hmac=%d dsu=%d sslw=%d sslr=%d dsi=%d dvi=%d dsf=%d dvu=%d dvf=%d | file[%s] oa=%d sc=%d rc=%d wc=%d | sys n=%d p=%d a=%d fa=%d g=%d r=%d",
         g_crypto_mod, re, rd, rh, rs, rw, rr, rdsi, rdvi, rdsf, rdvu, rdvf, g_file_mod, foa, fsc, frc, fwc, g_sys_nmods, sp, sa, sf, sg, sr);
}

// Uninstall the persistent capture hooks and restore the original GOT pointers. Called by
// the capture_stop tool (after it drains the ring) and by the settings toggle. A caller that
// stops capture without draining first throws away whatever the ring still holds — which is
// why the tool drains.
void adh_cmd_capture_stop(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    adh_capture_sender_stop(0);
    int java_pending = 0;
#ifdef ADH_HAVE_LSPLANT
    java_pending = adh_java_crypto_stop();
#endif
    int restored[17]; capture_native_restore(restored);
    int e = restored[0];
    int w = restored[1];
    int r = restored[2];
    int dg = restored[3];
    int hm = restored[4];
    int ds = restored[5];
    int pks = restored[6];
    int pkv = restored[7];
    int pke = restored[8];
    int pkd = restored[9];
    int aes = restored[10];
    int aeo = restored[11];
    int dsi = restored[12];
    int dvi = restored[13];
    int dsf = restored[14];
    int dvu = restored[15];
    int dvf = restored[16];
    unsigned pending_slots = adh_capture_got_pending();
    g_capture_on = (pending_slots || java_pending) ? 1 : 0;
    if (!pending_slots) capture_method_results_reset();
    cap_reset();
    // Keys outlive a single Cipher only until capture stops; drop the table so a later capture_start
    // cannot stamp a stale key onto a fresh ctx that reused the same address.
    if (pthread_mutex_trylock(&g_key_lock) == 0) {
        memset(g_keys, 0, sizeof(g_keys));
        g_key_next = 0;
        pthread_mutex_unlock(&g_key_lock);
    }
    char out[700];
    snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_stop\",\"ok\":%s,\"on\":%s,\"pendingSlots\":%u,\"javaPending\":%d,\"restored\":{\"evp\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d,"
        "\"pkeySign\":%d,\"pkeyVerify\":%d,\"pkeyEncrypt\":%d,\"pkeyDecrypt\":%d,\"aeadSeal\":%d,\"aeadOpen\":%d,"
        "\"digestSignInit\":%d,\"digestVerifyInit\":%d,\"digestSignFinal\":%d,\"digestVerifyUpdate\":%d,\"digestVerifyFinal\":%d}}\n",
        idj, g_capture_on ? "false" : "true", g_capture_on ? "true" : "false", pending_slots, java_pending, e, dg, hm, ds, w, r, pks, pkv, pke, pkd, aes, aeo, dsi, dvi, dsf, dvu, dvf);
    if (fd >= 0) send_line(fd, out);
    LOGI("capture_stop: restored evp=%d sslw=%d sslr=%d", e, w, r);
}

// Drain (pop) up to a batch of ring records + rich Java records, and report HONEST WS-C
// stats: seq (total capture attempts), dropped/jdropped (never silent), backlog (still in
// ring), first/last drop ts. adhd streams the records and surfaces dropped>0 as
// complete:false. Buffer grows as needed (the old fixed 64KB could overflow with a full ring).
void adh_cmd_capture_drain(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const int DRAIN_BATCH = 512;   // bound one response; adhd polls again to clear the backlog
    const int maxBatch = CAP_RING < DRAIN_BATCH ? CAP_RING : DRAIN_BATCH;
    struct CapRec *capcopy = malloc(sizeof(*capcopy) * (size_t)maxBatch);
    struct JCapRec *jcopy = malloc(sizeof(*jcopy) * JCAP_MAX);
    if (!capcopy || !jcopy) {
        free(capcopy); free(jcopy);
        send_oom(fd, idj, "capture_drain");
        return;
    }

    // Pop/copy under the lock, serialize after releasing it. The producer path uses trylock
    // and counts a busy lock as a drop; hex-formatting a full ring while holding g_cap_lock
    // made the drain itself the dropout source. Copying the bounded ring is orders of
    // magnitude cheaper than serializing it, and leaves the invariant unchanged.
    pthread_mutex_lock(&g_cap_lock);
    int ncaps = 0;
    while (g_ring_count > 0 && ncaps < maxBatch) {
        struct CapRec *src = &g_ring[g_ring_tail];
        struct CapRec *dst = &capcopy[ncaps++];
        memcpy(dst, src, offsetof(struct CapRec, data));
        memcpy(dst->data, src->data, (size_t)src->n);
        g_ring_tail = (g_ring_tail + 1) % CAP_RING;
        g_ring_count--;
    }
    if (ncaps > 0) __atomic_add_fetch(&g_cap_drained, (unsigned long long)ncaps, __ATOMIC_RELAXED);
    int backlog = g_ring_count + (int)__atomic_load_n(&g_cap_queued, __ATOMIC_RELAXED);
    unsigned long long queued = __atomic_load_n(&g_cap_queued, __ATOMIC_RELAXED);
    unsigned long long queued_seq = queued ? __atomic_load_n(&g_cap_queued_seq, __ATOMIC_RELAXED) : 0;
    unsigned long long seq = __atomic_load_n(&g_cap_seq, __ATOMIC_RELAXED);
    unsigned long long drained = __atomic_load_n(&g_cap_drained, __ATOMIC_RELAXED);
    unsigned long long dropped = __atomic_load_n(&g_cap_dropped, __ATOMIC_RELAXED);
    unsigned long long jdropped = __atomic_load_n(&g_jcap_dropped, __ATOMIC_RELAXED);
    long long fdrop = g_cap_first_drop_ns, ldrop = g_cap_last_drop_ns;
    int njcaps = 0;
    while (g_njcaps > 0) {
        struct JCapRec *src = &g_jcaps[g_jcap_tail];
        struct JCapRec *dst = &jcopy[njcaps++];
        memcpy(dst, src, offsetof(struct JCapRec, in));
        memcpy(dst->in, src->in, (size_t)src->nin);
        memcpy(dst->out, src->out, (size_t)src->nout);
        g_jcap_tail = (g_jcap_tail + 1) % JCAP_MAX;
        g_njcaps--;
    }
    unsigned long long frame_seq = ++g_cap_frame_seq;
    pthread_mutex_unlock(&g_cap_lock);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap);
    if (!out) {
        free(capcopy); free(jcopy);
        send_oom(fd, idj, "capture_drain");
        return;
    }
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_drain\",\"ok\":true,\"on\":%s,\"captures\":[",
        idj, g_capture_on ? "true" : "false");
    for (int i = 0; i < ncaps; i++) {
        // One record is up to CAP_BYTES of hex (two chars each) plus the JSON wrapper.
        // Growing by a flat 4200 truncated the second TLS record in a batch, which then
        // looked like a short body and broke HTTP reassembly on the host.
        if (len + (size_t)CAP_BYTES * 2 + 1024 > cap) {
            size_t nc = cap * 2;
            while (len + (size_t)CAP_BYTES * 2 + 1024 > nc) nc *= 2;
            char *no = realloc(out, nc); if (!no) break; out = no; cap = nc;
        }
        len = emit_caprec(out, len, cap, &capcopy[i], i == 0);
    }
    // rich Java-layer records: algorithm + op + key + iv + input + output
    len += snprintf(out + len, cap > len ? cap - len : 0, "],\"jcaptures\":[");
    for (int k = 0; k < njcaps; k++) {
        if (len + JCAP_RECORD_RESERVE > cap) { size_t nc = cap * 2; char *no = realloc(out, nc); if (!no) break; out = no; cap = nc; }
        len = emit_jcaprec(out, len, cap, &jcopy[k], k == 0);
    }
    snprintf(out + len, cap > len ? cap - len : 0,
        "],\"count\":%d,\"jcount\":%d,\"frameSeq\":%llu,\"backlog\":%d,\"queued\":%llu,\"queuedSeq\":%llu,\"seq\":%llu,\"dropped\":%llu,\"jdropped\":%llu,"
        "\"drained\":%llu,\"residual\":%lld,\"firstDropNs\":%lld,\"lastDropNs\":%lld,\"ring\":%d,\"complete\":%s,\"javaActive\":%s}\n",
        ncaps, njcaps, frame_seq, backlog, queued, queued_seq, seq, dropped, jdropped, drained,
        (long long)seq - (long long)drained - (long long)backlog - (long long)dropped,
        fdrop, ldrop, CAP_RING,
        (dropped == 0 && jdropped == 0) ? "true" : "false", g_java_active ? "true" : "false");
    send_line(fd, out);
    free(out);
    free(capcopy);
    free(jcopy);
}

// The system/detection observation used to have a one-shot op (detect_watch). It is gone:
// capture_start installs the GOT hooks (by name, on every module the caller names) and
// streams them as category=system. The host turns those lines into the detection summary.
// The caller triggers the workload through java_call.
//
// The inline-hook self-test op (inline_crypto_test) is gone too: native_hook mode=inline is
// the tool-level path, and it takes module/symbol from the caller.

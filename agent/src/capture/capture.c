// Runtime capture policy, wrappers, bounded buffers, and focused probe commands.

#include "capture.h"
#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "../runtime/jni.h"
#ifdef ADH_HAVE_INLINE_HOOK
#include "../hook/native_inline.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/system_properties.h>
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
#define CAP_BYTES 2048
#define CAP_RING  1024          // ~2 MiB; bounded agent memory (architecture red line)
struct CapRec { char func[24]; int inl; int n; int tid; long long ts_ns; unsigned char data[CAP_BYTES]; };
static struct CapRec g_ring[CAP_RING];
static int g_ring_head = 0, g_ring_tail = 0, g_ring_count = 0;   // ring: head=write, tail=read (under g_cap_lock)
static unsigned long long g_cap_seq = 0;       // total capture() attempts — ATOMIC (read/written off-lock)
static unsigned long long g_cap_dropped = 0;   // total dropped (ring full or lock busy) — ATOMIC
static long long g_cap_first_drop_ns = 0, g_cap_last_drop_ns = 0;   // best-effort diagnostic ts
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;
static void capture(const char *func, const unsigned char *in, int inl) {
    if (inl <= 0 || !in) return;
    // Runs on the target's own crypto/TLS thread — must NEVER block or sleep here (any
    // injected latency is an ANR risk and a timing-based anti-debug surface). Count every
    // attempt atomically, then TRY the lock without waiting: if a drain or another producer
    // holds it, account a drop and return immediately instead of stalling the target.
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
        r->tid = (int)gettid(); r->ts_ns = ts;
        memcpy(r->data, in, r->n);
        g_ring_head = (g_ring_head + 1) % CAP_RING;
        g_ring_count++;
    } else {
        __atomic_add_fetch(&g_cap_dropped, 1, __ATOMIC_RELAXED);
        if (!g_cap_first_drop_ns) g_cap_first_drop_ns = ts;
        g_cap_last_drop_ns = ts;
    }
    pthread_mutex_unlock(&g_cap_lock);
}

// Empty the ring (used by the one-shot probes in place of the old `g_ncaps = 0`). Discarded
// in-ring records are rolled into g_cap_dropped (see below); cumulative seq is never touched.
static void cap_reset(void) {
    pthread_mutex_lock(&g_cap_lock);
    // Records still in the ring are being discarded (a one-shot probe / capture_stop clears
    // stale captures before re-arming). They were counted in g_cap_seq but will never be
    // emitted — account them as dropped so the invariant emitted+backlog+dropped==seq holds
    // (WS-C: nothing vanishes silently). Without this, each reset-with-backlog leaks the
    // in-ring count from the accounting permanently (verify_v22 caught a stable off-by-N).
    if (g_ring_count > 0) __atomic_add_fetch(&g_cap_dropped, (unsigned long long)g_ring_count, __ATOMIC_RELAXED);
    g_ring_head = g_ring_tail = g_ring_count = 0;
    pthread_mutex_unlock(&g_cap_lock);
}
// Emit one record as a JSON object into (out,len,cap); returns new len. Underflow-safe
// (cap>len?cap-len:0 guards snprintf's would-be-length return that the old loops mishandled).
static size_t emit_caprec(char *out, size_t len, size_t cap, const struct CapRec *r, int first) {
    len += snprintf(out + len, cap > len ? cap - len : 0,
        "%s{\"func\":\"%s\",\"inl\":%d,\"tid\":%d,\"tsNs\":%lld,\"hex\":\"", first ? "" : ",", r->func, r->inl, r->tid, r->ts_ns);
    for (int b = 0; b < r->n && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->data[b]);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\"}");
    return len;
}
// Serialize (without popping) every record currently in the ring, tail→head. Used by the
// one-shot probes, which reset → trigger → serialize, producing far fewer than CAP_RING.
// Returns count emitted; *lenp updated. Caller holds no lock (we take it).
static int cap_emit_all(char *out, size_t *lenp, size_t cap) {
    pthread_mutex_lock(&g_cap_lock);
    int n = 0;
    for (int i = 0; i < g_ring_count; i++) {
        struct CapRec *r = &g_ring[(g_ring_tail + i) % CAP_RING];
        *lenp = emit_caprec(out, *lenp, cap, r, n == 0);
        n++;
    }
    pthread_mutex_unlock(&g_cap_lock);
    return n;
}

typedef int (*EVP_CipherUpdate_t)(void *, unsigned char *, int *, const unsigned char *, int);
static EVP_CipherUpdate_t g_evp_cipher_orig = NULL;
static int my_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    capture("EVP_CipherUpdate", in, inl);
    return g_evp_cipher_orig(ctx, out, outl, in, inl);
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

static int my_EVP_DigestSignUpdate(void *ctx, const void *data, size_t len) {
    capture(dsign_ctx_get(ctx) ? "EVP_DSignUpdate_asym" : "EVP_DigestSignUpdate", (const unsigned char *)data, (int)len);
    return g_orig_digest_sign(ctx, data, len);
}

typedef int (*digest_sign_final_t)(void *ctx, unsigned char *sig, size_t *sig_len);
static digest_sign_final_t g_orig_dsign_final = NULL;
static int my_EVP_DigestSignFinal(void *ctx, unsigned char *sig, size_t *sig_len) {
    int rc = g_orig_dsign_final(ctx, sig, sig_len);
    if (rc == 1 && sig && sig_len && dsign_ctx_get(ctx)) capture("EVP_DSignFinal_sig", sig, (int)*sig_len);  // skip the sig==NULL length-query call
    return rc;
}

static update3_t g_orig_digest_verify = NULL;
static int my_EVP_DigestVerifyUpdate(void *ctx, const void *data, size_t len) {
    capture(dsign_ctx_get(ctx) ? "EVP_DVerifyUpdate_asym" : "EVP_DigestVerifyUpdate", (const unsigned char *)data, (int)len);
    return g_orig_digest_verify(ctx, data, len);
}

typedef int (*digest_verify_final_t)(void *ctx, const unsigned char *sig, size_t sig_len);
static digest_verify_final_t g_orig_dverify_final = NULL;
static int my_EVP_DigestVerifyFinal(void *ctx, const unsigned char *sig, size_t sig_len) {
    if (dsign_ctx_get(ctx) && sig) capture("EVP_DVerifyFinal_sig", sig, (int)sig_len);   // presented signature, captured regardless of pass/fail
    return g_orig_dverify_final(ctx, sig, sig_len);
}

// ---- Signature (RSA/ECDSA) + AEAD (GCM/ChaCha20-Poly1305) ----
// 原生 GOT hook，标准 BoringSSL 导出符号；这些是当前能跨设备工作的原生可 hook 子集。

// EVP_PKEY_sign/verify are NOT imported by libjavacrypto.so at all (confirmed via
// `llvm-readelf --dyn-syms` against the on-device Conscrypt native lib) — Android's
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
    for (int i = 0; i < NF; i++) len += snprintf(out + len, cap - len, "%s\"%s\":\"%llx\"", i?",":"", names[i], (unsigned long long)addrs[i]);
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

// Recon: which modules' GOT holds the EVP/HMAC/SSL pointers (candidate crypto hook sites).
void adh_cmd_crypto_probe(int fd, const char *id) {
    const char *names[] = { "EVP_CipherUpdate", "EVP_EncryptUpdate", "EVP_DecryptUpdate", "EVP_DigestUpdate", "HMAC_Update", "SSL_read", "SSL_write" };
    void *addrs[7];
    for (int i = 0; i < 5; i++) addrs[i] = adh_resolve_sym("libcrypto.so", names[i]);
    addrs[5] = adh_resolve_sym("libssl.so", "SSL_read");
    addrs[6] = adh_resolve_sym("libssl.so", "SSL_write");
    got_probe(fd, id, "crypto_probe", names, addrs, 7);
}

// ---- network TLS-plaintext capture (SSL_read/SSL_write in libjavacrypto/Conscrypt) ----
typedef int (*SSL_rw_t)(void *, void *, int);
static SSL_rw_t g_orig_ssl_write = NULL, g_orig_ssl_read = NULL;
static int my_SSL_write(void *ssl, void *buf, int num) {
    if (num > 0) capture("SSL_write", (const unsigned char *)buf, num);   // outgoing plaintext
    return g_orig_ssl_write(ssl, buf, num);
}
static int my_SSL_read(void *ssl, void *buf, int num) {
    int ret = g_orig_ssl_read(ssl, buf, num);
    if (ret > 0) capture("SSL_read", (const unsigned char *)buf, ret);    // incoming plaintext
    return ret;
}

// Hook SSL_write/SSL_read in Conscrypt, trigger an HTTPS request via JNI reflection,
// and report the captured TLS plaintext (request + response).
void adh_cmd_net_hook_test(int fd, const char *id, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *ow = adh_resolve_sym("libssl.so", "SSL_write");
    void *orr = adh_resolve_sym("libssl.so", "SSL_read");
    g_orig_ssl_write = (SSL_rw_t)ow; g_orig_ssl_read = (SSL_rw_t)orr;
    int rw = ow ? adh_got_replace("libjavacrypto.so", ow, (void *)my_SSL_write) : -1;
    int rr = orr ? adh_got_replace("libjavacrypto.so", orr, (void *)my_SSL_read) : -1;
    cap_reset();

    int did = 0, triggered = 0; char result[128] = "";
    JNIEnv *env = adh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = className[0] ? adh_jni_load_app_class(env, className) : NULL;
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did);
    }
    if (rw > 0) adh_got_replace("libjavacrypto.so", (void *)my_SSL_write, ow);
    if (rr > 0) adh_got_replace("libjavacrypto.so", (void *)my_SSL_read, orr);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "net_hook_test"); return; }
    char rj[200]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"net_hook_test\",\"ok\":true,\"hooked\":{\"write\":%d,\"read\":%d},\"triggered\":%s,\"result\":\"%s\",\"captures\":[", idj, rw, rr, triggered ? "true" : "false", rj);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("net_hook_test: hooked w=%d r=%d triggered=%d result=%s captures=%d", rw, rr, triggered, result, n);
}

// ---- file I/O capture (open/openat/read/write/close via a caller module's GOT) ----
// Which module's GOT actually holds these libc pointers for Java FileInputStream/
// FileOutputStream varies by ART/API level (libopenjdk.so on modern Android) — use
// adh_cmd_file_probe to discover it empirically rather than hardcoding a guess.
typedef int (*open_t)(const char *, int, mode_t);
typedef int (*openat_t)(int, const char *, int, mode_t);
typedef ssize_t (*rw_t)(int, void *, size_t);
typedef int (*fclose_t)(int);
static open_t g_orig_open = NULL;
static openat_t g_orig_openat = NULL;
static rw_t g_orig_read = NULL;
static rw_t g_orig_fwrite_sys = NULL;
static fclose_t g_orig_fclose = NULL;
static volatile int g_file_close_hits = 0;

// arm64 ABI always passes a 3rd arg in a register even when the call site omits it
// (open()/openat() only read it when O_CREAT/O_TMPFILE is set) — always read+forward it.
static int my_open(const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (pathname) capture("open", (const unsigned char *)pathname, (int)strlen(pathname));
    return g_orig_open(pathname, flags, mode);
}
static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (pathname) capture("openat", (const unsigned char *)pathname, (int)strlen(pathname));
    return g_orig_openat(dirfd, pathname, flags, mode);
}
static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret = g_orig_read(fd, buf, count);
    if (ret > 0) capture("read", (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (count > 0) capture("write", (const unsigned char *)buf, (int)count);
    return g_orig_fwrite_sys(fd, (void *)buf, count);
}
static int my_file_close(int fd) {
    __atomic_add_fetch(&g_file_close_hits, 1, __ATOMIC_RELAXED);
    return g_orig_fclose(fd);
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
    if (number == __NR_openat) {
        const char *path = (const char *)a2;
        if (path) capture("openat", (const unsigned char *)path, (int)strlen(path));
    } else if (number == __NR_write) {
        if (a3 > 0) capture("write", (const unsigned char *)a2, (int)a3);
    }
    long ret = g_orig_syscall(number, a1, a2, a3, a4, a5, a6);
    if (number == __NR_read && ret > 0) {
        capture("read", (const unsigned char *)a2, (int)ret);
    } else if (number == __NR_close) {
        __atomic_add_fetch(&g_file_close_hits, 1, __ATOMIC_RELAXED);
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
    if (ret > 0) capture("read", (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write_chk(int fd, const void *buf, size_t count, size_t buflen) {
    if (count > 0) capture("write", (const unsigned char *)buf, (int)count);
    return g_orig_write_chk(fd, buf, count, buflen);
}

// Recon: for open/openat/read/write/close (libc.so), report which loaded modules'
// GOT holds each pointer (candidate hook sites) — mirrors adh_cmd_crypto_probe.
// Recon: which modules' GOT holds the libc file-I/O pointers (candidate file hook sites).
void adh_cmd_file_probe(int fd, const char *id) {
    const char *names[] = { "open", "openat", "read", "write", "close" };
    void *addrs[5];
    for (int i = 0; i < 5; i++) addrs[i] = adh_resolve_sym("libc.so", names[i]);
    got_probe(fd, id, "file_probe", names, addrs, 5);
}

// Hook open/openat/read/write/close in `module` (from adhd; discover it via adh_cmd_file_probe —
// no default, the agent never guesses a target module), trigger the target's file workload
// class (className, from adhd) via JNI reflection, and report captured paths + read/write bytes.
void adh_cmd_file_hook_test(int fd, const char *id, const char *module, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    // No hardcoded target module: adhd passes which loaded module's GOT backs java.io
    // (discover it via file_probe). Empty -> fail-loud rather than guess a device-specific lib.
    if (!module || !module[0]) { char e[220]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"file_hook_test\",\"ok\":false,\"error\":\"need module (which loaded module backs java.io; discover via file_probe)\"}\n", idj); send_line(fd, e); return; }
    const char *mod = module;
    void *oo  = adh_resolve_sym("libc.so", "open");
    void *ooa = adh_resolve_sym("libc.so", "openat");
    void *ord = adh_resolve_sym("libc.so", "read");
    void *owr = adh_resolve_sym("libc.so", "write");
    void *ocl = adh_resolve_sym("libc.so", "close");
    void *osc = adh_resolve_sym("libc.so", "syscall");
    void *orc = adh_resolve_sym("libc.so", "__read_chk");
    void *owv = adh_resolve_sym("libc.so", "__write_chk");
    g_orig_open = (open_t)oo; g_orig_openat = (openat_t)ooa;
    g_orig_read = (rw_t)ord; g_orig_fwrite_sys = (rw_t)owr; g_orig_fclose = (fclose_t)ocl;
    g_orig_syscall = (syscall_t)osc;
    g_orig_read_chk = (read_chk_t)orc; g_orig_write_chk = (write_chk_t)owv;

    int ro  = oo  ? adh_got_replace(mod, oo,  (void *)my_open)  : -1;
    int roa = ooa ? adh_got_replace(mod, ooa, (void *)my_openat) : -1;
    int rr  = ord ? adh_got_replace(mod, ord, (void *)my_read)  : -1;
    int rw  = owr ? adh_got_replace(mod, owr, (void *)my_write) : -1;
    int rc  = ocl ? adh_got_replace(mod, ocl, (void *)my_file_close) : -1;
    int rsc = osc ? adh_got_replace(mod, osc, (void *)my_syscall) : -1;
    int rrc = orc ? adh_got_replace(mod, orc, (void *)my_read_chk) : -1;
    int rwv = owv ? adh_got_replace(mod, owv, (void *)my_write_chk) : -1;
    cap_reset();
    g_file_close_hits = 0;

    int did = 0, triggered = 0; char result[160] = "";
    JNIEnv *env = adh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = className[0] ? adh_jni_load_app_class(env, className) : NULL;
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did);
    }

    if (ro  > 0) adh_got_replace(mod, (void *)my_open,       oo);
    if (roa > 0) adh_got_replace(mod, (void *)my_openat,     ooa);
    if (rr  > 0) adh_got_replace(mod, (void *)my_read,       ord);
    if (rw  > 0) adh_got_replace(mod, (void *)my_write,      owr);
    if (rc  > 0) adh_got_replace(mod, (void *)my_file_close, ocl);
    if (rsc > 0) adh_got_replace(mod, (void *)my_syscall,    osc);
    if (rrc > 0) adh_got_replace(mod, (void *)my_read_chk,   orc);
    if (rwv > 0) adh_got_replace(mod, (void *)my_write_chk,  owv);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "file_hook_test"); return; }
    char modj[64]; json_escape(mod, modj, sizeof(modj));
    char rj[220]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"file_hook_test\",\"ok\":true,\"module\":\"%s\","
        "\"hooked\":{\"open\":%d,\"openat\":%d,\"read\":%d,\"write\":%d,\"close\":%d,\"syscall\":%d,\"readChk\":%d,\"writeChk\":%d},"
        "\"triggered\":%s,\"result\":\"%s\",\"closeHits\":%d,\"captures\":[",
        idj, modj, ro, roa, rr, rw, rc, rsc, rrc, rwv, triggered ? "true" : "false", rj, g_file_close_hits);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("file_hook_test: mod=%s hooked o=%d oa=%d r=%d w=%d c=%d sc=%d triggered=%d captures=%d", mod, ro, roa, rr, rw, rc, rsc, triggered, n);
}

// Correlation flow: hook BOTH EVP_CipherUpdate (encrypt) and SSL_write (send) at
// once, trigger an encrypt-then-send flow, and return all captures with tid+ts so
// adhd can correlate "this plaintext was encrypted then sent" (取证闭环).
void adh_cmd_flow_watch(int fd, const char *id, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *oe = adh_resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    void *ow = adh_resolve_sym("libssl.so", "SSL_write");
    g_evp_cipher_orig = (EVP_CipherUpdate_t)oe;
    g_orig_ssl_write = (SSL_rw_t)ow;
    int re = oe ? adh_got_replace("libjavacrypto.so", oe, (void *)my_EVP_CipherUpdate) : -1;
    int rw = ow ? adh_got_replace("libjavacrypto.so", ow, (void *)my_SSL_write) : -1;
    cap_reset();

    int did = 0, triggered = 0; char result[128] = "";
    JNIEnv *env = adh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = className[0] ? adh_jni_load_app_class(env, className) : NULL;
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did);
    }
    if (re > 0) adh_got_replace("libjavacrypto.so", (void *)my_EVP_CipherUpdate, oe);
    if (rw > 0) adh_got_replace("libjavacrypto.so", (void *)my_SSL_write, ow);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "flow_watch"); return; }
    char rj[200]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"flow_watch\",\"ok\":true,\"hooked\":{\"evp\":%d,\"sslWrite\":%d},\"triggered\":%s,\"result\":\"%s\",\"captures\":[", idj, re, rw, triggered ? "true" : "false", rj);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("flow_watch: hooked evp=%d ssl=%d triggered=%d captures=%d", re, rw, triggered, n);
}

// Install EVP_CipherUpdate GOT hook in libjavacrypto (Conscrypt), trigger the
// sandbox's AES via JNI reflection, and return what plaintext the wrapper captured.
void adh_cmd_crypto_hook_test(int fd, const char *id, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *orig = adh_resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    g_evp_cipher_orig = (EVP_CipherUpdate_t)orig;
    int replaced = orig ? adh_got_replace("libjavacrypto.so", orig, (void *)my_EVP_CipherUpdate) : -1;
    cap_reset();

    // trigger the target's crypto workload class (className, from adhd) via the app classloader
    int did = 0, triggered = 0;
    JNIEnv *env = adh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass jc = className[0] ? adh_jni_load_app_class(env, className) : NULL;
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()V");
            if (run) { (*env)->CallStaticVoidMethod(env, jc, run); triggered = 1; }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did);
    }

    // unhook (restore) before building reply
    if (replaced > 0 && orig) adh_got_replace("libjavacrypto.so", (void *)my_EVP_CipherUpdate, orig);

    // build reply with captured records (hex)
    size_t cap = 1 << 15, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "crypto_hook_test"); return; }
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"crypto_hook_test\",\"ok\":true,\"replaced\":%d,\"triggered\":%s,\"captures\":[", idj, replaced, triggered ? "true" : "false");
    int ncaps = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", ncaps);
    send_line(fd, out);
    free(out);
    LOGI("crypto_hook_test: replaced=%d triggered=%d captures=%d", replaced, triggered, ncaps);
}

// ---- Java-layer rich capture: an interposing JCE provider (installed by the target/self-test
//      app) reports every Cipher/Mac/MessageDigest op here with algorithm+op+key+iv+input+output.
//      Bound at capture_start via RegisterNatives to the reporter class adhd names (target-agnostic;
//      no sandbox-specific JNI symbol). ----------------------------------------------------------
#define JCAP_MAX 96
#define JCAP_KEY 64
#define JCAP_IV 32
#define JCAP_DATA 1024
struct JCapRec {
    char algo[56], op[16]; int tid; long long ts_ns;
    int nkey, niv, nin, nout;
    unsigned char key[JCAP_KEY], iv[JCAP_IV], in[JCAP_DATA], out[JCAP_DATA];
};
static struct JCapRec g_jcaps[JCAP_MAX];
static int g_njcaps = 0;
static unsigned long long g_jcap_dropped = 0;   // WS-C: honest drop accounting (Java rich path)
static volatile int g_java_active = 0;

static int copy_jba(JNIEnv *env, jbyteArray a, unsigned char *dst, int cap) {
    if (!a) return 0;
    jsize n = (*env)->GetArrayLength(env, a);
    if (n <= 0) return 0;
    if (n > cap) n = cap;
    (*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)dst);
    return (int)n;
}

// nReport implementation. Registered onto the target's reporter class at capture_start
// (adh_capture_register_reporter) — no hardcoded JNI symbol ties the agent to any package.
static void adh_nreport_impl(
        JNIEnv *env, jclass cls, jstring jalgo, jstring jop,
        jbyteArray jkey, jbyteArray jiv, jbyteArray jin, jbyteArray jout) {
    (void)cls;
    g_java_active = 1;
    // Runs on the target's crypto thread — non-blocking like capture(): try the lock, and on
    // contention account a drop instead of stalling the target.
    if (pthread_mutex_trylock(&g_cap_lock) != 0) {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    if (g_njcaps < JCAP_MAX) {
        struct JCapRec *r = &g_jcaps[g_njcaps++];
        memset(r, 0, sizeof(*r));
        const char *a = jalgo ? (*env)->GetStringUTFChars(env, jalgo, NULL) : NULL;
        const char *o = jop ? (*env)->GetStringUTFChars(env, jop, NULL) : NULL;
        if (a) { strncpy(r->algo, a, sizeof(r->algo) - 1); (*env)->ReleaseStringUTFChars(env, jalgo, a); }
        if (o) { strncpy(r->op, o, sizeof(r->op) - 1); (*env)->ReleaseStringUTFChars(env, jop, o); }
        r->tid = (int)gettid();
        r->ts_ns = now_ns();
        r->nkey = copy_jba(env, jkey, r->key, JCAP_KEY);
        r->niv  = copy_jba(env, jiv,  r->iv,  JCAP_IV);
        r->nin  = copy_jba(env, jin,  r->in,  JCAP_DATA);
        r->nout = copy_jba(env, jout, r->out, JCAP_DATA);
    } else {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);   // fail-loud, reported via drain
    }
    pthread_mutex_unlock(&g_cap_lock);
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
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return (r == 0) ? 1 : 0;
}

// ---- anti-analysis / system-info hooks (module V) — defined here (above capture_start)
//      so the persistent capture path can install them. GOT-hook the target's own
//      detection / system-query calls to see WHAT it checks for, and stream each event into
//      the unified capture() ring so the 系统 panel fills live (not just one-shot
//      detect_watch). Defeating (returning fake values) is opt-in via g_defeat_ptrace —
//      default off = pure observation (CLAUDE.md: no self-hiding by default). ----
struct DetRec { char cat[16]; char detail[160]; };
static struct DetRec g_dets[64];
static int g_ndets = 0;
static pthread_mutex_t g_det_lock = PTHREAD_MUTEX_INITIALIZER;
static void det_record(const char *cat, const char *detail) {
    pthread_mutex_lock(&g_det_lock);
    if (g_ndets < 64) { struct DetRec *r = &g_dets[g_ndets++];
        strncpy(r->cat, cat, sizeof(r->cat) - 1); r->cat[sizeof(r->cat)-1]=0;
        strncpy(r->detail, detail, sizeof(r->detail) - 1); r->detail[sizeof(r->detail)-1]=0; }
    pthread_mutex_unlock(&g_det_lock);
}
static int g_defeat_ptrace = 0;   // 0 = observe only; 1 = neutralize TRACEME (opt-in resilience)

typedef long (*ptrace_t)(int, void *, void *, void *);
static ptrace_t g_orig_ptrace = NULL;
static long my_ptrace(int req, void *a, void *b, void *c) {
    char d[64]; snprintf(d, sizeof(d), "ptrace(request=%d%s)", req, req == 0 ? " PTRACE_TRACEME" : "");
    det_record("debug", d);
    capture("ptrace", (const unsigned char *)d, (int)strlen(d));
    if (req == 0 && g_defeat_ptrace) return 0;   // neutralize TRACEME only when defeat opt-in
    return g_orig_ptrace(req, a, b, c);
}
typedef int (*access_t)(const char *, int);
static access_t g_orig_access = NULL;
static int my_access(const char *p, int m) {
    if (p) { det_record(strstr(p, "su") ? "root" : "file", p);
             capture("access", (const unsigned char *)p, (int)strlen(p)); }
    return g_orig_access(p, m);
}
typedef int (*prop_t)(const char *, char *);
static prop_t g_orig_prop = NULL;
static int my_prop(const char *name, char *value) {
    det_record("prop", name ? name : "?");
    if (name) capture("sysprop", (const unsigned char *)name, (int)strlen(name));  // 读手机信息 ro.*
    return g_orig_prop(name, value);
}

// Persistent-hook target modules (from adhd's capture_start params) — remembered so
// capture_stop restores the exact GOT it patched. Empty = that category not installed.
static char g_file_mod[64] = "";
static char g_sys_mod[64] = "";
// crypto/TLS caller module whose GOT holds the EVP/SSL pointers. Empty = scan ALL file-backed
// modules (default): catches Conscrypt (libjavacrypto) AND non-Conscrypt BoringSSL callers
// (cronet's bundled copy, renamed/statically-linked libs). adhd may pass a specific module.
static char g_crypto_mod[64] = "";

// ---- continuous capture: install persistent EVP+SSL hooks, drain accumulated records
//      periodically from adhd (mirrors the ios-decrypt-helper log-store model: hooks
//      stay installed and events stream to the panel, instead of one-shot triggers) ----
static int g_capture_on = 0;
void adh_cmd_capture_start(int fd, const char *id, const char *cryptoModule, const char *fileModule, const char *sysModule) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *evp = adh_resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    void *dig = adh_resolve_sym("libcrypto.so", "EVP_DigestUpdate");
    void *hm  = adh_resolve_sym("libcrypto.so", "HMAC_Update");
    void *dsu = adh_resolve_sym("libcrypto.so", "EVP_DigestSignUpdate");
    void *ow  = adh_resolve_sym("libssl.so", "SSL_write");
    void *orr = adh_resolve_sym("libssl.so", "SSL_read");
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
    // whatever routes crypto (Conscrypt, cronet's BoringSSL, renamed libs), not just libjavacrypto.
    // Covers symmetric (EVP_CipherUpdate), digest (EVP_DigestUpdate), HMAC (HMAC_Update
    // and the EVP_PKEY HMAC path EVP_DigestSignUpdate), and TLS (SSL_read/write).
    strncpy(g_crypto_mod, (cryptoModule && cryptoModule[0]) ? cryptoModule : "", sizeof(g_crypto_mod)-1);
    g_crypto_mod[sizeof(g_crypto_mod)-1]=0;
    int re = evp ? adh_got_replace(g_crypto_mod, evp, (void *)my_EVP_CipherUpdate) : -1;
    int rd = dig ? adh_got_replace(g_crypto_mod, dig, (void *)my_EVP_DigestUpdate) : -1;
    int rh = hm  ? adh_got_replace(g_crypto_mod, hm,  (void *)my_HMAC_Update) : -1;
    int rs = dsu ? adh_got_replace(g_crypto_mod, dsu, (void *)my_EVP_DigestSignUpdate) : -1;
    int rw = ow  ? adh_got_replace(g_crypto_mod, ow,  (void *)my_SSL_write) : -1;
    int rr = orr ? adh_got_replace(g_crypto_mod, orr, (void *)my_SSL_read) : -1;
    // Name-based install (see adh_got_replace_by_name): these 7 are one-shot BoringSSL APIs the
    // app may never have called before capture_start runs, so their PLT slot is typically
    // still unbound — value-match (adh_got_replace) would silently find 0 matching slots even
    // though the symbol is genuinely imported. Matching by the reloc entry's own symbol name
    // works regardless of bind state.
    int rpks = pks ? adh_got_replace_by_name(g_crypto_mod, "ECDSA_sign", (void*)my_ECDSA_sign) : -1;
    int rpkv = pkv ? adh_got_replace_by_name(g_crypto_mod, "ECDSA_verify", (void*)my_ECDSA_verify) : -1;
    int rpke = pke ? adh_got_replace_by_name(g_crypto_mod, "EVP_PKEY_encrypt", (void*)my_EVP_PKEY_encrypt) : -1;
    int rpkd = pkd ? adh_got_replace_by_name(g_crypto_mod, "EVP_PKEY_decrypt", (void*)my_EVP_PKEY_decrypt) : -1;
    int raes = aes ? adh_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_seal", (void*)my_EVP_AEAD_CTX_seal) : -1;
    int raeo = aeo ? adh_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_open", (void*)my_EVP_AEAD_CTX_open) : -1;
    int rdsi = dsi ? adh_got_replace_by_name(g_crypto_mod, "EVP_DigestSignInit", (void*)my_EVP_DigestSignInit) : -1;
    int rdvi = dvi ? adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyInit", (void*)my_EVP_DigestVerifyInit) : -1;
    int rdsf = dsf ? adh_got_replace_by_name(g_crypto_mod, "EVP_DigestSignFinal", (void*)my_EVP_DigestSignFinal) : -1;
    int rdvu = dvu ? adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyUpdate", (void*)my_EVP_DigestVerifyUpdate) : -1;
    int rdvf = dvf ? adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyFinal", (void*)my_EVP_DigestVerifyFinal) : -1;

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
        fo  = oo  ? adh_got_replace(g_file_mod, oo,  (void *)my_open)     : -1;
        foa = ooa ? adh_got_replace(g_file_mod, ooa, (void *)my_openat)   : -1;
        frd = ord ? adh_got_replace(g_file_mod, ord, (void *)my_read)     : -1;
        fwr = owr ? adh_got_replace(g_file_mod, owr, (void *)my_write)    : -1;
        fsc = osc ? adh_got_replace(g_file_mod, osc, (void *)my_syscall)  : -1;
        frc = orc ? adh_got_replace(g_file_mod, orc, (void *)my_read_chk) : -1;
        fwc = owv ? adh_got_replace(g_file_mod, owv, (void *)my_write_chk): -1;
    }
    // -- 系统: persistent detection/system-query hooks (ptrace/access/__system_property_get)
    //    in sysModule. Observe-only (g_defeat_ptrace stays 0). Streams category=system. --
    int sp=-1, sa=-1, sg=-1;
    if (sysModule && sysModule[0]) {
        strncpy(g_sys_mod, sysModule, sizeof(g_sys_mod)-1); g_sys_mod[sizeof(g_sys_mod)-1]=0;
        void *op=adh_resolve_sym("libc.so","ptrace"), *oa=adh_resolve_sym("libc.so","access");
        void *og=adh_resolve_sym("libc.so","__system_property_get");
        if (op) g_orig_ptrace = (ptrace_t)op; if (oa) g_orig_access = (access_t)oa; if (og) g_orig_prop = (prop_t)og;
        // Name-based install: the detection trio is exactly what a target may not have called
        // yet, so its PLT slot can still be unbound and value-match finds nothing (measured on
        // the sandbox: capture_start reported sys p=0 a=0 g=0 while libadhdetect.so genuinely
        // imports all three). Resolve the slot from the module's own relocations instead.
        sp = op ? adh_got_replace_by_name(g_sys_mod, "ptrace", (void *)my_ptrace) : -1;
        sa = oa ? adh_got_replace_by_name(g_sys_mod, "access", (void *)my_access) : -1;
        sg = og ? adh_got_replace_by_name(g_sys_mod, "__system_property_get", (void *)my_prop) : -1;
    }
    g_capture_on = 1;
    char cmj[80], fmj[80], smj[80];
    json_escape(g_crypto_mod, cmj, sizeof(cmj));
    json_escape(fileModule ? fileModule : "", fmj, sizeof(fmj));
    json_escape(sysModule ? sysModule : "", smj, sizeof(smj));
    char out[1400];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_start\",\"ok\":true,\"cryptoModule\":\"%s\",\"evp\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d,"
        "\"pkey\":{\"sign\":%d,\"verify\":%d,\"encrypt\":%d,\"decrypt\":%d},"
        "\"aead\":{\"seal\":%d,\"open\":%d},"
        "\"digestSignVerify\":{\"signInit\":%d,\"verifyInit\":%d,\"signFinal\":%d,\"verifyUpdate\":%d,\"verifyFinal\":%d},"
        "\"fileModule\":\"%s\",\"file\":{\"open\":%d,\"openat\":%d,\"read\":%d,\"write\":%d,\"syscall\":%d,\"readChk\":%d,\"writeChk\":%d},"
        "\"sysModule\":\"%s\",\"sys\":{\"ptrace\":%d,\"access\":%d,\"prop\":%d},\"on\":true}\n",
        idj, cmj, re, rd, rh, rs, rw, rr,
        rpks, rpkv, rpke, rpkd, raes, raeo,
        rdsi, rdvi, rdsf, rdvu, rdvf,
        fmj, fo, foa, frd, fwr, fsc, frc, fwc, smj, sp, sa, sg);
    send_line(fd, out);
    LOGI("capture_start: crypto[%s] evp=%d dig=%d hmac=%d dsu=%d sslw=%d sslr=%d dsi=%d dvi=%d dsf=%d dvu=%d dvf=%d | file[%s] oa=%d sc=%d rc=%d wc=%d | sys[%s] p=%d a=%d g=%d",
         g_crypto_mod, re, rd, rh, rs, rw, rr, rdsi, rdvi, rdsf, rdvu, rdvf, g_file_mod, foa, fsc, frc, fwc, g_sys_mod, sp, sa, sg);
}

// Uninstall the persistent capture hooks and restore the original GOT pointers, so the
// one-shot probe endpoints (crypto_hook_test / net_hook_test / flow_watch) get a clean
// slot to install-and-restore their own hook. adhd suspends continuous capture around
// those probes, then calls capture_start again.
void adh_cmd_capture_stop(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int e = 0, w = 0, r = 0, dg = 0, hm = 0, ds = 0;
    int pks = 0, pkv = 0, pke = 0, pkd = 0, aes = 0, aeo = 0;
    int dsi = 0, dvi = 0, dsf = 0, dvu = 0, dvf = 0;
    if (g_evp_cipher_orig) e  = adh_got_replace(g_crypto_mod, (void *)my_EVP_CipherUpdate, (void *)g_evp_cipher_orig);
    if (g_orig_evp_digest) dg = adh_got_replace(g_crypto_mod, (void *)my_EVP_DigestUpdate, (void *)g_orig_evp_digest);
    if (g_orig_hmac)       hm = adh_got_replace(g_crypto_mod, (void *)my_HMAC_Update, (void *)g_orig_hmac);
    if (g_orig_digest_sign)ds = adh_got_replace(g_crypto_mod, (void *)my_EVP_DigestSignUpdate, (void *)g_orig_digest_sign);
    if (g_orig_ssl_write)  w  = adh_got_replace(g_crypto_mod, (void *)my_SSL_write, (void *)g_orig_ssl_write);
    if (g_orig_ssl_read)   r  = adh_got_replace(g_crypto_mod, (void *)my_SSL_read, (void *)g_orig_ssl_read);
    if (g_ecdsa_sign_orig)   pks = adh_got_replace_by_name(g_crypto_mod, "ECDSA_sign", (void *)g_ecdsa_sign_orig);
    if (g_ecdsa_verify_orig) pkv = adh_got_replace_by_name(g_crypto_mod, "ECDSA_verify", (void *)g_ecdsa_verify_orig);
    if (g_pkey_encrypt_orig) pke = adh_got_replace_by_name(g_crypto_mod, "EVP_PKEY_encrypt", (void *)g_pkey_encrypt_orig);
    if (g_pkey_decrypt_orig) pkd = adh_got_replace_by_name(g_crypto_mod, "EVP_PKEY_decrypt", (void *)g_pkey_decrypt_orig);
    if (g_aead_seal_orig)    aes = adh_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_seal", (void *)g_aead_seal_orig);
    if (g_aead_open_orig)    aeo = adh_got_replace_by_name(g_crypto_mod, "EVP_AEAD_CTX_open", (void *)g_aead_open_orig);
    if (g_orig_dsign_init)   dsi = adh_got_replace_by_name(g_crypto_mod, "EVP_DigestSignInit", (void *)g_orig_dsign_init);
    if (g_orig_dverify_init) dvi = adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyInit", (void *)g_orig_dverify_init);
    if (g_orig_dsign_final)  dsf = adh_got_replace_by_name(g_crypto_mod, "EVP_DigestSignFinal", (void *)g_orig_dsign_final);
    if (g_orig_digest_verify)dvu = adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyUpdate", (void *)g_orig_digest_verify);
    if (g_orig_dverify_final)dvf = adh_got_replace_by_name(g_crypto_mod, "EVP_DigestVerifyFinal", (void *)g_orig_dverify_final);
    // restore persistent file hooks in the module capture_start patched
    if (g_file_mod[0]) {
        if (g_orig_open)       adh_got_replace(g_file_mod, (void *)my_open,       (void *)g_orig_open);
        if (g_orig_openat)     adh_got_replace(g_file_mod, (void *)my_openat,     (void *)g_orig_openat);
        if (g_orig_read)       adh_got_replace(g_file_mod, (void *)my_read,       (void *)g_orig_read);
        if (g_orig_fwrite_sys) adh_got_replace(g_file_mod, (void *)my_write,      (void *)g_orig_fwrite_sys);
        if (g_orig_syscall)    adh_got_replace(g_file_mod, (void *)my_syscall,    (void *)g_orig_syscall);
        if (g_orig_read_chk)   adh_got_replace(g_file_mod, (void *)my_read_chk,   (void *)g_orig_read_chk);
        if (g_orig_write_chk)  adh_got_replace(g_file_mod, (void *)my_write_chk,  (void *)g_orig_write_chk);
        g_file_mod[0] = 0;
    }
    // restore persistent system/detection hooks
    if (g_sys_mod[0]) {
        if (g_orig_ptrace) adh_got_replace_by_name(g_sys_mod, "ptrace", (void *)g_orig_ptrace);
        if (g_orig_access) adh_got_replace_by_name(g_sys_mod, "access", (void *)g_orig_access);
        if (g_orig_prop)   adh_got_replace_by_name(g_sys_mod, "__system_property_get", (void *)g_orig_prop);
        g_sys_mod[0] = 0;
    }
    g_capture_on = 0;
    cap_reset();
    char out[700];
    snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_stop\",\"ok\":true,\"restored\":{\"evp\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d,"
        "\"pkeySign\":%d,\"pkeyVerify\":%d,\"pkeyEncrypt\":%d,\"pkeyDecrypt\":%d,\"aeadSeal\":%d,\"aeadOpen\":%d,"
        "\"digestSignInit\":%d,\"digestVerifyInit\":%d,\"digestSignFinal\":%d,\"digestVerifyUpdate\":%d,\"digestVerifyFinal\":%d}}\n",
        idj, e, dg, hm, ds, w, r, pks, pkv, pke, pkd, aes, aeo, dsi, dvi, dsf, dvu, dvf);
    send_line(fd, out);
    LOGI("capture_stop: restored evp=%d sslw=%d sslr=%d", e, w, r);
}

// Drain (pop) up to a batch of ring records + rich Java records, and report HONEST WS-C
// stats: seq (total capture attempts), dropped/jdropped (never silent), backlog (still in
// ring), first/last drop ts. adhd streams the records and surfaces dropped>0 as
// complete:false. Buffer grows as needed (the old fixed 64KB could overflow with a full ring).
void adh_cmd_capture_drain(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "capture_drain"); return; }
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_drain\",\"ok\":true,\"on\":%s,\"captures\":[",
        idj, g_capture_on ? "true" : "false");
    const int DRAIN_BATCH = 512;   // bound one response; adhd polls again to clear the backlog
    pthread_mutex_lock(&g_cap_lock);
    int ncaps = 0;
    while (g_ring_count > 0 && ncaps < DRAIN_BATCH) {
        if (len + 4200 > cap) { size_t nc = cap * 2; char *no = realloc(out, nc); if (!no) break; out = no; cap = nc; }
        struct CapRec *r = &g_ring[g_ring_tail];
        len = emit_caprec(out, len, cap, r, ncaps == 0);
        g_ring_tail = (g_ring_tail + 1) % CAP_RING;
        g_ring_count--; ncaps++;
    }
    int backlog = g_ring_count;
    unsigned long long seq = __atomic_load_n(&g_cap_seq, __ATOMIC_RELAXED);
    unsigned long long dropped = __atomic_load_n(&g_cap_dropped, __ATOMIC_RELAXED);
    unsigned long long jdropped = __atomic_load_n(&g_jcap_dropped, __ATOMIC_RELAXED);
    long long fdrop = g_cap_first_drop_ns, ldrop = g_cap_last_drop_ns;
    // rich Java-layer records: algorithm + op + key + iv + input + output
    len += snprintf(out + len, cap > len ? cap - len : 0, "],\"jcaptures\":[");
    for (int k = 0; k < g_njcaps; k++) {
        if (len + 9000 > cap) { size_t nc = cap * 2; char *no = realloc(out, nc); if (!no) break; out = no; cap = nc; }
        struct JCapRec *r = &g_jcaps[k];
        len += snprintf(out + len, cap > len ? cap - len : 0,
            "%s{\"algo\":\"%s\",\"op\":\"%s\",\"tid\":%d,\"tsNs\":%lld,\"key\":\"", k ? "," : "", r->algo, r->op, r->tid, r->ts_ns);
        for (int b = 0; b < r->nkey && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->key[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"iv\":\"");
        for (int b = 0; b < r->niv && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->iv[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"in\":\"");
        for (int b = 0; b < r->nin && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->in[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"out\":\"");
        for (int b = 0; b < r->nout && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->out[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"inl\":%d,\"outl\":%d}", r->nin, r->nout);
    }
    int njcaps = g_njcaps;
    g_njcaps = 0;
    pthread_mutex_unlock(&g_cap_lock);
    snprintf(out + len, cap > len ? cap - len : 0,
        "],\"count\":%d,\"jcount\":%d,\"backlog\":%d,\"seq\":%llu,\"dropped\":%llu,\"jdropped\":%llu,"
        "\"firstDropNs\":%lld,\"lastDropNs\":%lld,\"ring\":%d,\"complete\":%s,\"javaActive\":%s}\n",
        ncaps, njcaps, backlog, seq, dropped, jdropped, fdrop, ldrop, CAP_RING,
        (dropped == 0 && jdropped == 0) ? "true" : "false", g_java_active ? "true" : "false");
    send_line(fd, out);
    free(out);
}

// Install GOT hooks on libadhdetect's detection calls, trigger Detection.run(),
// report what the target checked.
void adh_cmd_detect_watch(int fd, const char *id, const char *module, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    // No hardcoded target module: adhd passes the module whose GOT holds the detection calls.
    if (!module || !module[0]) { char e[200]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"detect_watch\",\"ok\":false,\"error\":\"need module (which loaded module makes the detection calls)\"}\n", idj); send_line(fd, e); return; }
    const char *mod = module;
    void *op = adh_resolve_sym("libc.so", "ptrace");
    void *oa = adh_resolve_sym("libc.so", "access");
    void *og = adh_resolve_sym("libc.so", "__system_property_get");
    g_orig_ptrace = (ptrace_t)op; g_orig_access = (access_t)oa; g_orig_prop = (prop_t)og;
    // Name-based: the probe runs BEFORE the target has ever called these (that is the point —
    // install then trigger), so a value-match on the still-lazily-bound PLT slot finds nothing.
    int r1 = op ? adh_got_replace_by_name(mod, "ptrace", (void *)my_ptrace) : -1;
    int r2 = oa ? adh_got_replace_by_name(mod, "access", (void *)my_access) : -1;
    int r3 = og ? adh_got_replace_by_name(mod, "__system_property_get", (void *)my_prop) : -1;
    g_defeat_ptrace = 1;   // this one-shot probe defeats TRACEME (original behavior); reset after
    pthread_mutex_lock(&g_det_lock); g_ndets = 0; pthread_mutex_unlock(&g_det_lock);

    int did = 0, triggered = 0, rc = -999;
    JNIEnv *env = adh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = className[0] ? adh_jni_load_app_class(env, className) : NULL;
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()I");
            if (run) { rc = (*env)->CallStaticIntMethod(env, jc, run); triggered = 1; }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did);
    }
    // restore
    if (r1 > 0) adh_got_replace_by_name(mod, "ptrace", op);
    if (r2 > 0) adh_got_replace_by_name(mod, "access", oa);
    if (r3 > 0) adh_got_replace_by_name(mod, "__system_property_get", og);
    g_defeat_ptrace = 0;

    size_t cap = 1 << 13, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "detect_watch"); return; }
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"detect_watch\",\"ok\":true,\"hooked\":{\"ptrace\":%d,\"access\":%d,\"prop\":%d},\"triggered\":%s,\"detectRc\":%d,\"detections\":[", idj, r1, r2, r3, triggered ? "true" : "false", rc);
    pthread_mutex_lock(&g_det_lock);
    for (int k = 0; k < g_ndets; k++) { char dj[200]; json_escape(g_dets[k].detail, dj, sizeof(dj));
        len += snprintf(out + len, cap - len, "%s{\"category\":\"%s\",\"detail\":\"%s\"}", k ? "," : "", g_dets[k].cat, dj); }
    int n = g_ndets;
    pthread_mutex_unlock(&g_det_lock);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("detect_watch: hooked p=%d a=%d g=%d triggered=%d detections=%d", r1, r2, r3, triggered, n);
}

#ifdef ADH_HAVE_INLINE_HOOK
// v2.2 WS-A native inline self-test. The target supplies the module, symbol and a safe
// no-arg static trigger; the agent only supplies the ABI-specific wrapper and Dobby backend.
typedef int (*inline_crypto_update_t)(void *, unsigned char *, int *, const unsigned char *, int);
static inline_crypto_update_t g_inline_crypto_orig = NULL;
static void *g_inline_crypto_target = NULL;
static int g_inline_crypto_active = 0;
static int my_inline_crypto_update(void *ctx, unsigned char *out, int *outl,
                                   const unsigned char *in, int inl) {
    if (__atomic_load_n(&g_inline_crypto_active, __ATOMIC_RELAXED))
        capture("INLINE_EVP_CipherUpdate", in, inl);
    return g_inline_crypto_orig ? g_inline_crypto_orig(ctx, out, outl, in, inl) : 0;
}

void adh_cmd_inline_crypto_test(int fd, const char *id, const char *module,
                                   const char *symbol, const char *className, const char *method) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char mj[96], sj[96], cj[220], errj[180];
    json_escape(module ? module : "", mj, sizeof(mj));
    json_escape(symbol ? symbol : "", sj, sizeof(sj));
    json_escape(className ? className : "", cj, sizeof(cj));
    const char *error = "";
    void *target = (module && symbol) ? adh_resolve_sym(module, symbol) : NULL;
    void *original = NULL;
    int installed = 0, hooked = 0;
    if (target && g_inline_crypto_target == target && g_inline_crypto_orig) hooked = 1;
    else if (target && g_inline_crypto_target) error = "inline slot already owns another target";
    else if (target) {
        hooked = adh_inline_hook(target, (void *)my_inline_crypto_update, &original);
        if (hooked) {
            g_inline_crypto_orig = (inline_crypto_update_t)original;
            g_inline_crypto_target = target;
            installed = 1;
        }
    }
    int triggered = 0, value = 0, did = 0;
    cap_reset();

    if (!target) error = "symbol not found";
    else if (!hooked) { if (!error[0]) error = "inline backend rejected hook"; }
    else {
        __atomic_store_n(&g_inline_crypto_active, 1, __ATOMIC_RELAXED);
        JNIEnv *env = adh_jni_attach(&did);
        if (!env) error = "no JNI env";
        else {
            (*env)->PushLocalFrame(env, 48);
            jclass jc = adh_jni_load_app_class(env, className ? className : "");
            jmethodID mid = jc ? (*env)->GetStaticMethodID(env, jc, method ? method : "", "()I") : NULL;
            if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); mid = NULL; }
            if (!mid) error = "static int trigger not found";
            else {
                value = (*env)->CallStaticIntMethod(env, jc, mid);
                if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); error = "trigger threw"; }
                else triggered = 1;
            }
            (*env)->PopLocalFrame(env, NULL);
            adh_jni_detach(did);
        }
        __atomic_store_n(&g_inline_crypto_active, 0, __ATOMIC_RELAXED);
    }
    json_escape(error, errj, sizeof(errj));
    size_t cap = 1 << 15, len = 0; char *out = malloc(cap);
    if (!out) { send_oom(fd, idj, "inline_crypto_test"); return; }
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"inline_crypto_test\","
        "\"ok\":%s,\"module\":\"%s\",\"symbol\":\"%s\",\"hooked\":%s,\"installed\":%s,"
        "\"triggered\":%s,\"result\":%d,\"error\":\"%s\",\"captures\":[",
        idj, (hooked && triggered && !error[0]) ? "true" : "false", mj, sj,
        hooked ? "true" : "false", installed ? "true" : "false", triggered ? "true" : "false", value, errj);
    int n = cap_emit_all(out, &len, cap);
    len += snprintf(out + len, cap > len ? cap - len : 0, "],\"captureCount\":%d}\n", n);
    send_line(fd, out); free(out);
    LOGI("inline_crypto_test module=%s symbol=%s hooked=%d triggered=%d captures=%d error=%s",
         module ? module : "", symbol ? symbol : "", hooked, triggered, n, error);
}
#else
void adh_cmd_inline_crypto_test(int fd, const char *id, const char *module,
                                   const char *symbol, const char *className, const char *method) {
    (void)module; (void)symbol; (void)className; (void)method;
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char out[240];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"inline_crypto_test\","
        "\"ok\":false,\"hooked\":false,\"error\":\"inline backend not built - run tools/fetch_dobby.sh\"}\n",
        idj);
    send_line(fd, out);
}
#endif

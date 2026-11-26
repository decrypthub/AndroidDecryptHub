#ifndef ADH_CAPTURE_METHODS_H
#define ADH_CAPTURE_METHODS_H

// One versioned, bounded source for the persistent capture inventory and dependencies.
// This is NOT the independent 16-slot native_hook registry. Wire bits are meaningful only
// with this catalog version; Host persistence must keep stable IDs, never unversioned bits.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define ADH_CAPTURE_CATALOG "native-capture/1"
#define ADH_CF_DIGEST 1u
#define ADH_CF_HMAC 2u
#define ADH_CF_SYMMETRIC 4u
#define ADH_CF_ASYMMETRIC 8u
#define ADH_CF_TLS 16u
#define ADH_CF_AEAD 32u
#define ADH_CF_SYSTEM 64u
#define ADH_CF_FILE 128u
#define ADH_CM_BIT(id) (UINT32_C(1) << ADH_CM_##id)
#define ADH_CAPTURE_METHODS(X) \
 X(CIPHER_UPDATE, "EVP_CipherUpdate", ADH_CF_SYMMETRIC, ADH_CM_BIT(CIPHER_INIT)|ADH_CM_BIT(CIPHER_FREE)) \
 X(DIGEST_UPDATE, "EVP_DigestUpdate", ADH_CF_DIGEST, 0) \
 X(HMAC_UPDATE, "HMAC_Update", ADH_CF_HMAC, 0) \
 X(SIGN_UPDATE, "EVP_DigestSignUpdate", ADH_CF_HMAC|ADH_CF_ASYMMETRIC, ADH_CM_BIT(SIGN_INIT)) \
 X(SSL_WRITE, "SSL_write", ADH_CF_TLS, 0) \
 X(SSL_READ, "SSL_read", ADH_CF_TLS, 0) \
 X(CIPHER_INIT, "EVP_CipherInit_ex", ADH_CF_SYMMETRIC, ADH_CM_BIT(CIPHER_FREE)) \
 X(CIPHER_FREE, "EVP_CIPHER_CTX_free", ADH_CF_SYMMETRIC, 0) \
 X(ECDSA_SIGN, "ECDSA_sign", ADH_CF_ASYMMETRIC, 0) \
 X(ECDSA_VERIFY, "ECDSA_verify", ADH_CF_ASYMMETRIC, 0) \
 X(PKEY_ENCRYPT, "EVP_PKEY_encrypt", ADH_CF_ASYMMETRIC, 0) \
 X(PKEY_DECRYPT, "EVP_PKEY_decrypt", ADH_CF_ASYMMETRIC, 0) \
 X(AEAD_SEAL, "EVP_AEAD_CTX_seal", ADH_CF_AEAD, 0) \
 X(AEAD_OPEN, "EVP_AEAD_CTX_open", ADH_CF_AEAD, 0) \
 X(SIGN_INIT, "EVP_DigestSignInit", ADH_CF_HMAC|ADH_CF_ASYMMETRIC, 0) \
 X(VERIFY_INIT, "EVP_DigestVerifyInit", ADH_CF_ASYMMETRIC, 0) \
 X(SIGN_FINAL, "EVP_DigestSignFinal", ADH_CF_HMAC|ADH_CF_ASYMMETRIC, ADH_CM_BIT(SIGN_INIT)) \
 X(VERIFY_UPDATE, "EVP_DigestVerifyUpdate", ADH_CF_ASYMMETRIC, ADH_CM_BIT(VERIFY_INIT)) \
 X(VERIFY_FINAL, "EVP_DigestVerifyFinal", ADH_CF_ASYMMETRIC, ADH_CM_BIT(VERIFY_INIT)) \
 X(OPEN, "open", ADH_CF_FILE, 0) \
 X(OPENAT, "openat", ADH_CF_FILE, 0) \
 X(READ, "read", ADH_CF_FILE, 0) \
 X(WRITE, "write", ADH_CF_FILE, 0) \
 X(SYSCALL, "syscall", ADH_CF_FILE, 0) \
 X(READ_CHK, "__read_chk", ADH_CF_FILE, 0) \
 X(WRITE_CHK, "__write_chk", ADH_CF_FILE, 0) \
 X(PTRACE, "ptrace", ADH_CF_SYSTEM, 0) \
 X(ACCESS, "access", ADH_CF_SYSTEM, 0) \
 X(FACCESSAT, "faccessat", ADH_CF_SYSTEM, 0) \
 X(PROP_GET, "__system_property_get", ADH_CF_SYSTEM, 0) \
 X(PROP_READ, "__system_property_read_callback", ADH_CF_SYSTEM, 0)

#define ADH_CM_ENUM(id, symbol, families, deps) ADH_CM_##id,
enum { ADH_CAPTURE_METHODS(ADH_CM_ENUM) ADH_CM_COUNT };
#undef ADH_CM_ENUM
#define ADH_CM_ALL ((UINT32_C(1) << ADH_CM_COUNT) - 1)
struct AdhCaptureMethod { const char *symbol; uint32_t families, dependencies; };
#define ADH_CM_ROW(id, symbol, families, deps) {symbol, families, deps},
static const struct AdhCaptureMethod adh_capture_methods[ADH_CM_COUNT] = {
    ADH_CAPTURE_METHODS(ADH_CM_ROW)
};
#undef ADH_CM_ROW

static inline uint32_t adh_capture_method_effective(uint32_t selected, uint32_t families) {
    uint32_t allowed = 0;
    for (int i = 0; i < ADH_CM_COUNT; i++)
        if (adh_capture_methods[i].families & families) allowed |= UINT32_C(1) << i;
    uint32_t effective = selected & allowed;
    for (int pass = 0; pass < ADH_CM_COUNT; pass++) {
        uint32_t next = effective;
        for (int i = 0; i < ADH_CM_COUNT; i++)
            if (effective & (UINT32_C(1) << i)) next |= adh_capture_methods[i].dependencies & allowed;
        if (next == effective) break;
        effective = next;
    }
    return effective;
}

static inline int adh_capture_method_bits(const char *s, uint32_t *out) {
    if (!s || strlen(s) != ADH_CM_COUNT) return 0;
    uint32_t bits = 0;
    for (int i = 0; i < ADH_CM_COUNT; i++) {
        if (s[i] != '0' && s[i] != '1') return 0;
        if (s[i] == '1') bits |= UINT32_C(1) << i;
    }
    *out = bits;
    return 1;
}

static inline int adh_capture_revision(const char *s, uint32_t *out) {
    if (!s || !s[0] || (s[0] == '0' && s[1])) return 0;
    uint32_t v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || v > (UINT32_MAX - (unsigned)(*s - '0')) / 10) return 0;
        v = v * 10 + (unsigned)(*s - '0');
    }
    *out = v;
    return 1;
}

// Flat string-only protocol. Reject nested/escaped/duplicate/unterminated/oversized
// fields rather than trusting util.c's legacy truncating substring extractor.
static inline const char *adh_cm_space(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}
static inline int adh_cm_token(const char **p, const char **start, size_t *len) {
    if (**p != '"') return 0;
    *start = ++*p;
    while (**p && **p != '"') {
        if ((unsigned char)**p < 32 || **p == '\\') return 0;
        ++*p;
    }
    if (**p != '"') return 0;
    *len = (size_t)(*p - *start);
    ++*p;
    return 1;
}
static inline int adh_capture_string_field(const char *json, const char *field, char *out, size_t cap) {
    const char *p = adh_cm_space(json);
    int found = 0;
    if (*p++ != '{') return 0;
    p = adh_cm_space(p);
    while (*p != '}') {
        const char *key, *value; size_t nk, nv;
        if (!adh_cm_token(&p, &key, &nk)) return 0;
        p = adh_cm_space(p);
        if (*p++ != ':') return 0;
        p = adh_cm_space(p);
        if (!adh_cm_token(&p, &value, &nv)) return 0;
        if (nk == strlen(field) && !memcmp(key, field, nk)) {
            if (found || nv >= cap) return 0;
            memcpy(out, value, nv); out[nv] = 0; found = 1;
        }
        p = adh_cm_space(p);
        if (*p == '}') break;
        if (*p++ != ',') return 0;
        p = adh_cm_space(p);
        if (*p == '}') return 0;
    }
    return *p == '}' && !*adh_cm_space(p + 1) && found;
}

// Validation is side-effect free. Apply only after all fields and current capture state agree.
static inline const char *adh_capture_method_validate(const char *catalog, const char *revision,
        const char *selection, uint32_t current, int active, uint32_t *bits) {
    uint32_t expected;
    if (!catalog || strcmp(catalog, ADH_CAPTURE_CATALOG)) return "CATALOG_MISMATCH";
    if (!adh_capture_revision(revision, &expected)) return "INVALID_REVISION";
    if (expected != current) return "REVISION_CONFLICT";
    if (!adh_capture_method_bits(selection, bits)) return "INVALID_SELECTION";
    if (active) return "CAPTURE_ACTIVE";
    if (current == UINT32_MAX) return "REVISION_EXHAUSTED";
    return NULL;
}
#endif

// Fixture: the MUTATED forms — what the variant scan is for.
//
// Built into libadhcrypto_variant.so and scanned by tools/verify_v101_crypto_variants.sh.
//
// Every mutation below is the real one from the reference sample repo (CYRUS-STUDIO/CyReverse's
// md5_change_constant / sha1_change_constant / custom_base64_alphabet / dynamic_base64_alphabet /
// custom_crc32_table, read 2026-09-29) — the point of a fixture is that it repeats the mutation
// people actually ship, not one that is convenient for the detector:
//
//   * MD5: round constants untouched, init rewritten in place. Note the mutation keeps the low
//     three bytes of each word (0xAA452301 vs 0x67452301): only the top byte moved.
//   * SHA1: the mirror image — init untouched, each round constant's top byte rewritten.
//   * base64: a 64-char permutation of the standard character set (case-swapped, URL-safe tail).
//   * plus a base64 alphabet computed at RUNTIME (`out[i ^ (len % 64)] = std[i]`) and a CRC table
//     generated from a recycled polynomial (0xd76aa478, which is MD5's K[0] used as something else).
//     Both are deliberately present: they are the cases a static scan cannot see, and the detector
//     is required to SAY so rather than silently miss them.
//
// Clean-room: same algorithms and the same constant VALUES as the reference mutations (a constant is
// a fact, not an expression), but the code here is ours and no third-party source was copied.

#include <stdint.h>
#include <stddef.h>

// --- MD5: K table untouched, init rewritten (top byte only) -----------------------------------
const uint32_t var_md5_k[8] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
};
const uint32_t var_md5_iv[4] = { 0xaa452301, 0xbbcdab89, 0xccbadcfe, 0xdd325476 };

// --- SHA1: init untouched, round constants rewritten (top byte only, and his 2nd reuses 827999) -
const uint32_t var_sha1_iv[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
const uint32_t var_sha1_rc[5] = { 0xaa827999, 0xbb827999, 0xccd9eba1, 0xdd1bbcdc, 0xee62c1d6 };

// --- base64: custom alphabet as an isolated NUL-terminated run --------------------------------
const char var_b64_alphabet[65] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

// --- base64: dynamic alphabet, computed per invocation ----------------------------------------
// Only the STANDARD table exists in this image; the effective alphabet depends on the input length
// and is never in the file. A static scan must report the standard table and decline to claim
// anything about the dynamic one.
const char var_b64_base[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__attribute__((visibility("default"))) void adh_fixture_dynamic_alphabet(size_t len, char out[64]) {
  int key = (int)(len % 64);
  for (int i = 0; i < 64; i++) out[i ^ key] = var_b64_base[i];
}

// --- CRC: standard Castagnoli polynomial, and a table built from a recycled constant -----------
const uint32_t var_crc32c_poly = 0x82f63b78u;
const uint32_t var_recycled_poly = 0xd76aa478u;  // MD5's K[0], reused as a CRC polynomial

__attribute__((visibility("default"))) void adh_fixture_crc_tables(uint32_t std_[256], uint32_t recycled[256]) {
  for (int i = 0; i < 256; i++) {
    uint32_t a = (uint32_t)i, b = (uint32_t)i;
    for (int j = 0; j < 8; j++) {
      a = (a & 1) ? ((a >> 1) ^ var_crc32c_poly) : (a >> 1);
      b = (b & 1) ? ((b >> 1) ^ var_recycled_poly) : (b >> 1);
    }
    std_[i] = a;
    recycled[i] = b;
  }
}

volatile uint32_t g_var_sink;

__attribute__((visibility("default"))) uint32_t adh_fixture_variant_checksum(void) {
  uint32_t acc = 0;
  for (int i = 0; i < 8; i++) acc ^= var_md5_k[i];
  for (int i = 0; i < 4; i++) acc ^= var_md5_iv[i];
  for (int i = 0; i < 5; i++) acc ^= var_sha1_iv[i];
  for (int i = 0; i < 5; i++) acc ^= var_sha1_rc[i];
  for (int i = 0; i < 64; i++) acc = (acc << 1) ^ (uint32_t)var_b64_alphabet[i];
  for (int i = 0; i < 64; i++) acc ^= (uint32_t)var_b64_base[i];
  acc ^= var_crc32c_poly ^ var_recycled_poly;
  g_var_sink = acc;
  return acc;
}

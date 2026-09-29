// Fixture: the STANDARD forms — the negative control for the variant scan.
//
// Built into libadhcrypto_std.so by tools/build_crypto_variants.sh and scanned by
// tools/verify_v101_crypto_variants.sh. Its job is to prove the detector does NOT cry "variant" at
// a normal implementation: every constant here is textbook, so the only acceptable report is
// "standard" for every family it finds.
//
// Compiled -O0 so the tables are really emitted as data (an optimising build may fold them into
// immediates and the scan would then have nothing to look at — a fixture that lies about its own
// contents would make the acceptance meaningless).
//
// Clean-room: the algorithms are textbook and the constants are the published ones. No third-party
// source was copied (see the reference-repo note in daemon/src/crypto_variants.ts).

#include <stdint.h>

// MD5 round constants K[0..7] — the anchor `md5_change_constant` leaves alone.
const uint32_t std_md5_k[8] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
};
// MD5 init A..D — the part it rewrites.
const uint32_t std_md5_iv[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

// SHA1 init A..E (20 bytes, so it cannot be confused with MD5's 16-byte init).
const uint32_t std_sha1_iv[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
// SHA1 round constants — the part `sha1_change_constant` rewrites.
const uint32_t std_sha1_rc[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

// Standard base64 alphabet, NUL-terminated so the shape detector sees an isolated 64-byte run.
const char std_b64_alphabet[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// zlib/zip CRC-32 polynomial (the table itself is generated at runtime, as implementations do).
const uint32_t std_crc32_poly = 0xedb88320u;

volatile uint32_t g_std_sink;

// Referenced by an exported symbol so nothing above can be dropped as unused.
__attribute__((visibility("default"))) uint32_t adh_fixture_std_checksum(void) {
  uint32_t acc = 0;
  for (int i = 0; i < 8; i++) acc ^= std_md5_k[i];
  for (int i = 0; i < 4; i++) acc ^= std_md5_iv[i];
  for (int i = 0; i < 5; i++) acc ^= std_sha1_iv[i];
  for (int i = 0; i < 4; i++) acc ^= std_sha1_rc[i];
  for (int i = 0; i < 64; i++) acc = (acc << 1) ^ (uint32_t)std_b64_alphabet[i];
  acc ^= std_crc32_poly;
  g_std_sink = acc;
  return acc;
}

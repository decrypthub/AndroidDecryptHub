// Structural crypto identification — the answer to "the app changed the algorithm".
//
// Why this exists: `analysis.ts`'s constant scan (and every tool like it) looks for the STANDARD
// bytes of a standard algorithm. That misses an entire class of real targets: an app that
// implements the algorithm itself and perturbs it — swap the MD5 IV, reorder the base64 alphabet,
// use a different CRC polynomial. Nothing in that binary matches a standard signature, so the
// report says "no crypto found" about a payload that is doing MD5 right there. And because the
// implementation is the app's own code, the runtime capture path (which names a capture after the
// LIBRARY FUNCTION that was called) sees nothing either — both layers go blind at once.
//
// The observation this module is built on: a mutator normally changes ONE part and leaves the rest,
// so identification should key on the parts that survive. Verified against real sample code
// (CYRUS-STUDIO/CyReverse — md5_change_constant / sha1_change_constant / custom_base64_alphabet /
// dynamic_base64_alphabet / custom_crc32_table, read 2026-09-29):
//
//   - MD5 variant:  the 64 round constants are untouched, only the IV is rewritten
//     (0xaa452301… vs 0x67452301 — the low three bytes of each word kept!). So the K table is the
//     anchor and the IV is the companion whose absence proves the mutation.
//   - SHA1 variant: the opposite — the IV is untouched and the five ROUND CONSTANTS are rewritten
//     (0xAA827999 / 0xBB827999 / 0xCCD9EBA1 / 0xDD1BBCDC / 0xEE62C1D6). So for SHA1 the IV is the
//     anchor. A single "MD5/SHA1 constants" table could not have caught both.
//   - base64 variant: a 64-char permutation of the standard character set, sitting in .rodata as an
//     isolated run — detectable by SHAPE (64 distinct chars, all drawn from the base64 vocabulary)
//     rather than by content.
//   - dynamic base64: the alphabet is computed per invocation (`i ^ (len % 64)`) — see LIMITS.
//
// What this module deliberately does NOT do: guess. A finding is only emitted when a structural
// anchor is actually present, and the `variant` verdict always carries the evidence (which standard
// companion is missing). Everything a static scan cannot see is stated in `limits` instead of being
// silently absent — a scan that is quietly blind is worse than one that says where it is blind.
//
// Pure: no daemon state, no fs, no agent protocol. Unit-tested in daemon/test/crypto_variants.test.ts.

import { CRYPTO_CONSTS } from './analysis.ts';

/** Little-endian u32 buffer — the DEX/ARM data form these constants appear in. Deriving the byte
 *  patterns from the numbers (instead of hand-writing hex) is what keeps this table trustworthy. */
const le32 = (...vals: number[]): Buffer =>
  Buffer.from(vals.flatMap((v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]));

/** First four round constants of MD5's K table (the part a variant usually leaves alone). */
const MD5_K4 = le32(0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee);
/** MD5 init A..D — the part `md5_change_constant` rewrites. Also a strict prefix of SHA1's IV. */
const MD5_IV = le32(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
/** SHA1 init A..E — 20 bytes, so it cannot be confused with MD5's 16-byte IV. */
const SHA1_IV = le32(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0);
/** SHA1's four round constants — the part `sha1_change_constant` rewrites. */
const SHA1_RC = le32(0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6);
const SHA256_K4 = le32(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5);
const SHA256_INIT = le32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a);
/** Table-generating polynomials: the only thing left in .rodata when the 256-entry table itself is
 *  built at runtime (both CRC32 samples in the reference repo do exactly that). */
const CRC32_POLY = le32(0xedb88320);
const CRC32C_POLY = le32(0x82f63b78);
/** TEA/XXTEA delta (golden-ratio constant). */
const TEA_DELTA = le32(0x9e3779b9);

const B64_STD = Buffer.from(CRYPTO_CONSTS.find((c) => c.name === 'Base64-std')!.hex, 'hex');
const B64_URL = Buffer.from(CRYPTO_CONSTS.find((c) => c.name === 'Base64-url')!.hex, 'hex');
const AES_SBOX = Buffer.from(CRYPTO_CONSTS.find((c) => c.name === 'AES-Sbox')!.hex, 'hex');
const AES_INV = Buffer.from(CRYPTO_CONSTS.find((c) => c.name === 'AES-InvSbox')!.hex, 'hex');

export type CryptoFamily = 'MD5' | 'SHA1' | 'SHA256' | 'AES' | 'Base64' | 'CRC32' | 'TEA';

export interface FamilyFinding {
  family: CryptoFamily;
  /** `standard` = the structure AND its standard companion parts are both present.
   *  `variant`  = the structure is here but a standard part it should carry is missing. */
  verdict: 'standard' | 'variant';
  /** What proved the structure (a constant table that the mutation left intact). */
  anchor: { what: string; offset: string };
  /** Standard companions that are absent — the evidence for a `variant` verdict. */
  missing: string[];
  detail?: string;
}

export interface AlphabetFinding {
  offset: string;
  kind: 'standard' | 'url' | 'variant';
  sample: string;
  /** How many of the 64 positions differ from the closest standard alphabet. */
  substitutions: number;
}

export interface VariantReport {
  families: FamilyFinding[];
  alphabets: AlphabetFinding[];
  /** Static-scan limits, stated rather than silently omitted. */
  limits: string[];
}

const hex = (n: number) => '0x' + n.toString(16);

/** All offsets of `pat` in `buf`, capped (a stripped .so can repeat a constant many times). */
function findAll(buf: Buffer, pat: Buffer, cap = 8): number[] {
  const out: number[] = [];
  let idx = buf.indexOf(pat);
  while (idx >= 0 && out.length < cap) {
    out.push(idx);
    idx = buf.indexOf(pat, idx + 1);
  }
  return out;
}

/** Offsets of 16-byte windows that look like a perturbed copy of `std`: at least `minMatch` of the
 *  bytes agree in place. This is how a rewritten IV is reported as "standard with N bytes changed"
 *  instead of being missed entirely. */
function findPerturbed(buf: Buffer, std: Buffer, minMatch: number, cap = 4): { offset: number; matched: number }[] {
  const out: { offset: number; matched: number }[] = [];
  if (buf.length < std.length) return out;
  const first = std[0];
  for (let i = 0; i + std.length <= buf.length && out.length < cap; i++) {
    if (buf[i] !== first) continue; // cheap pre-filter: anchor on byte 0 before comparing the rest
    let matched = 0;
    for (let j = 0; j < std.length; j++) if (buf[i + j] === std[j]) matched++;
    if (matched >= minMatch && matched < std.length) out.push({ offset: i, matched });
  }
  return out;
}

function bufEq(buf: Buffer, off: number, pat: Buffer): boolean {
  return off + pat.length <= buf.length && buf.compare(pat, 0, pat.length, off, off + pat.length) === 0;
}

/** 64-byte windows that look like a base64 alphabet: 64 DISTINCT bytes, nearly all drawn from the
 *  base64 vocabulary, and standing alone (a NUL or a non-vocabulary byte on either side). A run of
 *  unrelated text cannot satisfy that; a substituted alphabet can. */
function findAlphabets(buf: Buffer): AlphabetFinding[] {
  const vocab = (b: number) =>
    (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2b || b === 0x2f || b === 0x2d || b === 0x5f;
  const out: AlphabetFinding[] = [];
  for (let i = 0; i + 64 <= buf.length; i++) {
    if (out.length >= 8) break;
    if (vocab(buf[i]) === false) continue;
    const seen = new Set<number>();
    let inVocab = 0;
    for (let j = 0; j < 64; j++) {
      const b = buf[i + j];
      seen.add(b);
      if (vocab(b)) inVocab++;
    }
    if (seen.size !== 64 || inVocab < 60) continue;
    const before = i > 0 ? buf[i - 1] : 0;
    const after = i + 64 < buf.length ? buf[i + 64] : 0;
    const isolated = before === 0 || !vocab(before);
    if (!isolated || vocab(after)) continue;
    const win = buf.subarray(i, i + 64);
    const kind = win.equals(B64_STD) ? 'standard' : win.equals(B64_URL) ? 'url' : 'variant';
    const std = kind === 'url' ? B64_URL : B64_STD;
    let substitutions = 0;
    for (let j = 0; j < 64; j++) if (win[j] !== std[j]) substitutions++;
    out.push({ offset: hex(i), kind, sample: win.toString('latin1'), substitutions });
    i += 63;
  }
  return out;
}

/**
 * Identify crypto STRUCTURE and say whether it is the standard form or a perturbed one.
 *
 * Only families with a present anchor are reported: absence of an anchor is not evidence of absence
 * of the algorithm (see `limits`), so claiming anything from it would be a guess.
 */
export function scanCryptoVariants(buf: Buffer): VariantReport {
  const families: FamilyFinding[] = [];
  const limits: string[] = [];

  // ---- MD5 (anchor: K table; companion: IV) --------------------------------------------------
  const md5k = findAll(buf, MD5_K4);
  // MD5's 16-byte init is a strict PREFIX of SHA1's 20-byte init, so an image containing SHA1 (which
  // is every image containing both) answers "yes" to a naive MD5-init search. Keep only the
  // occurrences that are not the first 16 bytes of a SHA1 init. Caught by the compiled fixture —
  // daemon/test's synthetic buffers never held both inits at once, a real .so usually does.
  const sha1IvOffsets = new Set(findAll(buf, SHA1_IV));
  const md5iv = findAll(buf, MD5_IV).filter((o) => !sha1IvOffsets.has(o));
  if (md5k.length) {
    const finding: FamilyFinding = {
      family: 'MD5',
      verdict: md5iv.length ? 'standard' : 'variant',
      anchor: { what: 'MD5 round-constant table K[0..3]', offset: hex(md5k[0]) },
      missing: md5iv.length ? [] : ['MD5 init A..D'],
    };
    if (!md5iv.length) {
      const pert = findPerturbed(buf, MD5_IV, 12);
      finding.detail = pert.length
        ? `a 16-byte window at ${hex(pert[0].offset)} matches the standard MD5 init in ${pert[0].matched}/16 bytes — the IV was rewritten in place, the round constants were not`
        : 'no standard MD5 init anywhere in the image';
    }
    families.push(finding);
  }

  // ---- SHA1 (anchor: IV; companion: round constants — the opposite of MD5) ---------------------
  const sha1iv = findAll(buf, SHA1_IV);
  const sha1rc = findAll(buf, SHA1_RC);  if (sha1iv.length) {
    const finding: FamilyFinding = {
      family: 'SHA1',
      verdict: sha1rc.length ? 'standard' : 'variant',
      anchor: { what: 'SHA1 init A..E', offset: hex(sha1iv[0]) },
      missing: sha1rc.length ? [] : ['SHA1 round constants 0x5a827999/0x6ed9eba1/0x8f1bbcdc/0xca62c1d6'],
    };
    if (!sha1rc.length) {
      const pert = findPerturbed(buf, SHA1_RC, 12);
      finding.detail = pert.length
        ? `a 16-byte window at ${hex(pert[0].offset)} matches the standard round constants in ${pert[0].matched}/16 bytes — the constants were rewritten, the IV was not`
        : 'standard round constants absent';
    }
    families.push(finding);
  } else if (md5iv.length && !md5k.length) {
    limits.push(
      `a standard MD5/SHA1 init prefix sits at ${hex(md5iv[0])} but neither family's structure table follows it — ` +
        'the 16-byte prefix is shared by both algorithms, so this is left unclassified rather than guessed',
    );
  }

  // ---- SHA256 (anchor: K table; companion: init H0..H3) ---------------------------------------
  const s256k = findAll(buf, SHA256_K4);
  const s256init = findAll(buf, SHA256_INIT);
  if (s256k.length) {
    families.push({
      family: 'SHA256',
      verdict: s256init.length ? 'standard' : 'variant',
      anchor: { what: 'SHA256 round-constant table K[0..3]', offset: hex(s256k[0]) },
      missing: s256init.length ? [] : ['SHA256 init H0..H3'],
    });
  }

  // ---- AES (anchor: S-box; companion: inverse S-box) ------------------------------------------
  const sbox = findAll(buf, AES_SBOX);
  const inv = findAll(buf, AES_INV);
  if (sbox.length || inv.length) {
    const both = sbox.length > 0 && inv.length > 0;
    families.push({
      family: 'AES',
      verdict: both ? 'standard' : 'variant',
      anchor: { what: sbox.length ? 'AES S-box' : 'AES inverse S-box', offset: hex((sbox.length ? sbox : inv)[0]) },
      missing: both ? [] : [sbox.length ? 'AES inverse S-box' : 'AES S-box'],
      detail: both ? undefined : 'one table of the pair is present — the other is either unused or replaced',
    });
  }

  // ---- CRC32 (the poly is all that survives when the table is generated at runtime) -----------
  const crc32 = findAll(buf, CRC32_POLY);
  const crc32c = findAll(buf, CRC32C_POLY);
  for (const [pat, what, name] of [
    [crc32, 'CRC-32 polynomial 0xedb88320 (zlib/zip)', 'CRC32'] as const,
    [crc32c, 'CRC-32C polynomial 0x82f63b78 (Castagnoli)', 'CRC32'] as const,
  ]) {
    if (pat.length) {
      families.push({
        family: 'CRC32',
        verdict: 'standard', // a known polynomial is a standard family, not a mutation of one
        anchor: { what, offset: hex(pat[0]) },
        missing: [],
      });
    }
  }

  const tea = findAll(buf, TEA_DELTA);
  if (tea.length) {
    families.push({
      family: 'TEA',
      verdict: 'standard',
      anchor: { what: 'TEA/XXTEA delta 0x9e3779b9 (also xxHash-style variants)', offset: hex(tea[0]) },
      missing: [],
    });
  }

  return {
    families,
    alphabets: findAlphabets(buf),
    limits: limits.concat([
      'static scan only: a table this image builds at runtime (e.g. a base64 alphabet computed as `i ^ (len % 64)`, or a 256-entry CRC table generated from a polynomial) has no data form in the file — absence here is not absence in the process',
      'a single 32-bit constant proves nothing: 0xd76aa478 is MD5 K[0] and was also used as a CRC polynomial by the reference sample, so only multi-word tables are treated as anchors',
      'a mutation that rewrites the ANCHOR too (custom AES S-box, self-invented round function) is invisible to any constant scan — that needs instruction-level structure (adhd: trace_digest / QBDI) or a runtime capture',
    ]),
  };
}

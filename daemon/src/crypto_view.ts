// How one crypto capture is shown on the 加解密 list.
//
// The stored record keeps the raw algo/op/func the hooks produced. This module only
// decides the row: a concrete algorithm name when the hook recorded one, otherwise an
// honest "未识别" plus the hook that fired. Native EVP_DigestUpdate cannot tell MD5
// from SHA-256 — the name lives on Init, which this capture path does not record — so
// the row says so instead of calling the event "Digest".
//
// Pure: no store, no I/O. The list route and the live broadcast both call cryptoView.

export interface CryptoCaptureLike {
  source?: string;
  func?: string;
  algo?: string;
  op?: string;
  inl?: number;
  hex?: string;
  outHex?: string;
  keyHex?: string;
  preview?: string;
}

export interface CryptoView {
  title: string;
  /** 加密 / 解密 / 签名 / 验签 / 哈希 / 认证, or '' when the hook does not say. */
  direction: string;
  hook: string;
  inBytes: number;
  outBytes: number;
  /** Empty when there is no payload. Truncation is marked on the input side. */
  sizeLabel: string;
  truncated: boolean;
  hasKey: boolean;
  /** Printable preview. Empty when the payload is binary or blank, so the row does not fill with dots. */
  preview: string;
  /** Init-only records (no input, no output) stay in the store but stay off the list. The later doFinal carries the key. */
  show: boolean;
}

const VAGUE_ALGO =
  /^(摘要 Digest|对称加解密|HMAC|RSA\/EC 签名|RSA\/EC 验签|RSA 非对称加密|RSA 非对称解密|AEAD 加密\(GCM\/ChaCha20-Poly1305\)|AEAD 解密\(GCM\/ChaCha20-Poly1305\)|TLS|Java Hook|Native Hook)$/;

const NATIVE: Record<string, { title: string; direction: string }> = {
  EVP_DigestUpdate: { title: '摘要 · 未识别', direction: '哈希' },
  HMAC_Update: { title: 'HMAC · 未识别', direction: '认证' },
  EVP_DigestSignUpdate: { title: 'HMAC · 未识别', direction: '认证' },
  EVP_DigestVerifyUpdate: { title: 'HMAC · 未识别', direction: '认证' },
  EVP_DSignUpdate_asym: { title: '签名 · 未识别', direction: '签名' },
  EVP_DSignFinal_sig: { title: '签名 · 未识别', direction: '签名' },
  EVP_DVerifyUpdate_asym: { title: '验签 · 未识别', direction: '验签' },
  EVP_DVerifyFinal_sig: { title: '验签 · 未识别', direction: '验签' },
  ECDSA_sign_digest: { title: '签名 · 未识别', direction: '签名' },
  ECDSA_sign_sig: { title: '签名 · 未识别', direction: '签名' },
  ECDSA_verify_digest: { title: '验签 · 未识别', direction: '验签' },
  ECDSA_verify_sig: { title: '验签 · 未识别', direction: '验签' },
  EVP_PKEY_encrypt_in: { title: 'RSA · 未识别', direction: '加密' },
  EVP_PKEY_encrypt_out: { title: 'RSA · 未识别', direction: '加密' },
  EVP_PKEY_decrypt_in: { title: 'RSA · 未识别', direction: '解密' },
  EVP_PKEY_decrypt_out: { title: 'RSA · 未识别', direction: '解密' },
  EVP_AEAD_seal_pt: { title: 'AEAD · 未识别', direction: '加密' },
  EVP_AEAD_seal_ct: { title: 'AEAD · 未识别', direction: '加密' },
  EVP_AEAD_open_ct: { title: 'AEAD · 未识别', direction: '解密' },
  EVP_AEAD_open_pt: { title: 'AEAD · 未识别', direction: '解密' },
};

/** Java hook label. hasBody distinguishes Cipher.doFinal from the init that only stored the key. */
export function javaHook(op: string, hasBody: boolean): string {
  switch (op) {
    case 'digest': return 'MessageDigest.digest';
    case 'mac': return hasBody ? 'Mac.doFinal' : 'Mac.init';
    case 'sign': return hasBody ? 'Signature.sign' : 'Signature.initSign';
    case 'verify': return hasBody ? 'Signature.verify' : 'Signature.initVerify';
    case 'init': return 'Cipher.init';
    case 'encrypt':
    case 'decrypt':
    case 'wrap':
    case 'unwrap':
    case 'doFinal':
      return hasBody ? 'Cipher.doFinal' : 'Cipher.init';
    default:
      return '';
  }
}

function javaDirection(op: string): string {
  if (op === 'encrypt' || op === 'wrap') return '加密';
  if (op === 'decrypt' || op === 'unwrap') return '解密';
  if (op === 'sign') return '签名';
  if (op === 'verify') return '验签';
  if (op === 'digest') return '哈希';
  if (op === 'mac') return '认证';
  return '';
}

function nativeView(func: string): { title: string; direction: string } {
  const known = NATIVE[func];
  if (known) return known;
  if (func.startsWith('EVP_Encrypt')) return { title: '对称 · 未识别', direction: '加密' };
  if (func.startsWith('EVP_Decrypt')) return { title: '对称 · 未识别', direction: '解密' };
  if (func.startsWith('EVP_Cipher')) return { title: '对称 · 未识别', direction: '' };
  if (func.startsWith('EVP_Digest')) return { title: '摘要 · 未识别', direction: '哈希' };
  return { title: func || '未识别', direction: '' };
}

function concreteAlgo(algo: string): string {
  const name = algo.trim();
  if (!name || VAGUE_ALGO.test(name)) return '';
  return name;
}

function byteLen(hex: string | undefined): number {
  if (!hex || hex.length % 2) return 0;
  return hex.length / 2;
}

/** A preview of only dots is a binary buffer, not something to put on the row. */
export function readablePreview(preview: string | undefined): string {
  const text = (preview || '').trim();
  if (!text) return '';
  if (!text.replace(/[.\s]/g, '')) return '';
  return text;
}

function sizeLabel(inBytes: number, outBytes: number, truncated: boolean): string {
  if (inBytes <= 0 && outBytes <= 0) return '';
  const input = inBytes > 0 ? `${inBytes} B${truncated ? ' 截断' : ''}` : '';
  const output = outBytes > 0 ? `${outBytes} B` : '';
  if (input && output) return `${input} → ${output}`;
  return input || output;
}

export function cryptoView(c: CryptoCaptureLike): CryptoView {
  const stored = byteLen(c.hex);
  const inBytes = c.inl && c.inl > 0 ? c.inl : stored;
  const outBytes = byteLen(c.outHex);
  const truncated = !!(c.inl && c.inl > 0 && c.hex && inBytes > stored);
  const hasBody = inBytes > 0 || outBytes > 0;
  const concrete = concreteAlgo(c.algo || '');
  const fromNative = nativeView(c.func || '');
  const java = c.source === 'java';
  const namedHook = c.func && c.func.includes('.') ? c.func : '';
  const hook = java ? (namedHook || javaHook(c.op || '', hasBody)) : (c.func || '');
  const direction = java ? javaDirection(c.op || '') : fromNative.direction;
  return {
    title: concrete || (java ? '未识别' : fromNative.title),
    direction,
    hook,
    inBytes,
    outBytes,
    sizeLabel: sizeLabel(inBytes, outBytes, truncated),
    truncated,
    hasKey: !!(c.keyHex && c.keyHex.length > 0),
    preview: readablePreview(c.preview),
    show: hasBody,
  };
}

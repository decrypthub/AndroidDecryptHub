// How one crypto capture is shown on the 加解密 list.
//
// The stored record keeps the raw algo/op/func the hooks produced. This module only
// decides the row: a concrete algorithm name when the hook recorded one, otherwise an
// an empty algorithm label plus the hook that fired. Native EVP_DigestUpdate cannot tell MD5
// from SHA-256 — the name lives on Init, which this capture path does not record — so
// do not fabricate an algorithm name from a generic native symbol.
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
  inputPreview?: string;
  inputBytesPresent?: boolean;
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
  /** Actual input as readable UTF-8 or a bounded hex prefix; blank when input is not captured. */
  preview: string;
  /** Init-only records (no input, no output) stay in the store but stay off the list. The later doFinal carries the key. */
  show: boolean;
}

const VAGUE_ALGO =
  /^(摘要 Digest|对称加解密|HMAC|RSA\/EC 签名|RSA\/EC 验签|RSA 非对称加密|RSA 非对称解密|AEAD 加密\(GCM\/ChaCha20-Poly1305\)|AEAD 解密\(GCM\/ChaCha20-Poly1305\)|TLS|Java Hook|Native Hook)$/;

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

function nativeDirection(func: string): string {
  if (/^(?:HMAC_|EVP_Digest(?:Sign|Verify)Update$)/.test(func)) return '认证';
  if (/^(?:EVP_DSign|ECDSA_sign)/.test(func)) return '签名';
  if (/^(?:EVP_DVerify|ECDSA_verify)/.test(func)) return '验签';
  if (/^EVP_(?:Encrypt|PKEY_encrypt|AEAD_seal)/.test(func)) return '加密';
  if (/^EVP_(?:Decrypt|PKEY_decrypt|AEAD_open)/.test(func)) return '解密';
  if (/^EVP_Digest/.test(func)) return '哈希';
  return '';
}

/** These hooks sampled an output buffer, not a second operation input. Keep raw records, not fake input rows. */
export function outputOnlyCapture(c: CryptoCaptureLike): boolean {
  return c.source!=='java' && /(?:_out$|^EVP_AEAD_(?:seal_ct|open_pt)$|^(?:ECDSA_sign_sig|EVP_DSignFinal_sig)$)/.test(c.func||'');
}

/** One pure formatter for Host metadata and browser fallback. Never substitutes algorithm/output for input. */
export function inputContentPreview(c: CryptoCaptureLike): string {
  if(outputOnlyCapture(c))return '';
  if(c.hex===undefined)return typeof c.inputPreview==='string'?c.inputPreview.slice(0,120):'';
  if(typeof c.hex!=='string'||!c.hex.length||!/^(?:[a-f\d]{2})*$/i.test(c.hex))return '';
  const clipped=c.hex.length>512,missing=typeof c.inl==='number'&&c.inl>c.hex.length/2;
  try {
    const text=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(c.hex.slice(0,512).match(/../g)??[],p=>parseInt(p,16)),{stream:clipped});
    if(text.trim()&&!/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(text)){
      const chars=Array.from(text.replace(/\s+/g,' '));return chars.slice(0,100).join('')+(clipped||missing||chars.length>100?'…':'');
    }
  } catch {/* Actual binary input is shown as bytes, not a placeholder or replacement characters. */}
  return 'HEX '+(c.hex.slice(0,64).match(/../g)??[]).join(' ').toLowerCase()+(c.hex.length>64||missing?'…':'');
}

function concreteAlgo(algo: string): string {
  const name = algo.trim();
  if (!name || VAGUE_ALGO.test(name) || /未识别|^unknown$/i.test(name)) return '';
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
  const java = c.source === 'java';
  const namedHook = c.func && c.func.includes('.') ? c.func : '';
  const hook = java ? (namedHook || javaHook(c.op || '', hasBody)) : (c.func || '');
  const direction = java ? javaDirection(c.op || '') : nativeDirection(c.func || '');
  return {
    title: concrete || '—',
    direction,
    hook,
    inBytes,
    outBytes,
    sizeLabel: sizeLabel(inBytes, outBytes, truncated),
    truncated,
    hasKey: !!(c.keyHex && c.keyHex.length > 0),
    preview: inputContentPreview(c),
    show: hasBody && !outputOnlyCapture(c),
  };
}

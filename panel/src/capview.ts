// 记录 → 视图模型。从旧 index.html 逐行移植的纯函数层，不碰 DOM。
import type { Cap } from './api';
import { panelDisplay } from './store';

export type CatKey = 'digest' | 'hmac' | 'sym' | 'asym' | 'aead' | 'file' | 'sys' | 'net' | 'other';
export const CATLABEL: Record<CatKey, string> = {
  digest: '摘要', hmac: 'HMAC', sym: '对称', asym: '非对称', aead: 'AEAD',
  file: '文件读写', sys: '系统', net: '网络', other: '其它',
};

export function catClass(c: Cap): CatKey {
  if (!c) return 'other';
  if (c.category === 'net') return 'net';
  if (c.category === 'file') return 'file';
  if (c.category === 'system') return 'sys';
  const a = c.algo || '';
  if (/AEAD|GCM|CCM|ChaCha20-Poly1305/i.test(a)) return 'aead';
  if (/Hmac|HMAC/i.test(a)) return 'hmac';
  if (/MD5|SHA|摘要|Digest/i.test(a)) return 'digest';
  if (/RSA|EC|DSA|非对称/i.test(a)) return 'asym';
  return 'sym';
}

const VAGUE_ALGO = /^(摘要 Digest|对称加解密|HMAC|RSA\/EC 签名|RSA\/EC 验签|RSA 非对称加密|RSA 非对称解密|AEAD 加密\(GCM\/ChaCha20-Poly1305\)|AEAD 解密\(GCM\/ChaCha20-Poly1305\)|TLS|Java Hook|Native Hook)$/;

function clientJavaHook(op: string, hasBody: boolean): string {
  if (op === 'digest') return 'MessageDigest.digest';
  if (op === 'mac') return hasBody ? 'Mac.doFinal' : 'Mac.init';
  if (op === 'sign') return hasBody ? 'Signature.sign' : 'Signature.initSign';
  if (op === 'verify') return hasBody ? 'Signature.verify' : 'Signature.initVerify';
  if (op === 'init') return 'Cipher.init';
  if (op === 'encrypt' || op === 'decrypt' || op === 'wrap' || op === 'unwrap' || op === 'doFinal')
    return hasBody ? 'Cipher.doFinal' : 'Cipher.init';
  return '';
}
function clientJavaDirection(op: string): string {
  if (op === 'encrypt' || op === 'wrap') return '加密';
  if (op === 'decrypt' || op === 'unwrap') return '解密';
  if (op === 'sign') return '签名';
  if (op === 'verify') return '验签';
  if (op === 'digest') return '哈希';
  if (op === 'mac') return '认证';
  return '';
}
function clientNativeView(func: string): { title: string; direction: string } {
  const known: Record<string, [string, string]> = {
    EVP_DigestUpdate: ['摘要 · 未识别', '哈希'], HMAC_Update: ['HMAC · 未识别', '认证'],
    EVP_DigestSignUpdate: ['HMAC · 未识别', '认证'], EVP_DigestVerifyUpdate: ['HMAC · 未识别', '认证'],
    EVP_DSignUpdate_asym: ['签名 · 未识别', '签名'], EVP_DSignFinal_sig: ['签名 · 未识别', '签名'],
    EVP_DVerifyUpdate_asym: ['验签 · 未识别', '验签'], EVP_DVerifyFinal_sig: ['验签 · 未识别', '验签'],
    ECDSA_sign_digest: ['签名 · 未识别', '签名'], ECDSA_sign_sig: ['签名 · 未识别', '签名'],
    ECDSA_verify_digest: ['验签 · 未识别', '验签'], ECDSA_verify_sig: ['验签 · 未识别', '验签'],
    EVP_PKEY_encrypt_in: ['RSA · 未识别', '加密'], EVP_PKEY_encrypt_out: ['RSA · 未识别', '加密'],
    EVP_PKEY_decrypt_in: ['RSA · 未识别', '解密'], EVP_PKEY_decrypt_out: ['RSA · 未识别', '解密'],
    EVP_AEAD_seal_pt: ['AEAD · 未识别', '加密'], EVP_AEAD_seal_ct: ['AEAD · 未识别', '加密'],
    EVP_AEAD_open_ct: ['AEAD · 未识别', '解密'], EVP_AEAD_open_pt: ['AEAD · 未识别', '解密'],
  };
  if (known[func]) return { title: known[func][0], direction: known[func][1] };
  if (func.startsWith('EVP_Encrypt')) return { title: '对称 · 未识别', direction: '加密' };
  if (func.startsWith('EVP_Decrypt')) return { title: '对称 · 未识别', direction: '解密' };
  if (func.startsWith('EVP_Cipher')) return { title: '对称 · 未识别', direction: '' };
  if (func.startsWith('EVP_Digest')) return { title: '摘要 · 未识别', direction: '哈希' };
  return { title: func || '未识别', direction: '' };
}

export interface CaptureLength {
  reported?: number; captured?: number; bytes?: number;
  truncated: boolean; inconsistent: boolean;
}
function captureLength(reported: unknown, hex: unknown): CaptureLength {
  const declared = typeof reported === 'number' && Number.isSafeInteger(reported) && reported >= 0 ? reported : undefined;
  const captured = typeof hex === 'string' && /^(?:[a-f\d]{2})*$/i.test(hex) ? hex.length / 2 : undefined;
  return { reported: declared, captured, bytes: declared ?? captured,
    truncated: declared != null && captured != null && captured < declared,
    inconsistent: declared != null && captured != null && captured > declared };
}
export function captureLengths(c: Cap): { input: CaptureLength; output: CaptureLength } {
  return { input: captureLength(c.inl, c.hex), output: captureLength(c.outl, c.outHex) };
}
export function captureLengthText(length: CaptureLength): string {
  if (length.bytes == null) return '未记录';
  if (length.reported == null) return `${length.bytes} B（已捕获）`;
  const extra = length.captured != null && length.captured !== length.reported
    ? ` · 已捕获 ${length.captured} B${length.inconsistent ? '（长度不一致）' : ''}` : '';
  return `${length.reported} B${extra}`;
}
/** A rich Java observation is a call sample, not a reconstruction of accumulated state.
 * Old records do not tell an absent byte argument from an explicitly empty one. */
export function inputEvidence(c: Cap): { fragment:boolean; emptyText:string; note:string; lengthText:string } {
  const length=captureLengths(c).input,fragment=c.source==='java'&&c.category==='crypto';
  if(!fragment)return {fragment:false,emptyText:'（空字节）',note:'',lengthText:captureLengthText(length)};
  const present=c.inputBytesPresent,nonempty=(length.captured??length.bytes??0)>0;
  return {fragment:true,
    emptyText:present===true?'（本次参数字节为空）':'（本次未捕获输入参数字节）',
    note:nonempty?'仅显示本次调用返回后的参数采样，可能包含输出缓冲区；完整/累积运算输入未记录。':present===true?'本次参数字节为空，不代表整个运算输入为空；累积输入未记录。':'无直接输入的调用或未采集到参数均可能出现此状态；累积输入未记录。',
    lengthText:captureLengthText(length)+'（本次捕获）'};
}
function compactContentPreview(c:Cap,fallback:string,length:CaptureLength):string {
  const binary=()=>`二进制${length.bytes!=null?' · '+length.bytes+' B':''}`;
  if(typeof c.hex==='string'&&c.hex.length&&/^(?:[a-f\d]{2})*$/i.test(c.hex)){
    try{const text=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(c.hex.slice(0,512).match(/../g)??[],p=>parseInt(p,16)),{stream:c.hex.length>512});if(/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text))return binary();return text.slice(0,100);}
    catch{return binary();}
  }
  return fallback&&((fallback.match(/\./g)?.length??0)/fallback.length)<0.3?fallback.slice(0,100):length.bytes?binary():fallback;
}
export interface CryptoView {
  title: string; direction: string; hook: string; sizeLabel: string;
  truncated: boolean; outputTruncated: boolean; hasKey: boolean; preview: string; show: boolean;
}
export function cryptoView(c: Cap): CryptoView {
  const lengths = captureLengths(c);
  const inBytes = lengths.input.bytes ?? 0;
  const outBytes = lengths.output.bytes ?? 0;
  const truncated = lengths.input.truncated;
  const hasBody = inBytes > 0 || outBytes > 0 || (lengths.input.captured ?? 0) > 0 || (lengths.output.captured ?? 0) > 0;
  const algo = (c.algo || '').trim();
  const concrete = algo && !VAGUE_ALGO.test(algo) ? algo : '';
  const func = c.func || '';
  const native = clientNativeView(func);
  const java = c.source === 'java' || (!!func && !func.includes('_') && !func.includes('.'));
  const op = c.op || '';
  const hook = java ? (typeof c.javaTarget==='string'&&c.javaTarget?c.javaTarget:(func.includes('.') ? func : clientJavaHook(op, hasBody))) : func;
  const direction = java ? clientJavaDirection(op) : native.direction;
  const preview = (c.preview || '').trim();
  const readable = preview.replace(/[.\s]/g, '') ? preview : '';
  const compact = (length: CaptureLength) => length.bytes == null ? '' :
    `${length.bytes} B${length.truncated ? ' 截断' : length.inconsistent ? `（捕获 ${length.captured} B，长度不一致）` : ''}`;
  const input = c.source==='java'&&lengths.input.bytes===0?'本次 0 B':compact(lengths.input);
  const output = compact(lengths.output);
  return {
    title: concrete || (java ? '未识别' : native.title),
    direction, hook,
    sizeLabel: input && output ? `${input} → ${output}` : input || output,
    truncated, outputTruncated: lengths.output.truncated, hasKey: !!(c.hasKey || c.keyHex), preview: compactContentPreview(c, readable, lengths.input), show: hasBody,
  };
}

export function httpListPreview(text: string | undefined): string {
  const raw = String(text || '');
  const lines = /[\r\n]/.test(raw) ? raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n') : raw.split('..');
  const line = (lines[0] || '').trim();
  const req = line.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+HTTP\/\d(?:\.\d)?$/i);
  if (req) {
    const method = req[1].toUpperCase();
    const target = req[2];
    if (/^https?:\/\//i.test(target)) return `${method} ${target}`;
    let host = '';
    for (const header of lines.slice(1)) {
      const found = header.match(/^Host:\s*(\S+)/i);
      if (found) { host = found[1]; break; }
    }
    if (host && target.charAt(0) === '/') return `${method} https://${host}${target}`;
    return `${method} ${target}`;
  }
  return line || raw.slice(0, 120);
}

export function systemRow(c: Cap): {method:string;object:string;result:string} {
  const activity=c.activity as Record<string,unknown>|undefined;
  if(activity&&typeof activity.method==='string'&&typeof activity.object==='string'&&typeof activity.result==='string')return activity as {method:string;object:string;result:string};
  let raw=String(c.preview??''),fields:Record<string,unknown>={};
  if(typeof c.hex==='string'&&c.hex.length<=32768&&/^(?:[a-f\d]{2})*$/i.test(c.hex)){
    try{raw=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(c.hex.match(/../g)??[],p=>parseInt(p,16)));}catch{/* use the recorded preview */}
  }
  if(raw.startsWith('{')){try{const parsed=JSON.parse(raw);if(parsed&&typeof parsed==='object'&&!Array.isArray(parsed))fields=parsed;}catch{/* incomplete JSON stays visible */}}
  else for(const part of raw.split('\t')){const i=part.indexOf('=');if(i>0)fields[part.slice(0,i)]=part.slice(i+1);}
  const text=(value:unknown)=>typeof value==='string'||typeof value==='number'?String(value):'';
  const object=c.path||text(fields.path)||text(fields.arg)||(text(fields.name)?text(fields.name)+(text(fields.value)?' = '+text(fields.value):''):'')||raw;
  const result=text(fields.error)?'异常：'+text(fields.error):fields.ret!==undefined?'返回 '+text(fields.ret):fields.result!==undefined?'结果 '+text(fields.result):'';
  return {method:text(fields.target)||String(c.func||c.algo||'未知调用'),object,result};
}

export function rowLens(c: Cap): string {
  if (c.category === 'net') {
    const shown = httpListPreview(c.preview);
    return shown || `in:${c.inl ?? 0}B`;
  }
  if(c.category==='file'||c.category==='system')return systemRow(c).object||'未记录对象';
  let meta = `in:${c.inl ?? 0}B`;
  if (c.outl) meta += ` · out:${c.outl}B`;
  return meta;
}

export function fmtTime(ts?: number): string {
  if (!ts) return '';
  const d = new Date(ts);
  if (!Number.isFinite(d.getTime())) return '';
  const opts = { hour12: false } as const;
  return panelDisplay.time === 'date' ? d.toLocaleString(undefined, opts) : d.toLocaleTimeString(undefined, opts);
}

export function fmtSize(n?: number): string {
  const v = n ?? 0;
  if (v >= 1048576) return `${(v / 1048576).toFixed(1)}M`;
  if (v >= 1024) return `${(v / 1024).toFixed(1)}K`;
  return `${v}B`;
}

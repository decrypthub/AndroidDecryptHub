// 已观察算法 / Hook 显示筛选 —— 移植自 daemon/public/algorithm-observations.js。
// 只读记录元数据，不碰 payload。hidden 键存 localStorage，按包隔离。

import type { Cap } from './api';

export const FAMILIES = Object.freeze({
  digest: '摘要', mac: '消息认证', symmetric: '对称加密', asymmetric: '非对称与签名',
  aead: 'AEAD', tls: '传输加密', kdf: '密钥派生', agreement: '密钥协商', random: '随机数', other: '其他',
} as const);
export const HOOK_GROUPS = Object.freeze({ crypto: '加解密', system: '系统调用', file: '文件读写', net: '网络' } as const);
export type HookCategory = keyof typeof HOOK_GROUPS;

const RULES: Array<[string, string, RegExp]> = [
  ['kdf', 'PBKDF2', /PBKDF2/], ['kdf', 'HKDF', /HKDF/], ['kdf', 'scrypt', /SCRYPT/],
  ['kdf', 'Argon2', /ARGON2/], ['kdf', '密钥派生', /^(?:KDF|密钥派生)$/],
  ['agreement', 'X25519', /X25519/], ['agreement', 'X448', /X448/], ['agreement', 'ECDH', /ECDH/],
  ['agreement', '密钥协商', /^DH$|DIFFIEHELLMAN|密钥协商/],
  ['random', '随机数', /SECURERANDOM|CSPRNG|^(?:RNG|RANDOM)$|随机数/],
  ['tls', 'TLS', /^(?:TLS|SSL)/],
  ['aead', 'ChaCha20-Poly1305', /CHACHA20POLY1305/], ['aead', 'AES-GCM', /AES(?:128|192|256)?GCM/],
  ['aead', 'AES-CCM', /AES(?:128|192|256)?CCM/], ['aead', 'AEAD', /AEAD|^GCM$|^CCM$/],
  ['mac', 'HMAC', /HMAC/], ['mac', 'CMAC', /CMAC/], ['mac', 'Poly1305', /POLY1305/],
  ['asymmetric', 'Ed25519', /ED25519/], ['asymmetric', 'ECDSA', /ECDSA/], ['asymmetric', 'RSA', /RSA/],
  ['asymmetric', 'DSA', /^DSA/], ['asymmetric', '签名与验签', /签名|验签|非对称/],
  ['digest', 'SHA-3', /SHA3(?:224|256|384|512)?$/],
  ['digest', 'SHA-512', /SHA512/], ['digest', 'SHA-384', /SHA384/], ['digest', 'SHA-256', /SHA256/],
  ['digest', 'SHA-224', /SHA224/], ['digest', 'SHA-1', /SHA1/], ['digest', 'MD5', /MD5/],
  ['digest', '摘要', /^(?:SHA|DIGEST)$|摘要/],
  ['symmetric', 'AES', /AES/], ['symmetric', 'ChaCha20', /CHACHA20/], ['symmetric', 'SM4', /SM4/],
  ['symmetric', 'DES', /^(?:(?:TRIPLE)?DES|3DES)(?:CBC|ECB)?$/], ['symmetric', '对称加密', /对称/],
];

type AlgoType = [family: string, name: string];

function identify(record: Cap): AlgoType | undefined {
  const tag = typeof record?.algo === 'string' ? record.algo.slice(0, 96).replace(/[\s_/-]+/g, '').toUpperCase() : '';
  if (record?.category === 'net') return /^(?:TLS|SSL)/.test(tag) ? ['tls', 'TLS'] : undefined;
  if (record?.category !== 'crypto') return;
  // 旧家族标签只列可能性，不代表真实跑过的算法。
  if (/^RSAEC(?:签名|验签)$/.test(tag)) return ['asymmetric', '签名与验签'];
  if (/^AEAD(?:加密|解密)\(/.test(tag)) return ['aead', 'AEAD'];
  const hmac = /^HMAC(?:WITH)?(SHA3(?:224|256|384|512)|SHA(?:1|224|256|384|512)|MD5)$/.exec(tag);
  if (hmac) {
    const hash = hmac[1].replace(/^SHA3(\d{3})$/, 'SHA-3-$1').replace(/^SHA(\d+)$/, 'SHA-$1');
    return ['mac', 'HMAC-' + hash];
  }
  const sha3 = /^SHA3(224|256|384|512)$/.exec(tag);
  if (sha3) return ['digest', 'SHA-3-' + sha3[1]];
  const aesMode = /^AES(?:128|192|256)?(CBC|CTR|CFB(?:8|128)?|OFB|ECB|XTS)(?:NOPADDING|PKCS[57]PADDING|ISO10126PADDING)?$/.exec(tag);
  if (aesMode) return ['symmetric', 'AES-' + aesMode[1]];
  const match = RULES.find(([, , pattern]) => pattern.test(tag));
  return match ? [match[0], match[1]] : ['other', '未识别算法'];
}

const algorithmKeyFor = ([family, name]: AlgoType) => 'algo:' + family + ':' + name;
export function algorithmKey(record: Cap) {
  const type = identify(record);
  return type && algorithmKeyFor(type);
}
const timeOf = (record: Cap) => Number.isFinite(record.ts) && record.ts > 0 ? record.ts : 0;

export interface MethodEntry { source: string; className: string; member: string; label: string; count?: number }
export interface AlgoEntry {
  key: string; family: string; name: string; count: number; shown: number; latest: number;
  methods: MethodEntry[];
}

export function summarize(records: Cap[], hidden = new Set<string>()): AlgoEntry[] {
  const entries = new Map<string, Omit<AlgoEntry, 'methods'> & { methods: Map<string, MethodEntry> }>();
  for (const record of records) {
    const type = identify(record);
    if (!type) continue;
    const [family, name] = type;
    const key = algorithmKeyFor(type);
    if (!entries.has(key)) entries.set(key, { key, family, name, count: 0, shown: 0, latest: 0, methods: new Map() });
    const entry = entries.get(key)!;
    const hk = hookKey(record);
    const shown = !hidden.has(key) && !(hk && hidden.has(hk));
    entry.count++;
    if (shown) entry.shown++;
    entry.latest = Math.max(entry.latest, timeOf(record));
    const method = recordedMethod(record);
    const methodKey = JSON.stringify(method);
    const previous = entry.methods.get(methodKey);
    entry.methods.set(methodKey, { ...method, count: (previous?.count ?? 0) + 1 });
  }
  // 设置页语义：固定名称序。不能按 latest/count 排——采集是实时的，行序会跟着跳，开关点不中。
  return [...entries.values()]
    .map(entry => ({ ...entry, methods: [...entry.methods.values()].sort((a, b) =>
      a.className.localeCompare(b.className) || a.member.localeCompare(b.member) || a.label.localeCompare(b.label)) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

const symbol = (value: unknown) => typeof value === 'string' && /^[\p{L}\p{N}_.$:@+<>-]{1,120}$/u.test(value) ? value : '';
const sourceOf = (record: Cap) => record.source === 'java' || record.source === 'native' ? record.source : '';
const javaIdentifier = /^[\p{L}_$][\p{L}\p{N}_$]*$/u;

function recordedMethod(record: Cap): MethodEntry {
  const source = sourceOf(record);
  const name = symbol(record.func);
  if (source === 'native') return { source, className: '', member: name, label: '' };
  if (source === 'java') {
    const parts = name.split('.');
    const tail = parts.pop()!;
    const valid = javaIdentifier.test(tail) || tail === '<init>' || tail === '<clinit>';
    if (valid && parts.length && parts.every(part => javaIdentifier.test(part))) {
      return { source, className: parts.join('.'), member: tail, label: '' };
    }
    // view.hook 可能是 UI 别名，不是记录到的类。
    const member = valid && !parts.length ? tail : '';
    const label = (name && !member ? name : '') || symbol((record.view as Record<string, unknown> | undefined)?.hook);
    return { source, className: '', member, label: label === member ? '' : label };
  }
  return { source, className: '', member: '', label: name };
}

export interface HookIdentity { key: string; category: string; source: string; name: string }
function hookIdentity(record: Cap): HookIdentity | undefined {
  const category = record?.category;
  if (!category || !Object.hasOwn(HOOK_GROUPS, category)) return;
  const name = symbol(record.func) || symbol((record.view as Record<string, unknown> | undefined)?.hook);
  if (!name) return;
  const source = sourceOf(record);
  return { key: JSON.stringify([category, source, name]), category, source, name };
}
export const hookKey = (record: Cap) => hookIdentity(record)?.key;
export const categoryKey = (category: string) =>
  Object.hasOwn(HOOK_GROUPS, category) ? JSON.stringify(['category', category]) : null;
export const recordVisible = (record: Cap, hidden: Set<string>) => {
  const ck = categoryKey(record?.category ?? '');
  if (ck && hidden.has(ck)) return false;
  const hk = hookKey(record);
  if (hk && hidden.has(hk)) return false;
  const ak = algorithmKey(record);
  return !(ak && hidden.has(ak));
};

export interface HookEntry extends HookIdentity { count: number; latest: number }
export function summarizeHooks(records: Cap[]): HookEntry[] {
  const items = new Map<string, HookEntry>();
  for (const record of records) {
    const hook = hookIdentity(record);
    if (!hook) continue;
    const previous = items.get(hook.key);
    const ts = timeOf(record);
    items.set(hook.key, { ...hook, count: (previous?.count ?? 0) + 1, latest: Math.max(previous?.latest ?? 0, ts) });
  }
  return [...items.values()].sort((a, b) => a.name.localeCompare(b.name) || a.source.localeCompare(b.source));
}

export interface EvidenceMethod extends MethodEntry { count: number }
export interface EvidenceGroup { records: number; uniqueEntries: number; methods: EvidenceMethod[] }
export function sessionHookEvidence(records: Cap[], pkg: string, sessionId: string): Record<string, EvidenceGroup> {
  const groups = new Map<string, { records: number; methods: Map<string, EvidenceMethod> }>(
    Object.keys(HOOK_GROUPS).map(key => [key, { records: 0, methods: new Map() }]));
  if (pkg && sessionId) for (const record of records) {
    if (record?.sessionId !== sessionId || (record.package && record.package !== pkg) ||
        !groups.has(record.category)) continue;
    const group = groups.get(record.category)!;
    group.records++;
    const method = recordedMethod(record);
    if (!method.member && !method.label) continue;
    const key = JSON.stringify(method);
    group.methods.set(key, { ...method, count: (group.methods.get(key)?.count ?? 0) + 1 });
  }
  return Object.fromEntries([...groups.entries()].map(([key, group]) => [key, {
    records: group.records, uniqueEntries: group.methods.size,
    methods: [...group.methods.values()].sort((a, b) => b.count - a.count ||
      a.className.localeCompare(b.className) || a.member.localeCompare(b.member) || a.label.localeCompare(b.label)).slice(0, 32),
  }]));
}

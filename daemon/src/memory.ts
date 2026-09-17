// Live target-memory helpers that combine an agent read with host-side analysis.
// They deliberately live in the daemon: the agent only reads bytes.
import { CAPSTONE_VERSION, disasmBytes } from './capstone.ts';
import { modulesFromMaps, sendCmd } from './service.ts';

export interface LiveDisasmOptions {
  addr?: string | number;
  size?: number;
  module?: string;
  offset?: string | number;
}

function parseAddress(value: string | number | bigint, assumeHex = false): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`invalid address: ${value}`);
    return BigInt(value);
  }
  const text = String(value).trim();
  if (!text) throw new Error('empty address');
  if (/^0x[0-9a-f]+$/i.test(text)) return BigInt(text);
  if (/^[0-9a-f]+$/i.test(text)) {
    return assumeHex || /[a-f]/i.test(text) ? BigInt(`0x${text}`) : BigInt(text);
  }
  throw new Error(`invalid address: ${value}`);
}

function hexAddress(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function findModule(modules: any[], name: string): any {
  const exact = modules.find((m) => m.name === name || m.path === name);
  if (exact) return exact;
  return modules.find((m) => String(m.path ?? '').endsWith(`/${name}`)) ??
    modules.find((m) => String(m.path ?? '').includes(name));
}

/**
 * Read target memory and disassemble it with Capstone on the host.
 * `addr` is an absolute address; alternatively `module` + `offset` resolves the module
 * base from the agent's live /proc/self/maps before reading.
 */
export async function liveDisasm(sid: string, opts: LiveDisasmOptions): Promise<any> {
  let address: bigint | null = null;
  let resolvedFrom: string | null = null;
  if (opts.addr !== undefined && opts.addr !== null && String(opts.addr).trim() !== '') {
    address = parseAddress(opts.addr, true);
  } else if (opts.module && opts.offset !== undefined && opts.offset !== null) {
    const maps = await sendCmd(sid, 'maps');
    if (!maps.ok) throw new Error(maps.error ?? 'maps command failed');
    const mod = findModule(modulesFromMaps(maps.regions ?? []), String(opts.module));
    if (!mod) throw new Error(`module not found: ${opts.module}`);
    const moduleOffset = parseAddress(opts.offset);
    address = BigInt(`0x${String(mod.base).replace(/^0x/i, '')}`) + moduleOffset;
    resolvedFrom = `${opts.module}+${hexAddress(moduleOffset)}`;
  }
  if (address === null) throw new Error('need addr or module+offset');
  if (address % 4n !== 0n) throw new Error(`address must be 4-byte aligned for AArch64: ${hexAddress(address)}`);

  const requested = Math.max(4, Math.min(65536, Math.trunc(Number(opts.size ?? 256))));
  const aligned = requested - (requested % 4) || 4;
  const r = await sendCmd(sid, 'read', { addr: hexAddress(address), size: aligned }, 20_000);
  if (!r.ok) throw new Error(r.error ?? 'memory read failed');
  const raw = Buffer.from(String(r.b64 ?? ''), 'base64');
  if (!raw.length) throw new Error('memory read returned no bytes');
  const usableLength = raw.length - (raw.length % 4);
  if (usableLength < 4) throw new Error(`memory read returned too few bytes: ${raw.length}`);
  const instructions = await disasmBytes(
    raw.subarray(0, usableLength),
    address,
    Math.min(4096, Math.floor(usableLength / 4)),
  );
  const decodedBytes = instructions.reduce((n, i) => n + Math.floor(i.bytes.length / 2), 0);
  return {
    addr: hexAddress(address),
    resolvedFrom,
    requestedSize: aligned,
    readSize: raw.length,
    shortRead: raw.length < aligned,
    trailingBytes: raw.length - usableLength,
    engine: 'capstone-wasm',
    capstone: CAPSTONE_VERSION,
    count: instructions.length,
    decodedBytes,
    undecodedBytes: raw.length - decodedBytes,
    instructions,
  };
}
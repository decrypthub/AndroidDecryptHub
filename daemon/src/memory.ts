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

/**
 * Canonical form of a caller-supplied address for the agent. The agent parses addresses with
 * strtoull(...,0), so the text the daemon validated and the text the agent acts on must be the
 * same string - this is the single place that decides how a bare address is read.
 */
export function normalizeAddressForAgent(addr: string): string {
  return hexAddress(parseAddress(addr));
}

/** Thrown when a module name matches more than one loaded module. */
/**
 * Classify an absolute address against the live maps: is it mapped at all, and is that mapping
 * executable? Used before an arbitrary native call so a stale address (unloaded module, typo) fails
 * here instead of jumping into unmapped memory inside the target.
 */
export interface AddressClass { mapped: boolean; executable: boolean; path?: string; }

/**
 * Host-side guard shared by every native_call entry point (MCP tool and REST route): a raw address
 * must be mapped AND executable before the agent is asked to call it. Kept here so the two paths
 * cannot drift - the REST route used to skip the check the MCP tool performed.
 */
export async function assertCallableAddress(sid: string, addr: unknown): Promise<{ ok: true; addr: string } | { ok: false; error: string }> {
  // A missing address (undefined / null / '' / 0) means "use module+symbol"; anything else is text.
  // JSON callers that send addr:0 with module+symbol used to have it stringified into "0" and
  // rejected as unmapped instead of falling back to the symbol path.
  const given = addr === undefined || addr === null || addr === '' || addr === 0;
  const trimmed = given ? '' : String(addr).trim();
  if (!trimmed) return { ok: true, addr: '' };            // module+symbol path; the agent resolves it
  const maps = await sendCmd(sid, 'maps');
  if (!maps.ok) throw new Error(maps.error ?? 'maps command failed');
  const cls = classifyAddress(maps.regions ?? [], trimmed);
  if (!cls.mapped) return { ok: false, error: `addr ${trimmed} is not in any mapped region of the target (stale or wrong)` };
  if (!cls.executable) return { ok: false, error: `addr ${trimmed} is mapped${cls.path ? ' (' + cls.path + ')' : ''} but not executable - refusing to use it as a call or hook target` };
  // Hand back the address that was actually checked (v4.99). The agent parses with strtoull(...,0),
  // where a bare digit string is decimal - or octal with a leading zero - so forwarding the caller's
  // original text could reach a different address than the one validated here ("010000000000" is
  // 10_000_000_000 to this guard and 0x40000000 to strtoull). The normalized 0x form is
  // unambiguous for both sides, and it also drops the surrounding whitespace that used to send a
  // padded string into the agent's addr branch instead of the module+symbol path.
  return { ok: true, addr: normalizeAddressForAgent(trimmed) };
}

export function classifyAddress(regions: MapsRegion[], addr: string | bigint | number): AddressClass {
  let value: bigint;
  try {
    value = typeof addr === 'bigint' ? addr : BigInt(parseAddress(addr));
  } catch {
    return { mapped: false, executable: false };
  }
  for (const r of regions) {
    const start = BigInt('0x' + String(r.start).replace(/^0x/i, ''));
    const end = BigInt('0x' + String(r.end).replace(/^0x/i, ''));
    if (value >= start && value < end) {
      return { mapped: true, executable: String(r.perms ?? '').includes('x'), path: r.path || undefined };
    }
  }
  return { mapped: false, executable: false };
}

export class ModuleAmbiguousError extends Error {
  candidates: string[];
  constructor(name: string, candidates: string[]) {
    super(`ambiguous module '${name}': ${candidates.join(', ')}`);
    this.candidates = candidates;
  }
}

/**
 * Resolve a module name against the live maps: exact basename/path first, then a unique suffix
 * match, and only then a unique substring match. `libc` used to silently pick whichever of
 * libc.so / libc++.so / libcutils.so the map order happened to hit first; ambiguity is an error.
 */
export function resolveModule(modules: any[], name: string): any {
  const exact = modules.find((m) => m.name === name || m.path === name);
  if (exact) return exact;
  const suffix = modules.filter((m) => String(m.path ?? '').endsWith(`/${name}`));
  if (suffix.length === 1) return suffix[0];
  if (suffix.length > 1) throw new ModuleAmbiguousError(name, suffix.map((m) => m.name));
  const loose = modules.filter((m) => String(m.path ?? '').includes(name));
  if (loose.length === 1) return loose[0];
  if (loose.length > 1) throw new ModuleAmbiguousError(name, loose.map((m) => m.name));
  return undefined;
}

const findModule = resolveModule;   // kept for the existing call sites in this module

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
    if (!(Number(mod.size) > 0) || moduleOffset >= BigInt(mod.size)) {
      throw new Error(`offset 0x${moduleOffset.toString(16)} is outside ${mod.name} (size ${mod.size} bytes)`);
    }
    address = BigInt(`0x${String(mod.base).replace(/^0x/i, '')}`) + moduleOffset;
    resolvedFrom = `${opts.module}+${hexAddress(moduleOffset)}`;
  }
  if (address === null) throw new Error('need addr or module+offset');
  if (address % 4n !== 0n) throw new Error(`address must be 4-byte aligned for AArch64: ${hexAddress(address)}`);

  // Number(undefined)/NaN used to become 4 through Math.max, so a typo disassembled four bytes and
  // looked like an answer. The size has to be a positive number now; the ceiling still clamps.
  const rawSize = Number(opts.size ?? 256);
  if (!Number.isFinite(rawSize) || rawSize <= 0) throw new Error(`size must be a positive number (got ${opts.size})`);
  const requested = Math.max(4, Math.min(65536, Math.trunc(rawSize)));
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
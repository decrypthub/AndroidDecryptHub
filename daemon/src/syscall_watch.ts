// Host-orchestrated direct-syscall watch. The agent stays execution-only: this module
// reconstructs one loaded ELF, finds `svc #0` sites with the existing static scanner,
// then asks the native-hook manager to inline-hook those exact addresses. NATIVE_HOOK
// events carry x0-x8; for a syscall site x8 is the syscall number.
import { svcScan } from './analysis.ts';
import { modulesFromMaps, reconstructSo, sendCmd } from './service.ts';
import { resolveModule } from './memory.ts';   // one strict module-name resolution for the whole daemon
import { nativeHookInstallPayload, normalizeThrottleMs } from './native_hook_args.ts';

export interface SyscallWatchOptions {
  module: string;
  limit?: number;
  // Only hook sites whose syscall number could be attributed statically. Numbers or names
  // ("uname", 160, "0xa0") are accepted; a filter that matches nothing fails loud instead of
  // silently hooking the wrong sites.
  syscalls?: (string | number)[] | string;
  // Per-hook event throttle in ms (0 = every hit emits). Hot syscalls (read/write/futex) produce
  // more events than the capture ring holds; the agent then reports at most one event per site per
  // window and counts the rest, so the digest stays honest instead of lossy.
  throttleMs?: number;
}

function hexAddress(value: bigint): string {
  return `0x${value.toString(16)}`;
}

export interface SvcSite {
  addr: bigint;
  vaddr: string;
  fileOff: string;
  nr: number | null;
  name: string | null;
  attribution: string;
}

/**
 * One inline hook per selected svc site. The sender is injectable so the payload that really reaches
 * the agent (backtrace:true plus throttleMs) is covered by a unit test, and the return shape is
 * deliberate: on a mid-batch failure the caller still receives the hooks that WERE installed, because
 * an unrolled-back watch would keep emitting events for the rest of the session.
 */
export async function installSvcSiteHooks(
  sid: string,
  sites: SvcSite[],
  throttleMs: number | undefined,
  send: typeof sendCmd = sendCmd,
): Promise<{ installed: any[]; error: Error | null }> {
  const installed: any[] = [];
  for (const site of sites) {
    const addr = site.addr;
    // v4.39: each event carries the caller chain captured at the hit, so a syscall can be attributed
    // to the app function that issued it instead of only to libc.
    const r = await send(sid, 'native_hook', nativeHookInstallPayload({
      addr: hexAddress(addr), backtrace: true, throttleMs,
    }), 20_000).catch((e) => ({ ok: false, error: (e as Error).message }));
    if (!r?.ok) return { installed, error: new Error(`svc hook failed at ${hexAddress(addr)}: ${r?.error ?? 'unknown error'}`) };
    installed.push({
      hookId: Number(r.hookId), addr: hexAddress(addr), vaddr: site.vaddr, fileOff: site.fileOff,
      syscall: site.nr == null ? null : { nr: site.nr, name: site.name },
      attribution: site.attribution,
    });
  }
  return { installed, error: null };
}

// arm64 syscall numbers (asm-generic) with the names an analyst actually filters on. The table is a
// convenience only - the number from the site is always reported next to it, and an unknown number
// stays unknown rather than being guessed.
const SYSCALL_NAMES: Record<number, string> = {
  29: 'ioctl', 48: 'faccessat', 56: 'openat', 57: 'close', 61: 'getdents64', 63: 'read', 64: 'write',
  79: 'newfstatat', 80: 'fstat', 98: 'futex', 101: 'nanosleep', 113: 'clock_gettime', 117: 'ptrace',
  129: 'kill', 131: 'tgkill', 160: 'uname', 167: 'prctl', 169: 'gettimeofday', 172: 'getpid',
  174: 'getuid', 175: 'geteuid', 176: 'getgid', 177: 'getegid', 178: 'gettid', 179: 'sysinfo',
  183: 'sethostname', 198: 'socket', 203: 'connect', 206: 'sendto', 207: 'recvfrom', 211: 'sendmsg',
  212: 'recvmsg', 215: 'munmap', 220: 'clone', 221: 'execve', 222: 'mmap', 226: 'mprotect',
  233: 'madvise', 260: 'wait4', 273: 'set_robust_list', 278: 'getrandom', 279: 'memfd_create',
  291: 'statx',
};

export function syscallName(nr: number): string { return SYSCALL_NAMES[nr] ?? `syscall_${nr}`; }
export function syscallTable(): Record<number, string> { return { ...SYSCALL_NAMES }; }

export function parseSyscallToken(token: string | number): number | null {
  if (typeof token === 'number') return Number.isFinite(token) ? Math.trunc(token) : null;
  const t = String(token).trim().toLowerCase();
  if (!t) return null;
  if (/^0x[0-9a-f]+$/.test(t)) return parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return parseInt(t, 10);
  const byName = Object.entries(SYSCALL_NAMES).find(([, name]) => name === t);
  return byName ? Number(byName[0]) : null;
}

export function resolveSyscallFilter(input: SyscallWatchOptions['syscalls']): { wanted: Set<number>; bad: string[] } | null {
  if (input == null) return null;
  const list = Array.isArray(input) ? input : String(input).split(',');
  const wanted = new Set<number>();
  const bad: string[] = [];
  for (const raw of list) {
    const token = String(raw).trim();
    if (!token) continue;
    const nr = parseSyscallToken(token);
    if (nr == null) bad.push(token); else wanted.add(nr);
  }
  // An empty filter ("", [] or only commas) means "no filter" - not "match nothing", which used to
  // fail with a message that did not even name a target.
  if (!wanted.size && !bad.length) return null;
  return { wanted, bad };
}

// Statically attribute the syscall number of one `svc #0` site by looking at the instructions right
// before it: bionic (and most compilers) materialise the number with MOVZ/MOV into x8/w8. The scan is
// pure byte arithmetic over the reconstructed file - no disassembler needed - and stops at the first
// control-flow instruction so a number that belongs to a neighbouring stub is never borrowed.
// NOTE: JS bitwise operators produce SIGNED int32 results, so 0xd2800008 & mask is negative and
// never === the positive literal. Every masked comparison below is forced unsigned with >>> 0.
function maskOf(word: number, mask: number): number { return (word & mask) >>> 0; }

function isControlFlow(word: number): boolean {
  if (maskOf(word, 0xffe0001f) === 0xd4000001) return true;     // svc
  if (maskOf(word, 0xff000000) === 0xd4000000) return true;     // other exception-generating
  if (maskOf(word, 0x7c000000) === 0x14000000) return true;     // b / bl
  if (maskOf(word, 0x7e000000) === 0x34000000) return true;     // cbz / cbnz
  if (maskOf(word, 0x7e000000) === 0x36000000) return true;     // tbz / tbnz
  if (maskOf(word, 0xff000010) === 0x54000000) return true;     // b.cond
  if (maskOf(word, 0xfffffc1f) === 0xd65f0000) return true;     // ret
  if (maskOf(word, 0xfffffc1f) === 0xd61f0000) return true;     // br
  if (maskOf(word, 0xfffffc1f) === 0xd63f0000) return true;     // blr
  return false;
}

// Conservative "might this instruction write x8/w8?" test, used to refuse an attribution when some
// instruction CLOSER to the svc could have overwritten the register we are about to trust. False
// positives only cost coverage (the site is reported as ambiguous); false negatives would produce a
// confident wrong number, which is the failure mode that matters.
function mayWriteX8(word: number): boolean {
  const w = word >>> 0;
  // Loads: LDR/STR family - bit 22 = 1 means load (writes Rt), 0 means store (does not).
  if ((w & 0x3b000000) === 0x39000000) return ((w >>> 22) & 1) === 1 && (w & 0x1f) === 8;
  // Pair loads/stores: LDP/STP family.
  if ((w & 0x3a000000) === 0x28000000) {
    if (((w >>> 22) & 1) !== 1) return false;
    return (w & 0x1f) === 8 || ((w >>> 10) & 0x1f) === 8;
  }
  // Everything else that can write a register (ALU/mov-family): conservative destination guess.
  if (isControlFlow(w)) return false;
  return (w & 0x1f) === 8;
}

export function attributeSite(buf: Buffer, fileOff: number): { nr: number | null; how: string; insns: string[] } {
  const insns: string[] = [];
  // Walking from the svc BACKWARDS: everything seen so far is CLOSER to the svc than the candidate we
  // are about to accept, so any of them writing x8 invalidates that candidate.
  let shadowed = false;
  for (let i = 1; i <= 10; i++) {
    const off = fileOff - i * 4;
    if (off < 0) break;
    const word = buf.readUInt32LE(off);
    const masked = maskOf(word, 0xffe0001f);
    // MOVZ x8/w8, #imm16  -> 0xd2800008 / 0x52800008 (sf / 32-bit)
    if (masked === 0xd2800008 || masked === 0x52800008) {
      const nr = (word >>> 5) & 0xffff;
      insns.push(`movz ${(word & 0x80000000) ? 'x8' : 'w8'}, #${nr}`);
      if (shadowed) return { nr: null, how: 'ambiguous-write', insns };
      return { nr, how: 'movz-imm', insns };
    }
    // MOVZ x8/w8, #imm16, lsl #16
    if (masked === 0xd2a00008 || masked === 0x52a00008) {
      const half = (word >>> 5) & 0xffff;
      insns.push(`movz ${(word & 0x80000000) ? 'x8' : 'w8'}, #${half}, lsl #16`);
      if (shadowed) return { nr: null, how: 'ambiguous-write', insns };
      // A MOVK closer to the svc would complete the constant; we do not model that pairing, so a
      // value that is only the high half stays ambiguous rather than half-right.
      return { nr: half << 16, how: 'movz-imm-lsl16', insns };
    }
    // MOVK x8 (keep) is part of a two-instruction constant: unmodelled, so refuse it.
    if (masked === 0xf2800008 || masked === 0x72800008) {
      insns.push('movk x8 (unmodelled)');
      shadowed = true;
      continue;
    }
    if (mayWriteX8(word)) {
      insns.push('x8-write@' + off.toString(16));
      shadowed = true;
    }
    if (isControlFlow(word)) { insns.push('stop@' + off.toString(16)); break; }
  }
  return { nr: null, how: shadowed ? 'ambiguous-write' : 'unknown', insns };
}

const findModule = resolveModule;   // exact -> unique suffix -> unique substring, else throw

export async function watchSyscalls(sid: string, opts: SyscallWatchOptions): Promise<any> {
  if (!opts.module) throw new Error('need module');
  const maps = await sendCmd(sid, 'maps');
  if (!maps.ok) throw new Error(maps.error ?? 'maps command failed');
  const mod = findModule(modulesFromMaps(maps.regions ?? []), opts.module);
  if (!mod) throw new Error(`module not found: ${opts.module}`);

  const buf = await reconstructSo(sid, String(mod.base));
  const scan = svcScan(buf);
  const scanTruncated = (scan as any).truncated === true;
  const limit = Math.max(1, Math.min(16, Math.trunc(Number(opts.limit ?? 8))));
  const base = BigInt(`0x${String(mod.base).replace(/^0x/i, '')}`);

  // Attribute every site (cheap: a few words of arithmetic each, bounded by the scanner's 4096 cap),
  // then either take the first N or only the ones the caller filtered for.
  const attributed = scan.hits.map((hit) => {
    const fileOff = Number(BigInt(String(hit.fileOff)));
    const attr = attributeSite(buf, fileOff);
    return {
      ...hit,
      fileOffNum: fileOff,
      nr: attr.nr,
      name: attr.nr == null ? null : syscallName(attr.nr),
      attribution: attr.how,
    };
  });
  const filter = resolveSyscallFilter(opts.syscalls);
  if (filter && filter.bad.length) {
    throw new Error(`unknown syscall filter value(s): ${filter.bad.join(', ')} (use a number or one of: ${Object.values(SYSCALL_NAMES).join(', ')})`);
  }
  const matched = filter ? attributed.filter((a) => a.nr != null && filter.wanted.has(a.nr)) : attributed;
  if (filter && matched.length === 0) {
    const known = attributed.filter((a) => a.nr != null).length;
    throw new Error(`no svc #0 site matched ${[...filter.wanted].map((n) => `${syscallName(n)}(${n})`).join('/')} in ${mod.name}: attributed ${known} of ${attributed.length} sites`);
  }
  const selected = matched.slice(0, limit);
  const sites: SvcSite[] = selected.map((hit) => ({
    addr: base + BigInt(String(hit.vaddr)),
    vaddr: String(hit.vaddr), fileOff: String(hit.fileOff),
    nr: hit.nr, name: hit.name, attribution: hit.attribution,
  }));
  const { installed, error } = await installSvcSiteHooks(sid, sites, opts.throttleMs);
  if (error) {
    // A half-installed watch must not be left running: the caller gets the error, the process gets
    // its syscalls back.
    for (const hook of installed) {
      await sendCmd(sid, 'native_hook', { action: 'unhook', hookId: hook.hookId }, 20_000).catch(() => null);
    }
    throw error;
  }

  const throttleMs = normalizeThrottleMs(opts.throttleMs);
  return {
    module: mod.name,
    base: mod.base,
    throttleMs,
    execSegs: scan.execSegs,
    scannedBytes: scan.scanned,
    svcCount: scan.hits.length,
    limit,
    installedCount: installed.length,
    truncated: matched.length > limit,
    scanTruncated,
    filter: filter ? [...filter.wanted].map((n) => ({ nr: n, name: syscallName(n) })) : null,
    attributedCount: attributed.filter((a) => a.nr != null).length,
    unknownCount: attributed.filter((a) => a.nr == null).length,
    matchedCount: matched.length,
    hooks: installed,
    event: 'NATIVE_HOOK',
    syscallRegister: 'x8',
    note: (filter
      ? 'Only sites whose syscall number was attributed statically AND matched the filter are hooked; x8 in the events is the runtime number (should equal the attributed one).'
      : 'Events from these hooks carry x8 as the syscall number; hooks[] reports the statically attributed number per site. Unhook with native_hook/unhook per hookId.')
      + (scanTruncated ? ' WARNING: the static scanner hit its 4096-site cap, so later sites were not examined.' : '')
      + (throttleMs ? ` Each hook emits at most one event per ${throttleMs} ms; NATIVE_HOOK events carry throttleMs/throttled and status reports the running total, so emitted events = hits - throttled.` : '')
      + ' Events also carry the caller chain (bt) for native_backtrace.',
  };
}
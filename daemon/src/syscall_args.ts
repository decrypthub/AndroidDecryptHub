// Decode the ARGUMENTS of a watched syscall from the register snapshot the hook captured.
//
// "uname was called" is rarely the answer an analyst wants; "which file was opened" / "which syscall
// number was requested" is. The NATIVE_HOOK event already carries x0-x8, and the agent can read the
// target's memory, so a pointer argument can be turned into the actual string/struct. The decoding
// itself is pure: the caller pre-reads the bytes the plan asks for, which keeps this unit-testable
// without a device.
export interface ArgRead { reg: number; addr: bigint; len: number; why: string }
export interface DecodedArg { name: string; kind: string; value: string; note?: string }

export interface ArgPlan { reads: ArgRead[]; decode: string }

// Values taken from the NDK's asm-generic/fcntl.h (arm64 uses asm-generic): the first version of
// this table had O_PATH/O_SYNC/O_TMPFILE shifted by hand and reported the fingerprint-relevant
// "O_PATH|O_CLOEXEC" probe as "O_SYNC". Composite values come first so the bit loop matches them
// before their components.
const OPEN_FLAGS: [number, string][] = [
  [0x101000, 'O_SYNC'], [0x420000, 'O_TMPFILE'],
  [0x40, 'O_CREAT'], [0x80, 'O_EXCL'], [0x100, 'O_NOCTTY'], [0x200, 'O_TRUNC'], [0x400, 'O_APPEND'],
  [0x800, 'O_NONBLOCK'], [0x1000, 'O_DSYNC'], [0x4000, 'O_DIRECT'], [0x10000, 'O_LARGEFILE'],
  [0x20000, 'O_DIRECTORY'], [0x40000, 'O_NOFOLLOW'], [0x80000, 'O_CLOEXEC'], [0x100000, 'O_NOATIME'],
  [0x200000, 'O_PATH'], [0x400000, 'O_TMPFILE_BASE'],
];
const ACCESS_MODES: [number, string][] = [[0, 'F_OK'], [1, 'X_OK'], [2, 'W_OK'], [4, 'R_OK']];
const SOCKET_DOMAINS: Record<number, string> = { 1: 'AF_UNIX', 2: 'AF_INET', 10: 'AF_INET6', 16: 'AF_NETLINK' };
const SOCKET_TYPES: Record<number, string> = { 1: 'SOCK_STREAM', 2: 'SOCK_DGRAM', 3: 'SOCK_RAW', 5: 'SOCK_SEQPACKET' };
const AT_FDCWD_SIGNED = -100n;

/** Normalise a register value that may be the 64-bit or 32-bit two's-complement of a negative int. */
function asSigned32(v: bigint): bigint {
  const low = v & 0xffffffffn;
  return BigInt.asIntN(32, low);
}

function translate(value: bigint, table: [number, string][], fallbackHex = true): string {
  const v = Number(value & 0xffffffffn);
  const parts: string[] = [];
  let rest = v;
  for (const [bit, name] of table) {
    if (bit === 0) continue;
    if ((v & bit) === bit) { parts.push(name); rest &= ~bit; }
  }
  if (v === 0) {
    const zero = table.find(([bit]) => bit === 0);
    if (zero) parts.push(zero[1]);
  }
  if (rest && fallbackHex) parts.push(`0x${rest.toString(16)}`);
  return parts.length ? parts.join('|') : (fallbackHex ? `0x${v.toString(16)}` : '0');
}

export function hexValue(v: bigint): string { return `${v < 0n ? '-' : ''}0x${(v < 0n ? -v : v).toString(16)}`; }

// openat flags: the low two bits are the ACCESS MODE (not a bit flag), so "0x80000" must read as
// O_RDONLY|O_CLOEXEC rather than only O_CLOEXEC.
export function decodeOpenFlags(value: bigint): string {
  const bits = Number(value & 0xffffffffn);
  const access = ['O_RDONLY', 'O_WRONLY', 'O_RDWR'][bits & 3] ?? `access=${bits & 3}`;
  const parts = [access];
  let rest = bits & ~3;
  for (const [bit, name] of OPEN_FLAGS) {
    if (bit < 3) continue;
    if ((bits & bit) === bit) { parts.push(name); rest &= ~bit; }
  }
  if (rest) parts.push(`0x${rest.toString(16)}`);
  return parts.join('|');
}

/** Which pointer arguments must be read (and how much) before decoding. */
export function argPlan(nr: number, regs: bigint[]): ArgPlan {
  const r = (i: number) => regs[i] ?? 0n;
  switch (nr) {
    // openat(dirfd, path, flags, mode)
    case 56: return { reads: [{ reg: 1, addr: r(1), len: 256, why: 'path' }], decode: 'openat' };
    // faccessat(dirfd, path, mode, flags)
    case 48: return { reads: [{ reg: 1, addr: r(1), len: 256, why: 'path' }], decode: 'faccessat' };
    // newfstatat(dirfd, path, statbuf, flags)
    case 79: return { reads: [{ reg: 1, addr: r(1), len: 256, why: 'path' }], decode: 'newfstatat' };
    // uname(buf)
    case 160: return { reads: [{ reg: 0, addr: r(0), len: 390, why: 'utsname' }], decode: 'uname' };
    // memfd_create(name, flags)
    case 279: return { reads: [{ reg: 0, addr: r(0), len: 256, why: 'name' }], decode: 'memfd_create' };
    // connect(fd, sockaddr, addrlen)
    case 203: {
      // addrlen is the third argument: reading 28 bytes for a sockaddr_in (16) walks into whatever
      // follows it, which may be unmapped and cost us the whole decode.
      const addrlen = Number(r(2) & 0xffffn);
      const len = Math.max(16, Math.min(addrlen || 28, 128));
      return { reads: [{ reg: 1, addr: r(1), len, why: 'sockaddr' }], decode: 'connect' };
    }
    default: return { reads: [], decode: 'raw' };
  }
}

function cstring(buf: Buffer | null | undefined, cap = 256): string | null {
  if (!buf || !buf.length) return null;
  const end = buf.indexOf(0);
  // No terminator means the read stopped before the end of the string (short read / unmapped page):
  // returning the printable prefix would fabricate a path that was never a complete one.
  if (end < 0) return null;
  const text = buf.subarray(0, Math.min(end, cap)).toString('utf8');
  // Bounded/printable check: a pointer that was not a string should not become garbage in the report.
  if (!text || /[\uFFFD\u0000-\u001f]/.test(text)) return null;
  return text.length > 200 ? text.slice(0, 200) + '...' : text;
}

export function decodeArgs(nr: number, regs: bigint[], mem: Record<number, Buffer | null | undefined> = {}): DecodedArg[] {
  const r = (i: number) => regs[i] ?? 0n;
  const fd = (v: bigint) =>
    (v === AT_FDCWD_SIGNED || asSigned32(v) === AT_FDCWD_SIGNED) ? 'AT_FDCWD' : String(Number(v & 0xffffffffn));
  switch (nr) {
    case 56: return [
      { name: 'dirfd', kind: 'fd', value: fd(r(0)) },
      { name: 'path', kind: 'string', value: cstring(mem[1]) ?? `${hexValue(r(1))} (unreadable)` },
      { name: 'flags', kind: 'flags', value: decodeOpenFlags(r(2)) },
      { name: 'mode', kind: 'hex', value: hexValue(r(3)) },
    ];
    case 48: return [
      { name: 'dirfd', kind: 'fd', value: fd(r(0)) },
      { name: 'path', kind: 'string', value: cstring(mem[1]) ?? `${hexValue(r(1))} (unreadable)` },
      { name: 'mode', kind: 'flags', value: translate(r(2), ACCESS_MODES, false) },
    ];
    case 79: return [
      { name: 'dirfd', kind: 'fd', value: fd(r(0)) },
      { name: 'path', kind: 'string', value: cstring(mem[1]) ?? `${hexValue(r(1))} (unreadable)` },
      { name: 'flags', kind: 'hex', value: hexValue(r(3)) },
    ];
    case 160: {
      const buf = mem[0];
      if (!buf || buf.length < 6 * 65) return [{ name: 'utsname', kind: 'ptr', value: `${hexValue(r(0))} (unreadable)` }];
      const field = (i: number) => cstring(buf.subarray(i * 65, (i + 1) * 65), 65) ?? '';
      return [
        { name: 'sysname', kind: 'string', value: field(0) },
        { name: 'nodename', kind: 'string', value: field(1) },
        { name: 'release', kind: 'string', value: field(2) },
        { name: 'version', kind: 'string', value: field(3) },
        { name: 'machine', kind: 'string', value: field(4) },
        { name: 'domainname', kind: 'string', value: field(5) },
      ];
    }
    case 279: return [
      { name: 'name', kind: 'string', value: cstring(mem[0], 256) ?? `${hexValue(r(0))} (unreadable)` },
      { name: 'flags', kind: 'hex', value: hexValue(r(1)) },
    ];
    case 203: {
      const buf = mem[1];
      const len = Number(r(2) & 0xffffn);
      if (!buf || buf.length < 2) return [{ name: 'sockaddr', kind: 'ptr', value: `${hexValue(r(1))} (unreadable)` }];
      const family = buf.readUInt16LE(0);
      if (family === 2 && buf.length >= 8) {
        const port = buf.readUInt16BE(2);
        const addr = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
        return [
          { name: 'fd', kind: 'fd', value: String(Number(r(0) & 0xffffffffn)) },
          { name: 'family', kind: 'enum', value: 'AF_INET' },
          { name: 'addr', kind: 'string', value: `${addr}:${port}` },
          { name: 'addrlen', kind: 'int', value: String(len) },
        ];
      }
      if (family === 10 && buf.length >= 24) {
        const port = buf.readUInt16BE(2);
        const raw = buf.subarray(8, 24);
        const groups: string[] = [];
        for (let i = 0; i < 16; i += 2) groups.push(raw.readUInt16BE(i).toString(16));
        return [
          { name: 'fd', kind: 'fd', value: String(Number(r(0) & 0xffffffffn)) },
          { name: 'family', kind: 'enum', value: 'AF_INET6' },
          { name: 'addr', kind: 'string', value: `[${groups.join(':')}]:${port}` },
          { name: 'addrlen', kind: 'int', value: String(len) },
        ];
      }
      return [
        { name: 'fd', kind: 'fd', value: String(Number(r(0) & 0xffffffffn)) },
        { name: 'family', kind: 'enum', value: SOCKET_DOMAINS[family] ?? `unknown(${family})` },
        { name: 'addrlen', kind: 'int', value: String(len) },
      ];
    }
    case 29: return [
      { name: 'fd', kind: 'fd', value: String(Number(r(0) & 0xffffffffn)) },
      { name: 'request', kind: 'hex', value: hexValue(r(1)) },
      { name: 'arg', kind: 'hex', value: hexValue(r(2)) },
    ];
    case 198: return [
      { name: 'domain', kind: 'enum', value: SOCKET_DOMAINS[Number(r(0) & 0xffn)] ?? hexValue(r(0)) },
      { name: 'type', kind: 'enum', value: SOCKET_TYPES[Number(r(1) & 0xffn)] ?? hexValue(r(1)) },
      { name: 'protocol', kind: 'int', value: String(Number(r(2) & 0xffffn)) },
    ];
    case 63: case 64: return [
      { name: 'fd', kind: 'fd', value: String(Number(r(0) & 0xffffffffn)) },
      { name: nr === 63 ? 'buf' : 'buf', kind: 'ptr', value: hexValue(r(1)) },
      { name: 'count', kind: 'int', value: String(Number(r(2) & 0xffffffffn)) },
    ];
    case 278: return [
      { name: 'buf', kind: 'ptr', value: hexValue(r(0)) },
      { name: 'len', kind: 'int', value: String(Number(r(1) & 0xffffffffn)) },
      { name: 'flags', kind: 'hex', value: hexValue(r(2)) },
    ];
    case 129: return [
      { name: 'pid', kind: 'int', value: String(Number(r(0) & 0xffffffffn)) },
      { name: 'sig', kind: 'int', value: String(Number(r(1) & 0xffffffffn)) },
    ];
    case 131: return [
      { name: 'tgid', kind: 'int', value: String(Number(r(0) & 0xffffffffn)) },
      { name: 'tid', kind: 'int', value: String(Number(r(1) & 0xffffffffn)) },
      { name: 'sig', kind: 'int', value: String(Number(r(2) & 0xffffffffn)) },
    ];
    case 167: return [
      { name: 'option', kind: 'hex', value: hexValue(r(0)) },
      { name: 'arg2', kind: 'hex', value: hexValue(r(1)) },
      { name: 'arg3', kind: 'hex', value: hexValue(r(2)) },
    ];
    default: return [
      { name: 'x0', kind: 'hex', value: hexValue(r(0)) },
      { name: 'x1', kind: 'hex', value: hexValue(r(1)) },
      { name: 'x2', kind: 'hex', value: hexValue(r(2)) },
    ];
  }
}

/** One line for a group example: "path=/proc/cpuinfo flags=O_RDONLY". */
export function summarizeArgs(args: DecodedArg[]): string {
  return args.map((a) => `${a.name}=${a.value}`).join(' ');
}

/** The path-ish argument of a syscall, for the "which files does it probe" histogram. */
export function pathOf(nr: number, args: DecodedArg[]): string | null {
  if (nr !== 56 && nr !== 48 && nr !== 79 && nr !== 279) return null;
  const key = nr === 279 ? 'name' : 'path';
  const arg = args.find((a) => a.name === key);
  if (!arg || arg.value.includes('(unreadable)')) return null;
  return arg.value;
}
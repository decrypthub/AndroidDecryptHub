import test from 'node:test';
import assert from 'node:assert/strict';
import { argPlan, decodeArgs, decodeOpenFlags, hexValue, pathOf, summarizeArgs } from '../src/syscall_args.ts';

// sockaddr_in: family=AF_INET, port=443 (BE), 1.2.3.4
const sockaddrInet = () => {
  const b = Buffer.alloc(16);
  b.writeUInt16LE(2, 0);
  b.writeUInt16BE(443, 2);
  b[4] = 1; b[5] = 2; b[6] = 3; b[7] = 4;
  return b;
};
const utsname = () => {
  const b = Buffer.alloc(6 * 65);
  const put = (i, text) => Buffer.from(text, 'utf8').copy(b, i * 65);
  put(0, 'Linux'); put(1, 'localhost'); put(2, '5.10.198-android13');
  put(3, '#1 SMP PREEMPT'); put(4, 'aarch64');
  return b;
};
const cstr = (text) => Buffer.from(`${text}\0`, 'utf8');

test('argPlan asks only for the pointers a syscall actually has', () => {
  const openat = argPlan(56, [0n, 0x1000n, 0n, 0n]);
  assert.equal(openat.reads.length, 1);
  assert.equal(openat.reads[0].reg, 1);
  assert.equal(openat.reads[0].addr, 0x1000n);
  const uname = argPlan(160, [0x2000n]);
  assert.equal(uname.reads[0].reg, 0);
  assert.equal(uname.reads[0].len, 390);
  assert.deepEqual(argPlan(9999, [1n, 2n]).reads, []);
});

test('AT_FDCWD is recognised in the unsigned encoding the register actually carries', () => {
  // The event holds x0 as hex: -100 arrives as 0xffffffffffffff9c (or 0xffffff9c from a 32-bit write).
  const a = decodeArgs(56, [0xffffffffffffff9cn, 0x1000n, 0n, 0n], { 1: cstr('/proc/self/maps') });
  assert.equal(a.find((x) => x.name === 'dirfd')?.value, 'AT_FDCWD');
  const b = decodeArgs(56, [0xffffff9cn, 0x1000n, 0n, 0n], { 1: cstr('/proc/self/maps') });
  assert.equal(b.find((x) => x.name === 'dirfd')?.value, 'AT_FDCWD');
  const c = decodeArgs(56, [5n, 0x1000n, 0n, 0n], { 1: cstr('/tmp/x') });
  assert.equal(c.find((x) => x.name === 'dirfd')?.value, '5');
});

test('open flags use the arm64 asm-generic values (O_PATH is not O_SYNC)', () => {
  const path = decodeOpenFlags(0x200000n | 0x80000n);      // O_PATH | O_CLOEXEC: the "look but do not open" probe
  assert.match(path, /O_PATH/);
  assert.match(path, /O_CLOEXEC/);
  assert.ok(!/O_SYNC/.test(path), `O_PATH must not be reported as O_SYNC (got ${path})`);
  const sync = decodeOpenFlags(0x101000n);                 // O_SYNC = __O_SYNC | O_DSYNC
  assert.match(sync, /O_SYNC/);
  const dir = decodeOpenFlags(0x20000n);                   // O_DIRECTORY
  assert.match(dir, /O_DIRECTORY/);
});

test('a short read without a NUL terminator is NOT turned into a path', () => {
  // /sys/devices/system/cpu/cpu7/c   <- the read stopped here; there is no terminator in the buffer
  const partial = Buffer.from('/sys/devices/system/cpu/cpu7/c', 'utf8');
  const args = decodeArgs(56, [0n, 0x1000n, 0n, 0n], { 1: partial });
  assert.match(String(args.find((a) => a.name === 'path')?.value), /unreadable/);
  assert.equal(pathOf(56, args), null);
});

test('uname decodes all six utsname fields including domainname', () => {
  const buf = utsname();
  Buffer.from('(none)', 'utf8').copy(buf, 5 * 65);
  const args = decodeArgs(160, [0x3000n], { 0: buf });
  assert.equal(args.find((a) => a.name === 'domainname')?.value, '(none)');
  assert.equal(args.length, 6);
});

test('negative register values keep their sign in the report', () => {
  assert.equal(hexValue(-1n), '-0x1');
  assert.equal(hexValue(0x20n), '0x20');
});

test('connect reads what addrlen claims, not a blanket 28 bytes', () => {
  const plan = argPlan(203, [0n, 0x4000n, 16n]);
  assert.equal(plan.reads[0].len, 16);
  const plan6 = argPlan(203, [0n, 0x4000n, 28n]);
  assert.equal(plan6.reads[0].len, 28);
});


test('openat decodes the path, the fd and the flag bits', () => {
  const args = decodeArgs(56, [-100n, 0x1000n, 0x80000n, 0n], { 1: cstr('/proc/cpuinfo') });
  const path = args.find((a) => a.name === 'path');
  assert.equal(path?.value, '/proc/cpuinfo');
  assert.equal(args.find((a) => a.name === 'dirfd')?.value, 'AT_FDCWD');
  assert.match(String(args.find((a) => a.name === 'flags')?.value), /O_RDONLY/);
  assert.match(String(args.find((a) => a.name === 'flags')?.value), /O_CLOEXEC/);
  assert.equal(pathOf(56, args), '/proc/cpuinfo');
  assert.match(summarizeArgs(args), /path=\/proc\/cpuinfo/);
});

test('uname decodes the utsname fields', () => {
  const args = decodeArgs(160, [0x3000n], { 0: utsname() });
  assert.equal(args.find((a) => a.name === 'sysname')?.value, 'Linux');
  assert.equal(args.find((a) => a.name === 'release')?.value, '5.10.198-android13');
  assert.equal(args.find((a) => a.name === 'machine')?.value, 'aarch64');
  assert.equal(pathOf(160, args), null);
});

test('connect decodes IPv4 and IPv6 sockaddrs', () => {
  const v4 = decodeArgs(203, [7n, 0x4000n, 16n], { 1: sockaddrInet() });
  assert.equal(v4.find((a) => a.name === 'family')?.value, 'AF_INET');
  assert.equal(v4.find((a) => a.name === 'addr')?.value, '1.2.3.4:443');

  const v6 = Buffer.alloc(28);
  v6.writeUInt16LE(10, 0);
  v6.writeUInt16BE(53, 2);
  for (let i = 0; i < 16; i++) v6[8 + i] = i === 15 ? 1 : 0;
  const decoded6 = decodeArgs(203, [7n, 0x5000n, 28n], { 1: v6 });
  assert.equal(decoded6.find((a) => a.name === 'family')?.value, 'AF_INET6');
  assert.match(String(decoded6.find((a) => a.name === 'addr')?.value), /:53$/);
});

test('ioctl keeps the request as hex - it is a command word, not a string', () => {
  const args = decodeArgs(29, [3n, 0x5401n, 0x6000n], {});
  assert.equal(args.find((a) => a.name === 'fd')?.value, '3');
  assert.equal(args.find((a) => a.name === 'request')?.value, '0x5401');
  assert.equal(args.find((a) => a.name === 'arg')?.value, '0x6000');
});

test('an unreadable pointer is reported as unreadable, not as an empty path', () => {
  const args = decodeArgs(56, [0n, 0xdeadbeefn, 0n, 0n], { 1: null });
  assert.match(String(args.find((a) => a.name === 'path')?.value), /unreadable/);
  assert.equal(pathOf(56, args), null);
});

test('a pointer to binary garbage does not become a path', () => {
  const garbage = Buffer.from([0x01, 0x02, 0x03, 0x00, 0xff, 0xfe]);
  const args = decodeArgs(56, [0n, 0x1000n, 0n, 0n], { 1: garbage });
  assert.equal(pathOf(56, args), null);
});

test('unknown syscalls fall back to the raw register snapshot', () => {
  const args = decodeArgs(9999, [1n, 2n, 3n, 4n], {});
  assert.deepEqual(args.map((a) => a.name), ['x0', 'x1', 'x2']);
  assert.equal(args[0].value, '0x1');
});

test('memfd_create uses the name argument as its path-like value', () => {
  const args = decodeArgs(279, [0x7000n, 1n], { 0: cstr('jit-cache') });
  assert.equal(pathOf(279, args), 'jit-cache');
});
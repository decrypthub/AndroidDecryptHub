// The app sandbox lives on the phone at /data/data/<package> (often a symlink to
// /data/user/0/<package>). Reading it does not need the app process: the host
// daemon lists and reads it through adb + su. The web file panel uses this.
// The in-process agent path (fs_browse.ts) stays for MCP and the device checks,
// which also want /proc/self.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

export const SANDBOX_LIST_CAP = 2000;
export const SANDBOX_READ_CAP = 1024 * 1024;

const PKG_RE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;

export interface SandboxEntry {
  name: string;
  type: 'd' | 'f' | 'l' | 'o';
  size: number;
  mode: number;
  mtime: number;
}

export interface SandboxListing {
  ok: true;
  path: string;
  count: number;
  truncated: boolean;
  entries: SandboxEntry[];
}

export interface SandboxRead {
  ok: true;
  path: string;
  /** Bytes actually returned (capped). */
  size: number;
  /** Full size on the device. */
  fsize: number;
  truncated: boolean;
  b64: string;
}

export interface SandboxDeps {
  shell(command: string): Promise<string>;
  execOut(command: string): Promise<Buffer>;
}

export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function assertPackage(pkg: string): string {
  const p = String(pkg ?? '').trim();
  if (!PKG_RE.test(p)) throw new Error('包名不正确');
  return p;
}

/** Absolute path with `.` and empty segments removed. `..` is refused, not resolved. */
export function normalizeAbs(raw: string): string {
  const path = String(raw ?? '').replace(/\\/g, '/').trim();
  if (!path.startsWith('/') || path.includes('\0') || /[\r\n]/.test(path)) throw new Error('这个路径不在该应用的沙盒里');
  const parts: string[] = [];
  for (const seg of path.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') throw new Error('这个路径不在该应用的沙盒里');
    parts.push(seg);
  }
  return '/' + parts.join('/');
}

export function pathInSandbox(pkg: string, abs: string): boolean {
  const roots = [
    `/data/data/${pkg}`,
    `/storage/emulated/0/Android/data/${pkg}`,
    `/storage/emulated/0/Android/obb/${pkg}`,
    `/sdcard/Android/data/${pkg}`,
    `/sdcard/Android/obb/${pkg}`,
  ];
  if (roots.some((r) => abs === r || abs.startsWith(r + '/'))) return true;
  const user = abs.match(/^\/data\/user(?:_de)?\/\d+\/([^/]+)(?:\/|$)/);
  return user?.[1] === pkg;
}

/** Package-private dirs plus the installed APK tree under /data/app/…/<pkg>-…/ */
export function pathOwnedByPackage(pkg: string, abs: string): boolean {
  if (pathInSandbox(pkg, abs)) return true;
  const esc = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^/data/app/(?:~~[^/]+/)?${esc}(?:-[^/]+)?(?:/|$)`).test(abs);
}

export function confineSandboxPath(pkg: string, raw: string): string {
  const p = assertPackage(pkg);
  const abs = normalizeAbs(raw);
  if (!pathInSandbox(p, abs)) throw new Error('这个路径不在该应用的沙盒里');
  return abs;
}

export function confinePackagePath(pkg: string, raw: string): string {
  const p = assertPackage(pkg);
  const abs = normalizeAbs(raw);
  if (!pathOwnedByPackage(p, abs)) throw new Error('这个路径不属于该应用');
  return abs;
}

/** Cap for pulling APK-shipped .so files (sandbox text reads stay at SANDBOX_READ_CAP). */
export const PACKAGE_FILE_READ_CAP = 64 * 1024 * 1024;

function su(script: string): string {
  return `su -c ${shQuote(script)}`;
}

/** One-line remote script. Names are base64 so spaces and quotes stay data. */
export function sandboxListCommand(abs: string): string {
  const q = shQuote(abs);
  const script = [
    `p=${q}`,
    `if [ ! -d "$p" ]; then if [ -e "$p" ] || [ -L "$p" ]; then echo NOTDIR; else echo MISSING; fi; exit 0; fi`,
    `real=$(readlink -f "$p" 2>/dev/null || true)`,
    `if [ -z "$real" ]; then echo NORESOLVE; exit 0; fi`,
    `echo "REAL $real"`,
    `if ! ls -1A "$p" >/dev/null 2>&1; then echo DENIED; exit 0; fi`,
    `echo OK`,
    `n=0`,
    `ls -1A "$p" | while IFS= read -r name; do [ -n "$name" ] || continue; n=$((n+1)); if [ "$n" -gt ${SANDBOX_LIST_CAP} ]; then echo TRUNC; break; fi; f="$p/$name"; if [ -d "$f" ]; then k=d; elif [ -L "$f" ]; then k=l; elif [ -f "$f" ]; then k=f; else k=o; fi; set -- $(stat -c '%s %Y %a' "$f" 2>/dev/null); printf 'E %s %s %s %s %s\\n' "$k" "\${1:-0}" "\${2:-0}" "\${3:-0}" "$(printf '%s' "$name" | base64 | tr -d '\\n')"; done`,
  ].join('; ');
  return su(script);
}

export function sandboxStatCommand(abs: string): string {
  const q = shQuote(abs);
  const script = [
    `p=${q}`,
    `if [ ! -e "$p" ] && [ ! -L "$p" ]; then echo MISSING; exit 0; fi`,
    `if [ -L "$p" ]; then real=$(readlink -f "$p" 2>/dev/null || true); else real=$p; fi`,
    `if [ -z "$real" ]; then echo NORESOLVE; exit 0; fi`,
    `if [ -d "$real" ]; then echo NOTFILE; exit 0; fi`,
    `echo "REAL $real"`,
    `sz=$(stat -c %s "$real" 2>/dev/null || echo 0)`,
    `echo "SIZE $sz"`,
  ].join('; ');
  return su(script);
}

export function sandboxReadCommand(real: string): string {
  return su(`head -c ${SANDBOX_READ_CAP} ${shQuote(real)}`);
}

export interface ParsedSandbox {
  real: string;
  size: number | null;
  code: string | null;
  truncated: boolean;
  entries: SandboxEntry[];
}

export function parseSandboxOutput(text: string): ParsedSandbox {
  let real = '';
  let size: number | null = null;
  let code: string | null = null;
  let truncated = false;
  const entries: SandboxEntry[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r/g, '').trim();
    if (!line || line === 'OK') continue;
    if (line === 'TRUNC') { truncated = true; continue; }
    if (line.startsWith('REAL ')) { real = line.slice(5).trim(); continue; }
    if (line.startsWith('SIZE ')) { size = Number(line.slice(5).trim()); continue; }
    if (/^(MISSING|NOTDIR|DENIED|NORESOLVE|NOTFILE)$/.test(line)) { code = line; continue; }
    if (!line.startsWith('E ')) continue;
    const parts = line.slice(2).split(' ');
    if (parts.length !== 5) continue;
    const [k, sizeS, mtimeS, modeS, b64] = parts;
    const name = Buffer.from(b64, 'base64').toString('utf8');
    if (!name || name === '.' || name === '..' || /[/\0\r\n]/.test(name)) continue;
    const type = k === 'd' || k === 'f' || k === 'l' ? k : 'o';
    entries.push({
      name,
      type,
      size: Number(sizeS) || 0,
      mtime: Number(mtimeS) || 0,
      mode: Number.parseInt(modeS, 8) || 0,
    });
  }
  if (entries.length > SANDBOX_LIST_CAP) {
    truncated = true;
    entries.length = SANDBOX_LIST_CAP;
  }
  return { real, size: Number.isFinite(size) ? size : null, code, truncated, entries };
}

function failCode(code: string, abs: string, pkg: string, kind: 'dir' | 'file'): Error {
  if (code === 'MISSING') {
    if (kind === 'dir' && abs === `/data/data/${pkg}`) return new Error('这个应用的沙盒目录不存在');
    return new Error(kind === 'dir' ? '目录不存在' : '文件不存在');
  }
  if (code === 'NOTDIR') return new Error('这不是目录');
  if (code === 'NOTFILE') return new Error('这不是文件');
  if (code === 'DENIED') return new Error('没有权限读取这个目录');
  if (code === 'NORESOLVE') return new Error('解析不了这个路径');
  return new Error('读沙盒失败');
}

function explainAdb(e: unknown): Error {
  const msg = e instanceof Error ? e.message : String(e);
  const line = msg.split('\n')[0].replace(/\s+/g, ' ').trim().slice(0, 200);
  if (/no devices|device offline|device not found/i.test(line)) return new Error('手机没有连上，读不了沙盒');
  if (/\bsu:|inaccessible or not found|Permission denied/i.test(line)) return new Error(`读沙盒需要手机上的 root（su）。${line}`);
  return new Error(line ? `读沙盒失败：${line}` : '读沙盒失败');
}

function adbBase(): string[] {
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return serial ? ['-s', serial] : [];
}

async function adbShell(command: string): Promise<string> {
  const { stdout } = await execFileP('adb', [...adbBase(), 'shell', command], {
    timeout: 20000, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  });
  return String(stdout ?? '');
}

async function adbOut(command: string, maxBuffer = 2 * 1024 * 1024): Promise<Buffer> {
  const { stdout } = await execFileP('adb', [...adbBase(), 'exec-out', command], {
    timeout: 120_000, windowsHide: true, maxBuffer, encoding: 'buffer',
  });
  return stdout as Buffer;
}

/** Default deps: small reads for sandbox text; SO pulls bump the buffer in pullPackageFile. */
const defaultDeps: SandboxDeps = {
  shell: adbShell,
  execOut: (c) => adbOut(c, /head -c \d{7,}/.test(c) ? PACKAGE_FILE_READ_CAP + 1024 * 1024 : 2 * 1024 * 1024),
};

export function packageFileReadCommand(real: string, cap = PACKAGE_FILE_READ_CAP): string {
  return su(`head -c ${cap} ${shQuote(real)}`);
}

/**
 * Pull a file the package owns (sandbox or /data/app/…/<pkg>-…/). Larger than the text
 * sandbox reader — used for APK-shipped .so download from the Dump page.
 */
export async function pullPackageFile(
  pkg: string, raw: string, deps: SandboxDeps = defaultDeps,
): Promise<SandboxRead> {
  const p = assertPackage(pkg);
  const abs = confinePackagePath(p, raw);
  let text: string;
  try { text = await deps.shell(sandboxStatCommand(abs)); }
  catch (e) { throw explainAdb(e); }
  const parsed = parseSandboxOutput(text);
  if (parsed.code) throw failCode(parsed.code, abs, p, 'file');
  if (!parsed.real) {
    const hint = text.replace(/\r/g, '').trim().split('\n')[0]?.trim().slice(0, 180) ?? '';
    throw new Error(hint ? `读文件失败：${hint}` : '读文件失败');
  }
  const real = confinePackagePath(p, parsed.real);
  const fsize = parsed.size ?? 0;
  if (fsize < 0) throw new Error('读文件失败：没有文件大小');
  if (fsize > PACKAGE_FILE_READ_CAP) {
    return {
      ok: true, path: abs, size: 0, fsize, truncated: true, b64: '',
    };
  }
  let buf = Buffer.alloc(0);
  if (fsize > 0) {
    try {
      buf = await deps.execOut(packageFileReadCommand(real, PACKAGE_FILE_READ_CAP));
    } catch (e) { throw explainAdb(e); }
    if (buf.length === 0) throw new Error('文件没有读出来');
  }
  return {
    ok: true,
    path: abs,
    size: buf.length,
    fsize,
    truncated: fsize > buf.length,
    b64: buf.toString('base64'),
  };
}

function requireReal(pkg: string, parsed: ParsedSandbox, rawText: string): string {
  if (!parsed.real) {
    const hint = rawText.replace(/\r/g, '').trim().split('\n')[0]?.trim().slice(0, 180) ?? '';
    throw new Error(hint ? `读沙盒失败：${hint}` : '读沙盒失败');
  }
  return confineSandboxPath(pkg, parsed.real);
}

export async function listSandboxDir(pkg: string, raw: string, deps: SandboxDeps = defaultDeps): Promise<SandboxListing> {
  const p = assertPackage(pkg);
  const abs = confineSandboxPath(p, raw);
  let text: string;
  try { text = await deps.shell(sandboxListCommand(abs)); }
  catch (e) { throw explainAdb(e); }
  const parsed = parseSandboxOutput(text);
  if (parsed.code) throw failCode(parsed.code, abs, p, 'dir');
  requireReal(p, parsed, text);
  return { ok: true, path: abs, count: parsed.entries.length, truncated: parsed.truncated, entries: parsed.entries };
}

export async function readSandboxFile(pkg: string, raw: string, deps: SandboxDeps = defaultDeps): Promise<SandboxRead> {
  const p = assertPackage(pkg);
  const abs = confineSandboxPath(p, raw);
  let text: string;
  try { text = await deps.shell(sandboxStatCommand(abs)); }
  catch (e) { throw explainAdb(e); }
  const parsed = parseSandboxOutput(text);
  if (parsed.code) throw failCode(parsed.code, abs, p, 'file');
  const real = requireReal(p, parsed, text);
  const fsize = parsed.size ?? 0;
  if (fsize < 0) throw new Error('读沙盒失败：没有文件大小');
  let buf = Buffer.alloc(0);
  if (fsize > 0) {
    try { buf = await deps.execOut(sandboxReadCommand(real)); }
    catch (e) { throw explainAdb(e); }
    if (buf.length === 0) throw new Error('文件没有读出来');
  }
  return {
    ok: true,
    path: abs,
    size: buf.length,
    fsize,
    truncated: fsize > buf.length,
    b64: buf.toString('base64'),
  };
}

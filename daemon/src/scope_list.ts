// The web switcher lists the packages checked in the phone's injection scope
// (/data/adb/adh/scope.json). That file is root-only; adb is how the host reads it.
// Display names come from each base APK's manifest (aapt), cached per package.
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { crc32 } from 'node:zlib';

const execFileP = promisify(execFile);
const SCOPE_PATH = '/data/adb/adh/scope.json';
const MANAGER_PKG = 'com.adh.manager';
const CACHE_MS = 3000;

export interface ScopedApp { package: string; label: string }

export function parseScopePackages(raw: string): string[] {
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  const text = (start >= 0 && end > start ? raw.slice(start, end + 1) : raw).trim();
  if (!text) return [];
  const obj = JSON.parse(text) as { packages?: unknown };
  if (!Array.isArray(obj.packages)) throw new Error('scope JSON has no packages array');
  const out: string[] = [];
  for (const item of obj.packages) {
    const pkg = String(item ?? '').trim();
    if (!pkg || pkg === MANAGER_PKG || out.includes(pkg)) continue;
    out.push(pkg);
  }
  return out;
}

/** aapt `dump badging` → the launcher name. Prefer a zh label when one is present. */
export function applicationLabel(badging: string): string {
  const lines = badging.split(/\r?\n/);
  const pick = (prefix: string) => {
    const line = lines.find(l => l.startsWith(prefix));
    const matched = line?.match(/:'(.*)'\s*$/);
    return matched ? matched[1].replace(/\\'/g, "'") : '';
  };
  return pick('application-label-zh') || pick('application-label:') || '';
}

let cache: { at: number; packages: string[]; error: string | null } | null = null;
const labelJobs = new Map<string, Promise<string>>();

function adbBase(): string[] {
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return serial ? ['-s', serial] : [];
}

async function adbShell(command: string): Promise<string> {
  const { stdout } = await execFileP('adb', [...adbBase(), 'shell', command], {
    timeout: 15000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
  });
  return String(stdout ?? '');
}

async function adbOut(command: string): Promise<Buffer> {
  const { stdout } = await execFileP('adb', [...adbBase(), 'exec-out', command], {
    timeout: 30000, windowsHide: true, maxBuffer: 80 * 1024 * 1024, encoding: 'buffer',
  });
  return stdout as Buffer;
}

function findAapt(): string | null {
  const root = process.env.ANDROID_SDK_ROOT || process.env.ANDROID_HOME
    || join(homedir(), 'AppData', 'Local', 'Android', 'Sdk');
  const tools = join(root, 'build-tools');
  if (!existsSync(tools)) return null;
  const versions = readdirSync(tools).sort().reverse();
  for (const version of versions) {
    const exe = join(tools, version, process.platform === 'win32' ? 'aapt.exe' : 'aapt');
    if (existsSync(exe)) return exe;
  }
  return null;
}

function storedZip(files: { name: string; data: Buffer }[]): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name);
    const crc = crc32(file.data) >>> 0;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(file.data.length, 18);
    local.writeUInt32LE(file.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(file.data.length, 20);
    cen.writeUInt32LE(file.data.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(offset, 42);
    locals.push(local, name, file.data);
    central.push(cen, name);
    offset += local.length + name.length + file.data.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

async function resolveLabel(pkg: string): Promise<string> {
  const aapt = findAapt();
  if (!aapt) return pkg;
  const listed = await adbShell(`pm path ${pkg}`);
  const lines = listed.split(/\r?\n/).map(s => s.trim()).filter(s => s.startsWith('package:'));
  const apk = lines.find(s => s.endsWith('/base.apk')) ?? lines[0];
  if (!apk) return pkg;
  const path = apk.slice('package:'.length).replace(/'/g, '');
  const quoted = `'${path}'`;
  const manifest = await adbOut(`su -c "unzip -p ${quoted} AndroidManifest.xml"`);
  const arsc = await adbOut(`su -c "unzip -p ${quoted} resources.arsc"`);
  if (manifest.length < 8 || arsc.length < 8) return pkg;
  const dir = mkdtempSync(join(tmpdir(), 'adh-label-'));
  try {
    const zipPath = join(dir, 'base.apk');
    writeFileSync(zipPath, storedZip([
      { name: 'AndroidManifest.xml', data: manifest },
      { name: 'resources.arsc', data: arsc },
    ]));
    const { stdout } = await execFileP(aapt, ['dump', 'badging', zipPath], {
      timeout: 20000, windowsHide: true, maxBuffer: 4 * 1024 * 1024,
    });
    return applicationLabel(String(stdout ?? '')) || pkg;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function labelFor(pkg: string): Promise<string> {
  const existing = labelJobs.get(pkg);
  if (existing) return existing;
  const job = resolveLabel(pkg).catch(() => pkg);
  labelJobs.set(pkg, job);
  return job;
}

// The agent dials 127.0.0.1 on the phone. That only reaches this daemon while
// `adb reverse` is in place, and the tunnel disappears on USB reconnect.
let reverseBusy = false;
let reverseState = '';
export function ensureAdbReverse(ports: number[], log: (line: string) => void): void {
  if (reverseBusy || !ports.length) return;
  reverseBusy = true;
  const args = adbBase();
  const finish = (state: string, line: string) => {
    if (state !== reverseState) {
      reverseState = state;
      log(line);
    }
    reverseBusy = false;
  };
  execFile('adb', [...args, 'get-state'], { timeout: 4000, windowsHide: true }, (err, stdout) => {
    if (err || String(stdout ?? '').trim() !== 'device') {
      finish('no-device', 'adb reverse: 没有在线设备，目标进程连不上本机');
      return;
    }
    let left = ports.length;
    let failed = '';
    for (const port of ports) {
      execFile('adb', [...args, 'reverse', `tcp:${port}`, `tcp:${port}`], { timeout: 8000, windowsHide: true }, (e) => {
        if (e && !failed) failed = e instanceof Error ? e.message.split('\n')[0] : String(e);
        if (--left > 0) return;
        if (failed) finish('fail', `adb reverse 失败: ${failed.slice(0, 180)}`);
        else finish('ok', `adb reverse: ${ports.map(p => 'tcp:' + p).join(' ')} → 本机`);
      });
    }
  });
}

/** Packages currently checked on the attached phone, with launcher names. */
export async function scopedApps(now = Date.now()): Promise<{ apps: ScopedApp[]; error: string | null }> {
  if (!cache || now - cache.at >= CACHE_MS) {
    try {
      const stdout = await adbShell(`su -c 'cat ${SCOPE_PATH}'`);
      cache = { at: now, packages: parseScopePackages(stdout), error: null };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      cache = { at: now, packages: [], error: message.split('\n')[0].slice(0, 240) };
    }
  }
  const apps: ScopedApp[] = [];
  for (const pkg of cache.packages) apps.push({ package: pkg, label: await labelFor(pkg) });
  return { apps, error: cache.error };
}

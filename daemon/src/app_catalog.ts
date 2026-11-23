import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { apkBadging, applicationLabel, pickBadgingIcon } from './scope_list.ts';

const execFileP = promisify(execFile);
const PKG_RE = /^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*$/;

export interface CatalogApp {
  package: string;
  apk: string;
  label: string;
  system: boolean;
  running: '' | 'background' | 'foreground';
}

interface Listed extends CatalogApp { icon: string }

let listed: Listed[] = [];
let listedAt = 0;
const labels = new Map<string, string>();
const icons = new Map<string, string>();
let pumping = false;

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

async function managerCatalog(): Promise<Map<string, { label: string; system: boolean }> | null> {
  const out = await adbShell(`content call --uri 'content://com.adh.manager.daemon-bridge' --method appCatalog`);
  const b64 = /base64=([A-Za-z0-9+/=]+)\}/.exec(out)?.[1] || '';
  if (!b64) return null;
  try {
    const arr = JSON.parse(Buffer.from(b64, 'base64').toString()) as { p: string; l: string; s: boolean }[];
    const map = new Map<string, { label: string; system: boolean }>();
    for (const row of arr) {
      if (row.p && PKG_RE.test(row.p)) map.set(row.p, { label: row.l || row.p, system: row.s });
    }
    return map;
  } catch {
    return null;
  }
}

export function parsePackageLines(text: string, system: boolean): Listed[] {
  const rows: Listed[] = [];
  for (const line of text.split(/\r?\n/)) {
    const matched = /^package:(.+)=([A-Za-z0-9_.]+)$/.exec(line.trim());
    if (!matched || !PKG_RE.test(matched[2]) || !matched[1].startsWith('/')) continue;
    rows.push({ package: matched[2], apk: matched[1], label: '', system, running: '', icon: '' });
  }
  return rows;
}

function runningPackages(ps: string, focus: string): Map<string, '' | 'background' | 'foreground'> {
  const out = new Map<string, '' | 'background' | 'foreground'>();
  for (const line of ps.split(/\n/)) {
    const name = line.trim().split(/\s+/).pop() || '';
    const pkg = name.split(':')[0];
    if (PKG_RE.test(pkg)) out.set(pkg, pkg === focus ? 'foreground' : 'background');
  }
  if (focus && PKG_RE.test(focus)) out.set(focus, 'foreground');
  return out;
}

async function refreshList(): Promise<void> {
  const [user, system, processes, activity, manager] = await Promise.all([
    adbShell('pm list packages -f -3'),
    adbShell('pm list packages -f -s'),
    adbShell('ps -A'),
    adbShell('dumpsys activity activities'),
    managerCatalog().catch(() => null),
  ]);
  if (manager) {
    for (const [pkg, info] of manager) labels.set(pkg, info.label);
  }
  const focus = /topResumedActivity=ActivityRecord\{[^\n]*\su\d+\s+([A-Za-z0-9_.]+)\//.exec(activity)?.[1] || '';
  const running = runningPackages(processes, focus);
  const byPackage = new Map<string, Listed>();
  for (const row of parsePackageLines(system, true)) byPackage.set(row.package, row);
  for (const row of parsePackageLines(user, false)) byPackage.set(row.package, row);
  listed = [...byPackage.values()].map(row => ({
    ...row,
    label: labels.get(row.package) || '',
    icon: icons.get(row.package) || '',
    running: running.get(row.package) || '',
  }));
  listedAt = Date.now();
  void pumpIdentity();
}

async function resolveIdentity(row: Listed): Promise<void> {
  // The Manager already named this app; the icon resolves lazily from the APK on request.
  // Pulling every app's resources.arsc here just for a badging icon hint floods adb.
  if (labels.has(row.package)) {
    icons.set(row.package, '');
    return;
  }
  try {
    const text = await apkBadging(row.apk);
    if (!labels.has(row.package)) labels.set(row.package, applicationLabel(text) || row.package);
    icons.set(row.package, pickBadgingIcon(text));
  } catch {
    if (!labels.has(row.package)) labels.set(row.package, row.package);
    icons.set(row.package, '');
  }
}

async function pumpIdentity(): Promise<void> {
  if (pumping) return;
  pumping = true;
  try {
    const pending = listed.filter(row => !icons.has(row.package)).sort((a, b) => Number(a.system) - Number(b.system));
    let index = 0;
    const worker = async () => {
      while (index < pending.length) await resolveIdentity(pending[index++]);
    };
    await Promise.all([worker(), worker()]);
  } finally {
    pumping = false;
  }
}

export async function readAppCatalog(): Promise<CatalogApp[]> {
  if (!listedAt || Date.now() - listedAt > 8000) await refreshList();
  return listed.map(row => ({
    package: row.package,
    apk: row.apk,
    label: labels.get(row.package) || row.label,
    system: row.system,
    running: row.running,
  }));
}

const identityJobs = new Map<string, Promise<void>>();

/** Resolve this one package's label/icon now instead of waiting for the background queue. */
export async function ensureCatalogIdentity(pkg: string): Promise<void> {
  let row = listed.find(item => item.package === pkg);
  if (!row) {
    await refreshList().catch(() => {});
    row = listed.find(item => item.package === pkg);
  }
  if (!row || icons.has(pkg)) return;
  let job = identityJobs.get(pkg);
  if (!job) {
    job = resolveIdentity(row).finally(() => identityJobs.delete(pkg));
    identityJobs.set(pkg, job);
  }
  await job;
}

export function catalogIcon(pkg: string): { apk: string; path: string } | null {
  if (!icons.has(pkg)) return null;
  const row = listed.find(item => item.package === pkg);
  return row ? { apk: row.apk, path: icons.get(pkg) || '' } : { apk: '', path: '' };
}

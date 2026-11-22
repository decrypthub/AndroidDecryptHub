import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { AGENT_PORT, HTTP_PORT } from './config.ts';

/** Opt-in, bounded observation of a consenting app that loads its own reporter.
 * Leave the device's application scope and existing reverse routes alone.
 */
export interface LocalObserver {
  package: string;
  pid: number;
  model: string;
}

function readLocalObserver(): LocalObserver | null {
  const pkg = process.env.ADH_OBSERVE_APP;
  if (!pkg) return null;
  const serial = process.env.ANDROID_SERIAL ?? '';
  if (!/^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$/.test(pkg) ||
      !/^[A-Za-z0-9_-]+$/.test(serial) || !process.env.ADH_DATA_DIR) {
    throw Error('Local observation needs an exact USB serial, package and isolated ADH_DATA_DIR');
  }
  if (readdirSync(process.env.ADH_DATA_DIR).length || process.env.ADH_CAPTURES_DIR) {
    throw Error('Local observation needs a new empty data directory and no capture-directory override');
  }
  const adb = (args: string[]) => execFileSync('adb', args, {
    encoding: 'utf8', timeout: 5000, windowsHide: true,
  }).trim();
  const device = (...args: string[]) => adb(['-s', serial, ...args]);
  const usb = adb(['devices', '-l']).split(/\r?\n/).flatMap(line => {
    const m = /^(\S+)\s+device(?:\s|$)/.exec(line);
    return m ? [m[1]] : [];
  });
  if (usb.length !== 1 || usb[0] !== serial) throw Error('Expected only the selected USB device online');
  const model = device('shell', 'getprop', 'ro.product.model');
  const pidText = device('shell', 'pidof', pkg);
  if (!model || !/^[1-9]\d*$/.test(pidText)) throw Error('Expected one running process for the chosen app');
  const pid = Number(pidText);
  if (!Number.isSafeInteger(pid)) throw Error('Invalid process ID');
  const port = 'tcp:' + AGENT_PORT;
  const m = device('reverse', '--list').split(/\r?\n/)
    .some(line => line.trim().split(/\s+/).slice(-2).join(' ') === port + ' ' + port);
  if (!m) throw Error('Expected the existing matching USB reverse; no routes were changed');
  return { package: pkg, pid, model: model.slice(0, 64) };
}

export const localObserver = readLocalObserver();
export const localObserverHost = '127.0.0.1:' + HTTP_PORT;

export function acceptsLocalHello(observer: LocalObserver, message: {
  t?: string; package?: string; pid?: number; entry?: string;
}): boolean {
  return message.t === 'hello' && message.package === observer.package &&
    message.pid === observer.pid && message.entry === 'jni_onload';
}

const VIEW_ROUTES = new Set([
  '/', '/health', '/raven.svg', '/raven.png', '/favicon.ico', '/operation-client.js',
  '/algorithm-observations.js', '/operations.js', '/api/config', '/api/agents', '/api/apps',
]);
const APP_READ_ROUTES = new Set([
  '/api/captures', '/api/events', '/api/http/exchanges', '/api/detect/summary',
]);

/** No operator endpoints, file/memory reads, or mutation routes in local observation mode. */
export function localViewAllows(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (method !== 'GET') return false;
  const path = url.pathname;
  if (VIEW_ROUTES.has(path) || path === '/' + observer.package || /^\/api\/captures\/[1-9]\d*$/.test(path)) return true;
  if (path === '/api/devices') return url.searchParams.get('action') === 'list';
  return APP_READ_ROUTES.has(path) && url.searchParams.getAll('package').length === 1 &&
    url.searchParams.get('package') === observer.package;
}

import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { AGENT_PORT, HTTP_PORT } from './config.ts';
import { confineDevicePath } from './sandbox_fs.ts';

/** Opt-in, bounded observation of a consenting app that loads its own reporter.
 * Leave the device's application scope and existing reverse routes alone.
 */
export interface LocalObserver {
  package: string;
  pid: number;
  model: string;
  usbSerial?: string;
  ownFilesSerial?: string;
  fileBrowserOnly?: boolean;
  externalUser?: number;
  editableText?: string;
  demoExternal?: boolean;
  demoExternalEdit?: boolean;
  demoApiSerial?: string;
  /** USB inventory entry may call the fixed apiLab provider. It does not follow the selected package. */
  declaredApiSerial?: string;
}

export const OWN_API_DEMO_PACKAGE = 'com.adh.sandbox.apilab';
export const OWN_DEMO_API_ROUTE = '/api/observer/demo-api';
export const OWN_FILE_DEMO_PACKAGE = 'com.adh.sandbox.filelab';
export const OWN_FILE_DEMO_NOTE = 'adh-demo-external.txt';

function readLocalObserver(): LocalObserver | null {
  const pkg = process.env.ADH_OBSERVE_APP;
  const fileBrowserOnly = process.env.ADH_OWN_FILE_BROWSER === '1';
  const editableText = process.env.ADH_OWN_FILE_EDIT;
  const demoApi = process.env.ADH_OWN_API_DEMO === '1';
  if (demoApi && (fileBrowserOnly || pkg!==OWN_API_DEMO_PACKAGE)) {
    throw Error('API observation needs the isolated apiLab Demo');
  }
  const demoExternal = process.env.ADH_OWN_EXTERNAL_DEMO === '1';
  const demoExternalEdit = process.env.ADH_OWN_EXTERNAL_EDIT === '1';
  if ((demoExternal && (!fileBrowserOnly || pkg !== OWN_FILE_DEMO_PACKAGE)) || (demoExternalEdit && !demoExternal)) {
    throw Error('Demo external files need the isolated fileLab build and explicit files-only mode');
  }
  if (!fileBrowserOnly && editableText !== undefined) throw Error('File editing needs the explicit files-only mode');
  if (!pkg) {
    if (fileBrowserOnly) throw Error('Files-only mode needs an exact debuggable APP');
    return null;
  }
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
  if (fileBrowserOnly || demoApi) {
    if (!model || (fileBrowserOnly && process.env.ADH_OBSERVE_OWN_FILES !== '1')) throw Error('Expected the selected USB Demo and explicit local scope');
    if (editableText !== undefined && !isEditableName(editableText)) throw Error('Specify one ordinary .txt name under files only');
    const user = device('shell', 'am', 'get-current-user');
    const uid = device('shell', 'run-as', pkg, 'id', '-u');
    if (user !== '0' || !/^\d+$/.test(uid) || Number(uid) < 10000) {
      throw Error('Expected a debuggable APP using its own application UID on the primary Android profile');
    }
    if (demoApi) return { package:pkg, pid:0, model:model.slice(0,64), usbSerial:serial, demoApiSerial:serial };
    return { package:pkg, pid:0, model:model.slice(0,64), usbSerial:serial, ownFilesSerial:serial, fileBrowserOnly:true,
      externalUser:Number(user), editableText, demoExternal, demoExternalEdit };
  }
  const pidText = device('shell', 'pidof', pkg);
  if (!model || !/^[1-9]\d*$/.test(pidText)) throw Error('Expected one running process for the chosen app');
  const pid = Number(pidText);
  if (!Number.isSafeInteger(pid)) throw Error('Invalid process ID');
  const port = 'tcp:' + AGENT_PORT;
  const m = device('reverse', '--list').split(/\r?\n/)
    .some(line => line.trim().split(/\s+/).slice(-2).join(' ') === port + ' ' + port);
  if (!m) throw Error('Expected the existing matching USB reverse; no routes were changed');
  const ownFilesSerial = process.env.ADH_OBSERVE_OWN_FILES === '1' ? serial : undefined;
  const declaredApiSerial = process.env.ADH_USB_APP_INVENTORY === '1' ? serial : undefined;
  return { package: pkg, pid, model: model.slice(0, 64), usbSerial:serial, ownFilesSerial, declaredApiSerial };
}

function isEditableName(name:string):boolean {
  return /^[a-z0-9][a-z0-9._-]{0,79}\.txt$/i.test(name);
}

export function allowedOwnedRoot(observer:LocalObserver,root:string):boolean {
  if (!observer.ownFilesSerial) return false;
  return observer.fileBrowserOnly
    ? root==='app'||(root==='external'&&observer.externalUser===0)
    : root==='files';
}

export function usesDemoExternal(observer:LocalObserver,root:string):boolean {
  return root==='external'&&observer.demoExternal===true&&observer.fileBrowserOnly===true&&
    observer.package===OWN_FILE_DEMO_PACKAGE&&allowedOwnedRoot(observer,root);
}

export function allowedOwnedSave(observer:LocalObserver,root:string,path:string):boolean {
  if(usesDemoExternal(observer,root)) return observer.demoExternalEdit===true&&path===OWN_FILE_DEMO_NOTE;
  return !!observer.ownFilesSerial&&observer.fileBrowserOnly===true&&root==='app'&&
    typeof observer.editableText==='string'&&isEditableName(observer.editableText)&&path==='files/'+observer.editableText;
}

export const localObserver = readLocalObserver();

export function noteObservedPid(pkg: string, pid: number) {
  if (localObserver && localObserver.package === pkg && Number.isSafeInteger(pid) && pid >= 0) localObserver.pid = pid;
}
export const localObserverHost = '127.0.0.1:' + HTTP_PORT;
export const OWN_APP_FILES_ROUTE = '/api/observer/app-files';

export function acceptsLocalHello(observer: LocalObserver, message: {
  t?: string; package?: string; pid?: number; entry?: string;
}): boolean {
  return !observer.fileBrowserOnly && !observer.demoApiSerial && message.t === 'hello' && message.package === observer.package &&
    message.pid === observer.pid && (message.entry === 'jni_onload' || message.entry === 'start');
}

/** Root listing of one selected app's own sandbox. Paths outside that sandbox are refused. */
export function allowsSelectedAppFiles(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (observer.fileBrowserOnly || observer.demoApiSerial || !observer.usbSerial) return false;
  if (url.pathname === '/api/fs/list' && method === 'GET') {
    const packages = url.searchParams.getAll('package');
    const paths = url.searchParams.getAll('path');
    if (packages.length !== 1 || paths.length !== 1 || [...url.searchParams.keys()].some(key => key !== 'package' && key !== 'path')) return false;
    try { confineDevicePath(paths[0]); return /^[\w]+(?:\.[\w]+)*$/.test(packages[0]); } catch { return false; }
  }
  return url.pathname === '/api/fs/read' && method === 'POST' && url.search === '';
}

const DUMP_READ = new Set(['/api/unpack/history', '/api/unpack/inventory']);
const DUMP_WRITE = new Set([
  '/api/unpack/dump-one', '/api/unpack/dump-so-one', '/api/unpack/pull-so',
  '/api/unpack/dump-all', '/api/unpack/dump-so', '/api/unpack/run',
]);
/** Memory dump stays on the injected process. These routes do not widen file access. */
export function allowsInjectedDump(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (observer.fileBrowserOnly || observer.demoApiSerial || !observer.usbSerial) return false;
  if (method === 'GET' && DUMP_READ.has(url.pathname)) {
    return [...url.searchParams.keys()].every(key => key === 'package' || key === 'session');
  }
  return method === 'POST' && DUMP_WRITE.has(url.pathname) && url.search === '';
}

/** App icon is metadata. Open, stop and restart name one installed package in the body. */
export function allowsAppControl(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (observer.fileBrowserOnly || observer.demoApiSerial || !observer.usbSerial) return false;
  if (url.pathname === '/api/apps/icon' && method === 'GET') {
    const packages = url.searchParams.getAll('package');
    return packages.length === 1 && /^[\w]+(?:\.[\w]+)*$/.test(packages[0]) && [...url.searchParams.keys()].every(key => key === 'package' || key === 'v');
  }
  return url.pathname === '/api/apps/control' && method === 'POST' && url.search === '';
}

/** Hook presets for the selected app. One package on read; the write body is checked by the route. */
export function allowsCaptureFamilies(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (observer.fileBrowserOnly || observer.demoApiSerial || !observer.usbSerial) return false;
  if (url.pathname !== '/api/capture/families') return false;
  if (method === 'GET') {
    const packages = url.searchParams.getAll('package');
    return packages.length === 1 && /^[\w]+(?:\.[\w]+)*$/.test(packages[0]) && [...url.searchParams.keys()].every(key => key === 'package');
  }
  return method === 'POST' && url.search === '';
}

/** Injection scope for the USB panel: read the phone file, or add/remove exactly one installed package. */
export function allowsPanelScope(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  if (observer.fileBrowserOnly || observer.demoApiSerial || !observer.usbSerial) return false;
  return url.pathname === '/api/scope' && url.search === '' && (method === 'GET' || method === 'POST');
}

/** The only phone-confirmed capture settings this entry may touch. Other packages are refused. */
export function demoApiRequest(observer: LocalObserver, method: string | undefined, url: URL): { package: string } | null {
  if (url.pathname !== OWN_DEMO_API_ROUTE || (method !== 'GET' && method !== 'POST')) return null;
  const dedicated = observer.package === OWN_API_DEMO_PACKAGE && !!observer.demoApiSerial && !observer.declaredApiSerial;
  if (dedicated) return url.search === '' ? { package: OWN_API_DEMO_PACKAGE } : null;
  const listed = url.searchParams.getAll('package');
  if (!observer.declaredApiSerial || observer.fileBrowserOnly || observer.demoApiSerial) return null;
  if (listed.length !== 1 || listed[0] !== OWN_API_DEMO_PACKAGE || [...url.searchParams.keys()].some(key => key !== 'package')) return null;
  return { package: OWN_API_DEMO_PACKAGE };
}

const VIEW_ROUTES = new Set([
  '/', '/health', '/raven.svg', '/raven.png', '/favicon.ico', '/operation-client.js',
  '/algorithm-observations.js', '/operations.js', '/api/config', '/api/agents', '/api/apps',
]);
const APP_READ_ROUTES = new Set([
  '/api/captures', '/api/events', '/api/http/exchanges', '/api/detect/summary',
]);

/** File editing is absent by default; the separate file-only mode opts in one existing text path. */
export function localViewAllows(observer: LocalObserver, method: string | undefined, url: URL): boolean {
  const path = url.pathname;
  if (path === OWN_DEMO_API_ROUTE) return demoApiRequest(observer, method, url)!==null;
  if (allowsSelectedAppFiles(observer, method, url) || allowsInjectedDump(observer, method, url) || allowsPanelScope(observer, method, url) || allowsCaptureFamilies(observer, method, url) || allowsAppControl(observer, method, url)) return true;
  if (path === OWN_APP_FILES_ROUTE) {
    const query=url.searchParams;
    const keys=observer.fileBrowserOnly?['action','path','root']:['action','path'];
    if(query.getAll('action').length!==1 || query.getAll('path').length>1 ||
       query.getAll('root').length>1 || ![...query.keys()].every(k=>keys.includes(k))) return false;
    const root=query.get('root')??(observer.fileBrowserOnly?'app':'files');
    if(!allowedOwnedRoot(observer,root)) return false;
    const action=query.get('action');
    if(method==='GET') return action==='list'||action==='preview';
    return method==='POST'&&action==='save'&&allowedOwnedSave(observer,root,query.get('path')??'');
  }
  if (method !== 'GET') return false;
  if (VIEW_ROUTES.has(path) || path === '/' + observer.package) return true;
  if (path === '/api/devices') return url.searchParams.get('action') === 'list';
  if (observer.fileBrowserOnly || observer.demoApiSerial) return false;
  if (/^\/api\/captures\/[1-9]\d*$/.test(path)) return true;
  return APP_READ_ROUTES.has(path) && url.searchParams.getAll('package').length === 1 &&
    url.searchParams.get('package') === observer.package;
}

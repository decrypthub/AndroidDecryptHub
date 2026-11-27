import { spawn } from 'node:child_process';
import { readdirSync,readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { adbExec } from './adb_wire.ts';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AGENT_PORT, DEVICE_AGENT_PORT, HTTP_PORT } from './config.ts';
import {deviceRequestScope} from './agent_scope.ts';
import {usbAgentRoutes} from './usb_agent_routes.ts';
import { parseAdbDevices } from './transport/adb_device.ts';
import { log,sessions } from './state.ts';

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

export const OWN_DEMO_PACKAGE = 'com.adh.sandbox';
export const OWN_API_DEMO_PACKAGE = `${OWN_DEMO_PACKAGE}.apilab`;
export const OWN_DEMO_API_ROUTE = '/api/observer/demo-api';
export const OWN_FILE_DEMO_PACKAGE = `${OWN_DEMO_PACKAGE}.filelab`;
export const OWN_FILE_DEMO_NOTE = 'adh-demo-external.txt';

export function isOwnDemoPackage(pkg:string):boolean {
  return pkg===OWN_DEMO_PACKAGE||pkg.startsWith(`${OWN_DEMO_PACKAGE}.`);
}

/** Explicit restart of the same owned data root; never silently adopt another device/app. */
export function assertObserverDataDirectory(dataDir:string,serial:string,pkg:string,resume=false,captureOverride=false){
  if(captureOverride)throw Error('Local observation refuses a capture-directory override');
  if(!readdirSync(dataDir).length)return;
  let owner:any;try{if(resume)owner=JSON.parse(readFileSync(join(dataDir,'.adh-local-observer.json'),'utf8'));}catch{/* invalid ownership is rejected below */}
  if(!resume||owner?.version!==1||owner?.serial!==serial||owner?.package!==pkg)throw Error('Local observation needs an empty data directory, or explicit resume with matching device/app ownership');
}

async function readLocalObserver(): Promise<LocalObserver | null> {
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
  assertObserverDataDirectory(process.env.ADH_DATA_DIR,serial,pkg,process.env.ADH_RESUME_OBSERVER_DATA==='1',!!process.env.ADH_CAPTURES_DIR);
  // An explicitly owned resume restores the local archive even when ADB is unavailable.
  // Live routes and every device operation still require fresh USB/process proof later.
  if(process.env.ADH_RESUME_OBSERVER_DATA==='1'&&!fileBrowserOnly&&!demoApi){
    const owner=JSON.parse(readFileSync(join(process.env.ADH_DATA_DIR,'.adh-local-observer.json'),'utf8'));
    if(owner.version!==1||owner.serial!==serial||owner.package!==pkg)throw Error('Resume ownership mismatch');
    return {package:pkg,pid:0,model:'已记住的设备',usbSerial:serial,
      ownFilesSerial:process.env.ADH_OBSERVE_OWN_FILES==='1'?serial:undefined,
      declaredApiSerial:process.env.ADH_USB_APP_INVENTORY==='1'?serial:undefined};
  }

  const adb = async (args: string[]) => (await adbExec(args, { timeout: 5000 })).stdout.trim();
  const device = (...args: string[]) => adb(['-s', serial, ...args]);
  const usb = (await adb(['devices', '-l'])).split(/\r?\n/).flatMap(line => {
    const m = /^(\S+)\s+device(?:\s|$)/.exec(line);
    return m ? [m[1]] : [];
  });
  if (!usb.includes(serial)) throw Error('Expected the selected USB device online');
  const model = await device('shell', 'getprop', 'ro.product.model');
  if (fileBrowserOnly || demoApi) {
    if (!model || (fileBrowserOnly && process.env.ADH_OBSERVE_OWN_FILES !== '1')) throw Error('Expected the selected USB Demo and explicit local scope');
    if (editableText !== undefined && !isEditableName(editableText)) throw Error('Specify one ordinary .txt name under files only');
    const user = await device('shell', 'am', 'get-current-user');
    const uid = await device('shell', 'run-as', pkg, 'id', '-u');
    if (user !== '0' || !/^\d+$/.test(uid) || Number(uid) < 10000) {
      throw Error('Expected a debuggable APP using its own application UID on the primary Android profile');
    }
    if (demoApi) return { package:pkg, pid:0, model:model.slice(0,64), usbSerial:serial, demoApiSerial:serial };
    return { package:pkg, pid:0, model:model.slice(0,64), usbSerial:serial, ownFilesSerial:serial, fileBrowserOnly:true,
      externalUser:Number(user), editableText, demoExternal, demoExternalEdit };
  }
  const pidText = await device('shell', 'pidof', pkg);
  if (!model || !/^[1-9]\d*$/.test(pidText)) throw Error('Expected one running process for the chosen app');
  const pid = Number(pidText);
  if (!Number.isSafeInteger(pid)) throw Error('Invalid process ID');
  const port = 'tcp:' + DEVICE_AGENT_PORT;
  const m = (await device('reverse', '--list')).split(/\r?\n/)
    .some(line => line.trim().split(/\s+/).slice(-2).join(' ') === port + ' ' + port);
  if (!m&&process.env.ADH_LEGACY_AGENT_ONLY==='1') throw Error('Expected the existing matching USB reverse; no routes were changed');
  const ownFilesSerial = process.env.ADH_OBSERVE_OWN_FILES === '1' ? serial : undefined;
  const declaredApiSerial = process.env.ADH_USB_APP_INVENTORY === '1' ? serial : undefined;
  ensureSandboxNetFixture(serial, pkg);
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

const TLS_TEST_PORT = 8762;

let tlsChild: ReturnType<typeof spawn> | null = null;

function spawnTlsTestServer() {
  if (tlsChild && tlsChild.exitCode === null && !tlsChild.killed) return;
  const script = join(dirname(fileURLToPath(import.meta.url)), '..', 'tls_test_server.mjs');
  const child = spawn(process.execPath, [script], { stdio: 'ignore', windowsHide: true });
  tlsChild = child;
  child.once('exit', () => { if (tlsChild === child) tlsChild = null; });
  process.once('exit', () => { try { child.kill(); } catch { /* already gone */ } });
}

/**
 * The sandbox network probe dials device-side 127.0.0.1:8762, which must be reversed to
 * the host TLS test server. Add our route only when absent (never touch existing routes)
 * and start tls_test_server.mjs when nothing listens on the host port yet.
 */
export function ensureSandboxNetFixture(serial: string, pkg: string) {
  if (!isOwnDemoPackage(pkg)) return;
  void (async () => {
    try {
      const port = 'tcp:' + TLS_TEST_PORT;
      const { stdout: list } = await adbExec(['-s', serial, 'reverse', '--list'], { timeout: 5000 });
      const have = list.split(/\r?\n/).some(line => line.trim().split(/\s+/).slice(-2).join(' ') === port + ' ' + port);
      if (!have) await adbExec(['-s', serial, 'reverse', port, port], { timeout: 5000 });
    } catch (e) {
      log(`[sandbox-net] adb reverse tcp:${TLS_TEST_PORT} 未建立:`, (e as Error).message);
    }
  })();
  const probe = connect(TLS_TEST_PORT, '127.0.0.1');
  probe.once('connect', () => probe.destroy());
  probe.once('error', () => spawnTlsTestServer());
}

export let localObserver: LocalObserver | null = null;
/** index.ts 在 listen 前 await：USB 启动检查走 5037 协议，不起 adb 进程。 */
export async function initLocalObserver(): Promise<void> { localObserver = await readLocalObserver(); }

const OBSERVE_PKG_RE = /^[A-Za-z][\w]*(?:\.[A-Za-z][\w]*)+$/;
const OBSERVE_SERIAL_RE = /^[A-Za-z0-9_-]+$/;

/** Read the browser's immutable request target, never another tab's selection. */
export function currentLocalObserver():LocalObserver|null {
  const root=localObserver;if(!root)return null;const scope=deviceRequestScope();
  const serial=scope?.serial??root.usbSerial,pkg=scope?.package??root.package;
  if((root.fileBrowserOnly||root.demoApiSerial)&&(serial!==root.usbSerial||pkg!==root.package))
    throw Object.assign(new Error('此隔离入口的设备和应用是固定的'),{status:403,code:'OBSERVATION_SCOPE_FIXED'});
  if(serial===root.usbSerial&&pkg===root.package)return root;
  return observerForTarget(serial??'',pkg);
}
function observerForTarget(serial:string,pkg:string):LocalObserver {
  const root=localObserver!;
  const rows=[...sessions.values()].filter(s=>s.online&&s.package===pkg&&s.deviceBinding?.serial===serial&&s.process===pkg);
  return {package:pkg,pid:rows.length===1?rows[0].pid:0,model:serial===root.usbSerial?root.model:'已选设备',usbSerial:serial,
    ownFilesSerial:process.env.ADH_OBSERVE_OWN_FILES==='1'?serial:undefined,
    declaredApiSerial:process.env.ADH_USB_APP_INVENTORY==='1'?serial:undefined};
}
/** Selection authorizes/ensures this device route and returns metadata. It does not mutate
 * the boot target, redirect any other request, or destroy another device's sessions. */
export async function retargetObserver(serial:string,pkg:string):Promise<LocalObserver>{
  const current=localObserver;if(!current)throw Error('此入口不是本机观察模式');
  if(current.fileBrowserOnly||current.demoApiSerial)throw Error('此入口的观察目标是固定的');
  if(!OBSERVE_SERIAL_RE.test(serial)||!OBSERVE_PKG_RE.test(pkg))throw Error('需要有效的设备序列号和包名');
  const routes=usbAgentRoutes();if(!routes)throw Error('设备路由尚未就绪');await routes.ensure(serial);
  const next=observerForTarget(serial,pkg);ensureSandboxNetFixture(serial,pkg);return next;
}
export function noteObservedPid(pkg:string,pid:number,serial?:string){
  if(localObserver&&localObserver.package===pkg&&localObserver.usbSerial===serial&&Number.isSafeInteger(pid)&&pid>=0)localObserver.pid=pid;
}
export const localObserverHost = '127.0.0.1:' + HTTP_PORT;
/** 本机观察入口的合法 Host：127.0.0.1 与 localhost 都算本机，其余 Host 视为重绑定。 */
export const observerHost = (host: string | undefined) =>
  host === localObserverHost || host === 'localhost:' + HTTP_PORT;
export const OWN_APP_FILES_ROUTE = '/api/observer/app-files';

export function acceptsLocalHello(observer: LocalObserver, message: {
  t?: string; package?: string; pid?: number; entry?: string;
}): boolean {
  // Package + entry are the real boundary: other injected apps dial the same port and are kept
  // out by package. Matching observer.pid exactly used to deadlock the panel — an app killed by
  // the system or restarted outside the panel came back with a new pid and every hello was
  // dropped, so the viewer looked like its data had vanished. Any pid of the observed package
  // is the app itself, whatever generation.
  return !observer.fileBrowserOnly && !observer.demoApiSerial && message.t === 'hello' && message.package === observer.package &&
    (message.entry === 'jni_onload' || message.entry === 'start');
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


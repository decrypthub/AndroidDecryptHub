// Host-orchestrated direct-syscall watch. The agent stays execution-only: this module
// reconstructs one loaded ELF, finds `svc #0` sites with the existing static scanner,
// then asks the native-hook manager to inline-hook those exact addresses. NATIVE_HOOK
// events carry x0-x8; for a syscall site x8 is the syscall number.
import { svcScan } from './analysis.ts';
import { modulesFromMaps, reconstructSo, sendCmd } from './service.ts';

export interface SyscallWatchOptions {
  module: string;
  limit?: number;
}

function hexAddress(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function findModule(modules: any[], name: string): any {
  const exact = modules.find((m) => m.name === name || m.path === name);
  if (exact) return exact;
  return modules.find((m) => String(m.path ?? '').endsWith(`/${name}`)) ??
    modules.find((m) => String(m.path ?? '').includes(name));
}

export async function watchSyscalls(sid: string, opts: SyscallWatchOptions): Promise<any> {
  if (!opts.module) throw new Error('need module');
  const maps = await sendCmd(sid, 'maps');
  if (!maps.ok) throw new Error(maps.error ?? 'maps command failed');
  const mod = findModule(modulesFromMaps(maps.regions ?? []), opts.module);
  if (!mod) throw new Error(`module not found: ${opts.module}`);

  const buf = await reconstructSo(sid, String(mod.base));
  const scan = svcScan(buf);
  const limit = Math.max(1, Math.min(16, Math.trunc(Number(opts.limit ?? 8))));
  const selected = scan.hits.slice(0, limit);
  const base = BigInt(`0x${String(mod.base).replace(/^0x/i, '')}`);
  const installed: any[] = [];
  try {
    for (const hit of selected) {
      const addr = base + BigInt(String(hit.vaddr));
      const r = await sendCmd(sid, 'native_hook', {
        action: 'hook', mode: 'inline', module: '', symbol: '', addr: hexAddress(addr),
      }, 20_000);
      if (!r.ok) throw new Error(`svc hook failed at ${hexAddress(addr)}: ${r.error ?? 'unknown error'}`);
      installed.push({ hookId: Number(r.hookId), addr: hexAddress(addr), vaddr: String(hit.vaddr), fileOff: String(hit.fileOff) });
    }
  } catch (e) {
    for (const hook of installed) {
      await sendCmd(sid, 'native_hook', { action: 'unhook', hookId: hook.hookId }, 20_000).catch(() => null);
    }
    throw e;
  }

  return {
    module: mod.name,
    base: mod.base,
    execSegs: scan.execSegs,
    scannedBytes: scan.scanned,
    svcCount: scan.hits.length,
    limit,
    installedCount: installed.length,
    truncated: scan.hits.length > limit,
    hooks: installed,
    event: 'NATIVE_HOOK',
    syscallRegister: 'x8',
    note: 'Events from these hooks carry x8 as the syscall number. Unhook with native_hook/unhook per hookId.',
  };
}
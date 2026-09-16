// Injection-backend matrix (module W). Shared by the REST surface (GET /api/backends) and the MCP
// tool `backends`, so an AI client and the browser console see exactly the same truth.
//
// The Host ADH Daemon has no adb: for Frida Gadget it reports what is cached on this machine plus
// the loader command; the device-side backends (Zygisk scope, optional Xposed module) are driven
// through ADH Manager → Device Daemon and are reported here as pointers, not as actions.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { agentCmd, modulesFromMaps } from './service.ts';
import { sessions } from './state.ts';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

export interface GadgetCacheEntry { version: string; abi: string; bytes: number; path: string }

/** Pinned versions (manifest) + what is actually downloaded under agent/third_party/frida. */
export function gadgetCache(): { pinned: string[]; cached: GadgetCacheEntry[] } {
  const cacheRoot = join(repoRoot, 'agent', 'third_party', 'frida');
  const manifestFile = join(repoRoot, 'tools', 'frida_gadget_versions.json');
  let pinned: string[] = [];
  try {
    const parsed = JSON.parse(readFileSync(manifestFile, 'utf8'));
    pinned = Object.keys(parsed?.versions ?? {}).sort();
  } catch { pinned = []; }
  const cached: GadgetCacheEntry[] = [];
  if (existsSync(cacheRoot)) {
    for (const version of readdirSync(cacheRoot)) {
      const versionDir = join(cacheRoot, version);
      if (!statSync(versionDir).isDirectory()) continue;
      for (const abi of readdirSync(versionDir)) {
        const so = join(versionDir, abi, 'libfrida-gadget.so');
        if (!existsSync(so)) continue;
        cached.push({ version, abi, bytes: statSync(so).size, path: so });
      }
    }
  }
  return { pinned, cached };
}

export function backendMatrix() {
  const { pinned, cached } = gadgetCache();
  return {
    agents: [...sessions.values()].map((s) => ({
      session: s.sessionId,
      package: s.package,
      pid: s.pid,
      online: s.online,
      entry: s.entry,
      // Coarse host-side label; classifySession() below resolves one session precisely from the
      // agent's own module list (the agent .so path tells Zygisk / Xposed module / self-load apart).
      entryKind: s.entry === 'start' ? 'injected (adh_agent_start)' : 'jni_onload (self-load / gadget / xposed)',
    })),
    gadget: {
      pinned,
      cached,
      loader: 'tools/load_frida_gadget.sh',
      note: 'optional high-footprint backend: the host tool stages it into <pkg>/code_cache and triggers load_so (MCP: load_library); the daemon itself has no adb.',
    },
    xposed: {
      module: 'com.adh.xposed',
      source: 'injector/xposed',
      control: 'device-side: ADH Manager (Scope screen) -> Device Daemon, AIDL v5',
      verify: ['tools/verify_v31_xposed.sh', 'tools/verify_v32_backend_control.sh'],
    },
    zygisk: {
      module: 'injector/zygisk',
      control: 'device-side: ADH Manager -> Device Daemon (scope.json allowlist)',
      verify: ['tools/verify_v27_zygisk.sh'],
    },
    updatedAt: Date.now(),
  };
}

/**
 * Which injection paths are actually visible inside one target process. Derived from the agent's
 * own /proc/self/maps, so it reports the truth rather than what the host believes it injected.
 */
export async function classifySession(session: string) {
  const r = await agentCmd(session, 'maps');
  if (!r?.ok) throw new Error(String(r?.error ?? 'agent maps failed'));
  const mods = modulesFromMaps(r.regions ?? []);
  const paths = mods.map((m: any) => String(m?.path ?? m?.name ?? ''));
  const backends: string[] = ['adhd_agent'];
  if (paths.some((p) => p.includes('/data/adb/modules/adh/'))) backends.push('zygisk');
  if (paths.some((p) => p.includes('com.adh.xposed'))) backends.push('xposed_module');
  if (paths.some((p) => /libgadget\.so|frida/i.test(p))) backends.push('frida_gadget');
  if (paths.some((p) => /\/lib\/arm64\/libadh_agent\.so$/.test(p))) backends.push('self_load');
  return { session, moduleCount: mods.length, backends };
}
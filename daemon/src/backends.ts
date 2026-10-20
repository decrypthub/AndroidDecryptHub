// Injection-backend matrix (module W). Shared by the REST surface (GET /api/backends) and the MCP
// tool `backends`, so an AI client and the browser console see exactly the same truth.
//
// Official paths: Zygisk (device scope via ADH Manager → Device Daemon) and sandbox self-load.
// Frida Gadget is not a product backend — do not advertise cache/loader commands here.
import { agentCmd, modulesFromMaps } from './service.ts';
import { sessions } from './state.ts';

export function backendMatrix() {
  return {
    agents: [...sessions.values()].map((s) => ({
      session: s.sessionId,
      package: s.package,
      process: s.process,
      pid: s.pid,
      online: s.online,
      entry: s.entry,
      // Coarse host-side label; classifySession() below resolves one session precisely from the
      // agent's own module list (the agent .so path tells Zygisk / self-load apart).
      entryKind: s.entry === 'start' ? 'injected (adh_agent_start)' : 'jni_onload (self-load)',
    })),
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
  if (paths.some((p) => /\/lib\/arm64\/libadh_agent\.so$/.test(p))) backends.push('self_load');
  return { session, moduleCount: mods.length, backends };
}

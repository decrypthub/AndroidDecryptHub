// Which loaded modules belong to the selected app. Pure: no process state, no filesystem.
//
// A process maps hundreds of system libraries. The Dump page's SO column is the app's own
// native libraries, the ones whose path sits under that package, not libc / apex / the agent.

export interface AppSoModule {
  name: string;
  path: string;
}

export function appOwnedSoModules<T extends AppSoModule>(modules: readonly T[], packageName: string): T[] {
  const pkg = packageName.trim();
  if (!pkg || pkg === '?') return [];
  return modules.filter((m) => isAppOwnedSo(m, pkg));
}

function isAppOwnedSo(mod: AppSoModule, pkg: string): boolean {
  const name = mod.name.trim();
  const path = mod.path.trim();
  if (!name.endsWith('.so') && !path.endsWith('.so')) return false;
  if (name === 'libadh_agent.so') return false;
  if (path.includes('/data/adb/')) return false;
  const parts = path.split('/');
  return parts.some((part) => part === pkg || part.startsWith(pkg + '-'));
}

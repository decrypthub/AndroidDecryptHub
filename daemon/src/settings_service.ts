import { applyCaptureEnabled, autoAntiDebugEnabled } from './service.ts';
import { configStats, mergeSettings, saveSettings, settings } from './state.ts';

// Serialize save→publish→apply across MCP and HTTP. A second patch cannot change the
// global settings while the first is still applying them to targets.
let tail: Promise<unknown> = Promise.resolve();
export function patchSettings(patch: unknown, applyCapture = applyCaptureEnabled) {
  const run = tail.then(async () => {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      return { ok: false, code: 'INVALID_SETTINGS', error: 'settings patch must be an object', persisted: false, applied: [] as string[] };
    }
    if (['capture', 'ui', 'artifacts', 'startup'].some(key => Object.hasOwn(patch, key)
      && (!(patch as any)[key] || typeof (patch as any)[key] !== 'object' || Array.isArray((patch as any)[key])))) {
      return { ok: false, code: 'INVALID_SETTINGS', error: 'settings sections must be objects', persisted: false, applied: [] as string[] };
    }
    const candidate = structuredClone(settings);
    const applied = mergeSettings(patch, candidate);
    if (!applied.length) return { ok: false, code: 'INVALID_SETTINGS', error: 'no supported settings sections', persisted: false, applied };
    try { saveSettings(candidate); }
    catch (error) {
      return { ok: false, code: 'SETTINGS_PERSIST_FAILED', error: `settings were not saved or applied: ${(error as Error).message}`, persisted: false, applied: [] as string[], settings: structuredClone(settings) };
    }
    Object.assign(settings, candidate);
    const capture = (patch as Record<string, any>).capture;
    // Output filters apply on ingestion; startup/auto-dump changes apply at the next
    // explicit start/hello. A UI-only or retention patch must not re-install hooks.
    const needsCaptureApply = typeof capture?.enabled === 'boolean'
      || ['cryptoModule', 'fileModule', 'sysModule'].some(key => typeof capture?.[key] === 'string');
    let runtime: Awaited<ReturnType<typeof applyCaptureEnabled>> = { ok: true, targets: [] };
    if (needsCaptureApply) {
      try { runtime = await applyCapture(); }
      catch (error) { runtime = { ok: false, targets: [], error: (error as Error).message }; }
    }
    return {
      ok: runtime.ok, applied, persisted: true, runtimeApplied: runtime.ok, runtime,
      settings: structuredClone(settings), stats: configStats(), autoAntiDebug: autoAntiDebugEnabled(),
      deferred: [ ...(applied.includes('startup') ? ['startup:next-hello'] : []),
        ...(typeof capture?.autoDumpDex === 'boolean' ? ['autoDumpDex:next-automatic-capture-loop'] : []) ],
      maintenanceRequired: applied.includes('artifacts') || !!capture && ['retain', 'maxAgeDays'].some(key => Object.hasOwn(capture, key)),
      ...(!runtime.ok ? { code: 'SETTINGS_APPLY_FAILED', error: runtime.error || 'settings saved; some target operations failed' } : {}),
    };
  });
  tail = run.catch(() => {});
  return run;
}

export function settingsHttpStatus(result: { ok: boolean; code?: string }) {
  return result.ok ? 200 : result.code === 'SETTINGS_PERSIST_FAILED' ? 500
    : result.code === 'SETTINGS_APPLY_FAILED' ? 502 : 400;
}

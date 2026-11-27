import { checkpoint, localEffect } from './execution_context.ts';
import { getHookPlans } from './hook_plan_host.ts';
import { isValidPackage } from './mcp_onboarding.ts';
import { automaticSnapshot, runAutomatic } from './operation_host.ts';
import { applyCaptureEnabled, applySelectedFamilies, autoAntiDebugEnabled } from './service.ts';
import { captureSettingsForPackage, configStats, CRYPTO_FAMILY_KEYS, hostSettingsSnapshot, mergeSettings, saveSettings, sessions, settings } from './state.ts';
import type { CryptoFamilies, CryptoFamily, Settings } from './state.ts';

// Save, publish and apply in order across both settings entry points and reconnects.
let tail: Promise<unknown> = Promise.resolve();
function serializeSettings<T>(work: () => Promise<T>): Promise<T> {
  const run = tail.then(work);
  tail = run.catch(() => {});
  return run;
}

function persistSettings(candidate: Settings): string | undefined {
  checkpoint();
  try { localEffect(() => saveSettings(candidate), { kind: 'host', action: 'settings.save' }); }
  catch (error) { return `settings were not saved or applied: ${(error as Error).message}`; }
  Object.assign(settings, candidate);
}

export async function applyCaptureSettingsOnConnect(sessionId: string) {
  const session = sessions.get(sessionId);
  if (!session?.online || !captureSettingsForPackage(session.package).enabled) return;
  return runAutomatic(sessionId, 'automatic-capture-families', automaticSnapshot(sessionId), () => serializeSettings(async () => {
    if (!captureSettingsForPackage(session.package).enabled) return { ok: true, targets: [] };
    return applySelectedFamilies({ sessionId, held: getHookPlans().heldSessions() });
  }));
}

export function patchAppCaptureFamily(patch: unknown) {
  return serializeSettings(async () => {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      return { ok: false, code: 'INVALID_SETTINGS', error: '需要应用和一个算法开关', persisted: false };
    }
    const { package: pkg, family, enabled } = patch as Record<string, unknown>;
    if (Object.keys(patch).length !== 3 || typeof pkg !== 'string' || !isValidPackage(pkg)
      || typeof family !== 'string' || !CRYPTO_FAMILY_KEYS.includes(family as CryptoFamily) || typeof enabled !== 'boolean') {
      return { ok: false, code: 'INVALID_SETTINGS', error: '需要有效的包名和一个算法开关', persisted: false };
    }
    const previous = captureSettingsForPackage(pkg);
    const families = Object.fromEntries(CRYPTO_FAMILY_KEYS.map(key => [key,
      key === family ? enabled : previous.enabled && previous.families[key],
    ])) as CryptoFamilies;
    const candidate = structuredClone(settings);
    candidate.capture.familiesByPackage = { ...candidate.capture.familiesByPackage, [pkg]: families };
    const persistError = persistSettings(candidate);
    if (persistError) return { ok: false, code: 'SETTINGS_PERSIST_FAILED', error: persistError, persisted: false };

    let runtime: Awaited<ReturnType<typeof applySelectedFamilies>>;
    try {
      runtime = await applySelectedFamilies({ packageName: pkg, held: getHookPlans().heldSessions(), stopIfDisabled: true });
    } catch (error) {
      runtime = { ok: false, targets: [], error: (error as Error).message };
    }
    return {
      ok: runtime.ok, package: pkg, capture: captureSettingsForPackage(pkg), persisted: true, runtime,
      ...(!runtime.ok ? { code: 'SETTINGS_APPLY_FAILED', error: runtime.error || '已保存，部分会话未应用' } : {}),
    };
  });
}

export function patchSettings(patch: unknown, applyCapture = applyCaptureEnabled) {
  return serializeSettings(async () => {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      return { ok: false, code: 'INVALID_SETTINGS', error: 'settings patch must be an object', persisted: false, applied: [] as string[] };
    }
    if (['capture', 'ui', 'artifacts', 'startup'].some(key => Object.hasOwn(patch, key)
      && (!(patch as any)[key] || typeof (patch as any)[key] !== 'object' || Array.isArray((patch as any)[key])))) {
      return { ok: false, code: 'INVALID_SETTINGS', error: 'settings sections must be objects', persisted: false, applied: [] as string[] };
    }
    const beforeEnabled = settings.capture.enabled;
    const candidate = structuredClone(settings);
    const applied = mergeSettings(patch, candidate);
    const capturePatch = (patch as Record<string, any>).capture;
    const postedFamilies = capturePatch?.families && typeof capturePatch.families === 'object'
      ? Object.entries(capturePatch.families).filter((entry): entry is [string, boolean] => typeof entry[1] === 'boolean')
      : [];
    if (postedFamilies.length === 1 && (CRYPTO_FAMILY_KEYS as readonly string[]).includes(postedFamilies[0][0]) && postedFamilies[0][1] === true && !beforeEnabled && Object.keys(capturePatch).length === 1) {
      for (const key of CRYPTO_FAMILY_KEYS) if (key !== postedFamilies[0][0]) candidate.capture.families[key] = false;
    }
    if (postedFamilies.length && typeof capturePatch?.enabled !== 'boolean') candidate.capture.enabled = CRYPTO_FAMILY_KEYS.some((key) => candidate.capture.families[key] !== false);
    if (!applied.length) return { ok: false, code: 'INVALID_SETTINGS', error: 'no supported settings sections', persisted: false, applied };
    const persistError = persistSettings(candidate);
    if (persistError) {
      return { ok: false, code: 'SETTINGS_PERSIST_FAILED', error: persistError, persisted: false, applied: [] as string[], settings: hostSettingsSnapshot() };
    }
    const capture = (patch as Record<string, any>).capture;
    // A families patch is the panel's algorithm choice and installs that set.
    // An enable-only patch only resumes draining. Legacy module fields stay templates.
    const needsCaptureApply = typeof capture?.enabled === 'boolean';
    const familiesChosen = !!capture && Object.hasOwn(capture, 'families');
    let runtime: Awaited<ReturnType<typeof applyCaptureEnabled>> = { ok: true, targets: [] };
    if (needsCaptureApply && !familiesChosen || familiesChosen && !settings.capture.enabled) {
      try { runtime = await applyCapture(familiesChosen ? getHookPlans().heldSessions() : undefined); }
      catch (error) { runtime = { ok: false, targets: [], error: (error as Error).message }; }
    }
    // One checked family updates Host settings. Sessions with an open Hook plan keep that plan's policy.
    if (familiesChosen) {
      try {
        const hooked = await applySelectedFamilies({ held: getHookPlans().heldSessions() });
        runtime = {
          ok: runtime.ok && hooked.ok,
          targets: [...runtime.targets, ...hooked.targets],
          ...(hooked.error ? { error: hooked.error } : {}),
        };
      } catch (error) {
        runtime = { ok: false, targets: runtime.targets, error: (error as Error).message };
      }
    }
    return {
      ok: runtime.ok, applied, persisted: true, runtimeApplied: runtime.ok, runtime,
      settings: hostSettingsSnapshot(), stats: configStats(), autoAntiDebug: autoAntiDebugEnabled(),
      deferred: [ ...(applied.includes('startup') ? ['startup:hook-plan-template-only'] : []),
        ...(['autoDumpDex','cryptoModule','fileModule','sysModule'].some(key=>Object.hasOwn(capture||{},key)) ? ['legacy-capture:hook-plan-template-only'] : []) ],
      maintenanceRequired: applied.includes('artifacts') || !!capture && ['retain', 'maxAgeDays'].some(key => Object.hasOwn(capture, key)),
      ...(!runtime.ok ? { code: 'SETTINGS_APPLY_FAILED', error: runtime.error || 'settings saved; some target operations failed' } : {}),
    };
  });
}

export function settingsHttpStatus(result: { ok: boolean; code?: string }) {
  return result.ok ? 200 : result.code === 'SETTINGS_PERSIST_FAILED' ? 500
    : result.code === 'SETTINGS_APPLY_FAILED' ? 502 : 400;
}

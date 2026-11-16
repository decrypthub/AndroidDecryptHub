// Destructive retention is reachable only through an explicit operation, never import/boot/save.
import { retainCaptureFiles } from './capture_persist.ts';
import { applyCaptureRetainCap, DATA_DIR, previewArtifactRetention, settings } from './state.ts';
import { pruneArtifactsAndIndex } from './service.ts';

export function maintainData(options: { dryRun?: boolean; confirm?: boolean } = {}) {
  const dryRun = options.dryRun !== false;
  if (!dryRun && options.confirm !== true) return { ok: false, dryRun, error: 'retention requires confirm:true; preview first' };
  const plan = previewArtifactRetention();
  const captures = retainCaptureFiles(DATA_DIR, settings.capture, dryRun);
  if (dryRun) return {
    ok: captures.errors.length === 0, dryRun, policy: structuredClone({ capture: settings.capture, artifacts: settings.artifacts }),
    artifacts: { count: plan.evict.length, bytes: plan.evict.reduce((n, a) => n + a.size, 0), remainingBytes: plan.remainingBytes }, captures,
  };
  const artifacts = pruneArtifactsAndIndex();
  applyCaptureRetainCap();
  return { ok: !!artifacts && artifacts.failed === 0 && captures.errors.length === 0, dryRun, artifacts, captures };
}

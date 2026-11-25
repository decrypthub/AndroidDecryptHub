import test from 'node:test';
import assert from 'node:assert/strict';
import { readPackageIcon } from '../src/package_icon.ts';

test('host APK icon parsing is not an implicit product fallback', async () => {
  const fallback = process.env.ADH_ICON_HOST_FALLBACK;
  delete process.env.ADH_ICON_HOST_FALLBACK;
  try {
    await assert.rejects(
      () => readPackageIcon('com.example.no-such-package', ''),
      (error: unknown) => (error as { code?: string }).code === 'DEVICE_ICON_UNAVAILABLE',
    );
  } finally {
    if (fallback === undefined) delete process.env.ADH_ICON_HOST_FALLBACK;
    else process.env.ADH_ICON_HOST_FALLBACK = fallback;
  }
});

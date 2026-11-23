import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageLines } from '../src/app_catalog.ts';
import { pickBadgingIcon, applicationLabel } from '../src/scope_list.ts';

test('package lines keep the apk path and the system flag', () => {
  const rows = parsePackageLines([
    'package:/data/app/~~x==/com.example.app-a/base.apk=com.example.app',
    'package:/system/app/Settings/Settings.apk=com.android.settings',
    'noise',
  ].join('\n'), true);
  assert.deepEqual(rows.map(row => [row.package, row.system]), [
    ['com.example.app', true],
    ['com.android.settings', true],
  ]);
  assert.equal(rows[0].apk.endsWith('/base.apk'), true);
});

test('the launcher icon is the full bitmap, not a foreground layer', () => {
  const text = [
    "application-label-zh:'设置'",
    "application-icon-160:'res/mipmap-mdpi-v4/ic_launcher_foreground.png'",
    "application-icon-240:'res/mipmap-anydpi-v26/ic_launcher.xml'",
    "application-icon-480:'res/mipmap-xxxhdpi-v4/ic_launcher.png'",
    "application-icon-640:'res/mipmap-xxxhdpi-v4/ic_launcher_round.png'",
  ].join('\n');
  assert.equal(applicationLabel(text), '设置');
  assert.equal(pickBadgingIcon(text), 'res/mipmap-xxxhdpi-v4/ic_launcher.png');
});

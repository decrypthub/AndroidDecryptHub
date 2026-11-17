// Source consistency gate; never reads operator state or connects to a device.
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const prop=Object.fromEntries(read('injector/zygisk/module/module.prop').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>[s.slice(0,s.indexOf('=')),s.slice(s.indexOf('=')+1)]));
const version=prop.version.replace(/^v/,'');assert.match(version,/^\d+\.\d+\.\d+$/);
const update=JSON.parse(read('injector/zygisk/update.json'));
assert.equal(update.version,'v'+version);assert.equal(update.versionCode,Number(prop.versionCode));
assert.ok(update.zipUrl.endsWith(`/v${version}/adh-bundle-v${version}.zip`));
assert.ok(update.changelog.endsWith('/v'+version));
for(const component of ['manager','daemon']){
  const source=read(`device/${component}/build.gradle.kts`);
  assert.equal(/versionName\s*=\s*"([^"]+)"/.exec(source)?.[1],version,component+' version');
  if(component==='manager')assert.equal(Number(/versionCode\s*=\s*(\d+)/.exec(source)?.[1]),update.versionCode);
}
assert.equal(/#define AGENT_VER\s+"([^"]+)"/.exec(read('agent/src/bootstrap/agent_internal.h'))?.[1],version);
const pkg=JSON.parse(read('daemon/package.json')),lock=JSON.parse(read('daemon/package-lock.json'));
assert.equal(pkg.version,version);assert.equal(lock.version,version);assert.equal(lock.packages[''].version,version);
console.log('PASS release source versions '+version+' / code '+update.versionCode);

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, utimesSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveStoragePaths } from '../src/storage.ts';

const mcpUrl = pathToFileURL(resolve('src/mcp.ts')).href;
const stateUrl = pathToFileURL(resolve('src/state.ts')).href;
const lifecycleUrl = pathToFileURL(resolve('src/host_lifecycle.ts')).href;
const maintenanceUrl = pathToFileURL(resolve('src/maintenance.ts')).href;
const serviceUrl = pathToFileURL(resolve('src/service.ts')).href;
const guard = `
  import assert from 'node:assert/strict';
  import fs from 'node:fs';
  import cp from 'node:child_process';
  import net from 'node:net';
  import {syncBuiltinESMExports} from 'node:module';
  cp.execFile = cp.spawn = () => { throw Error('device/child execution forbidden in lifecycle fixture'); };
  net.Server.prototype.listen = () => { throw Error('listeners forbidden in lifecycle fixture'); };
  syncBuiltinESMExports();
`;
function child(root: string, code: string) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', guard + code], {
    encoding: 'utf8', timeout: 20000, windowsHide: true,
    env: { ...process.env, ADH_DATA_DIR: root, ADH_CAPTURES_DIR: join(root, 'captures'), ADH_SKIP_ARTIFACT_LOAD: '0' },
  });
  assert.equal(result.status, 0, `${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
}
function cleanup(root: string) {
  assert.ok(root.startsWith(join(tmpdir(), 'adh-p0-')));
  rmSync(root, { recursive: true, force: true });
}

test('path resolution isolates all storage with ADH_DATA_DIR and preserves the legacy default', () => {
  const isolated = resolveStoragePaths({ ADH_DATA_DIR: join(tmpdir(), 'adh-isolated') });
  assert.equal(isolated.capturesDir, join(isolated.dataDir, 'captures'));
  assert.equal(resolveStoragePaths({}).capturesDir, resolve('..', 'captures'));
  const first = { ADH_SKIP_ARTIFACT_LOAD: '1', ADH_TEST_RUN_ID: '00000000-0000-4000-8000-000000000001' };
  const second = { ...first, ADH_TEST_RUN_ID: '00000000-0000-4000-8000-000000000002' };
  assert.notEqual(resolveStoragePaths(first).dataDir, resolveStoragePaths(second).dataDir);
  assert.deepEqual(resolveStoragePaths(first), resolveStoragePaths(first));
  assert.equal(resolveStoragePaths({ ...first, ADH_TEST_RUN_ID: '../outside' }).dataDir,
    resolveStoragePaths({ ADH_SKIP_ARTIFACT_LOAD: '1' }).dataDir);
});

test('importing MCP into an absent data root creates no files, dirs, database, listener or device calls', () => {
  const root = mkdtempSync(join(tmpdir(), 'adh-p0-'));
  try {
    const absent = join(root, 'absent');
    child(absent, `await import(${JSON.stringify(mcpUrl)}); assert.equal(fs.existsSync(process.env.ADH_DATA_DIR), false);`);
  } finally { cleanup(root); }
});

test('recovery retains expired evidence and corrupt index bytes; cleanup needs a separate explicit call', () => {
  const root = mkdtempSync(join(tmpdir(), 'adh-p0-'));
  try {
    const capDir = join(root, 'captures'); mkdirSync(capDir);
    const bytes = Buffer.from('synthetic expired artifact');
    const sha = createHash('sha256').update(bytes).digest('hex');
    const artifact = join(capDir, `${sha.slice(0, 16)}.dex.bin`);
    writeFileSync(artifact, bytes); utimesSync(artifact, 1000, 1000);
    const pkg = 'com.example.fixture'; const pkgDir = join(root, 'packages', pkg); mkdirSync(pkgDir, { recursive: true });
    const rows = Array.from({ length: 70 }, (_, n) => JSON.stringify({ id: n + 1, ts: 1000, package: pkg, sessionId: 'old', hex: '41' })).join('\n') + '\n';
    writeFileSync(join(pkgDir, 'captures.jsonl'), rows);
    writeFileSync(join(root, 'settings.json'), JSON.stringify({ capture: { enabled: false, autoDumpDex: false, retain: 50, maxAgeDays: 14 }, artifacts: { maxAgeDays: 14 } }));
    writeFileSync(join(root, 'dex-index.sqlite'), 'corrupt derived index sentinel');
    writeFileSync(join(root, 'events.jsonl'), JSON.stringify({ seq: 1, ts: 1000, type: 'dump.new', data: { sha256: sha, package: pkg, source: 'fixture' } }) + '\n');
    child(root, `
      const root = process.env.ADH_DATA_DIR;
      const snapshot = () => {
        const files = [];
        const walk = p => { for(const n of fs.readdirSync(p)) { const f=p+'/'+n, st=fs.statSync(f); if(st.isDirectory())walk(f); else files.push([f,fs.readFileSync(f).toString('base64'),st.mtimeMs]); } };
        walk(root); return files;
      };
      const before = snapshot();
      await import(${JSON.stringify(mcpUrl)});
      assert.deepEqual(snapshot(), before, 'module imports must not change existing bytes or metadata');
      const state = await import(${JSON.stringify(stateUrl)});
      assert.equal(state.captures.length, 0); assert.equal(state.dumps.size, 0);
      const {initializeHost} = await import(${JSON.stringify(lifecycleUrl)});
      assert.equal(initializeHost().alreadyInitialized, false);
      assert.equal(initializeHost().alreadyInitialized, true);
      assert.equal(state.captures.length, 50); assert.equal(state.dumps.size, 1);
      assert.equal(state.settings.capture.enabled, false);
      assert.equal([...state.dumps.values()][0].package, ${JSON.stringify(pkg)});
      assert.deepEqual(snapshot(), before, 'recovery must not age-prune, trim, rewrite sidecars or rebuild indexes');
      const {persistArtifact} = await import(${JSON.stringify(serviceUrl)});
      const added = await persistArtifact(Buffer.from('new synthetic artifact'), {source:'fixture',addr:'',tag:'new',sessionId:'fixture',package:${JSON.stringify(pkg)}});
      assert.equal(fs.existsSync(${JSON.stringify(artifact)}),true, 'writing new artifacts cannot delete historical evidence');
      assert.equal(fs.readFileSync(${JSON.stringify(join(pkgDir, 'captures.jsonl'))},'utf8'),${JSON.stringify(rows)});
      const afterWrite = snapshot();
      const {maintainData} = await import(${JSON.stringify(maintenanceUrl)});
      const preview=maintainData(); assert.equal(preview.dryRun, true); assert.equal(preview.artifacts.count,1); assert.equal(preview.captures.removed,70);
      assert.equal(maintainData({dryRun:false}).ok,false);
      assert.deepEqual(snapshot(), afterWrite, 'preview and refused cleanup must preserve evidence');
      fs.unlinkSync(root+'/dex-index.sqlite'); // only the synthetic corrupt cache, after preservation assertions
      assert.equal(maintainData({dryRun:false,confirm:true}).ok,true);
      assert.equal(fs.existsSync(${JSON.stringify(artifact)}),false);
      assert.equal(fs.existsSync(${JSON.stringify(join(pkgDir, 'captures.jsonl'))}),false);
      assert.equal(fs.existsSync(added.meta.path),true, 'maintenance preserves unexpired artifacts');
    `);
    // All assertions and cleanup operate only on generated temporary fixtures.
  } finally { cleanup(root); }
});

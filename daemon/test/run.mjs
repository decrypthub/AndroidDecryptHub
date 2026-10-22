// Test launcher. Sets the environment the suite needs BEFORE the runner spawns one process per
// test file, then hands over to `node --test`.
//
// Why this exists: state.ts re-adopts every artifact in captures/ at import time, which on a working
// machine is ~1.2 GiB. Twelve test processes doing that at once made the parallel suite flaky (a
// file would occasionally fail with no useful output) and slow. CI has an empty tree and never hit
// it, but a gate that is only green on a clean machine is not a gate. ADH_SKIP_ARTIFACT_LOAD makes
// the store start empty, so the suite is hermetic and order-independent.
//
// `stdio: 'inherit'` (not a pipe) matters: the harness forbids capturing a child's piped output.
import { spawn } from 'node:child_process';

const args = ['--test', ...process.argv.slice(2)];
const child = spawn(process.execPath, args, {
  stdio: 'inherit',
  env: { ...process.env, ADH_SKIP_ARTIFACT_LOAD: '1' },
});
child.on('error', (e) => {
  console.error(`test launcher: failed to start node --test: ${e.message}`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) {
    console.error(`test launcher: node --test was killed by ${signal}`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});

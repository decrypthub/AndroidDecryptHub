// Test launcher. Sets the environment the suite needs BEFORE the runner spawns one process per
// test file, then hands over to `node --test`.
//
// Imports are now non-destructive; explicit test operations must still never use an inherited
// operator data/capture root. The flag assigns each test process its own temporary default root.
//
// `stdio: 'inherit'` (not a pipe) matters: the harness forbids capturing a child's piped output.
import { spawn } from 'node:child_process';

const args = ['--test', ...process.argv.slice(2)];
const { ADH_DATA_DIR, ADH_CAPTURES_DIR, ADH_OPERATOR_TOKEN, ...isolatedEnv } = process.env;
const child = spawn(process.execPath, args, {
  stdio: 'inherit',
  env: { ...isolatedEnv, ADH_SKIP_ARTIFACT_LOAD: '1' },
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

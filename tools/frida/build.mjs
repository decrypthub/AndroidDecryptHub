#!/usr/bin/env node
// ADH Frida hook bundler.
//
// Why this exists: as of Frida 17.0.0 the language bridges (Java.perform()/ObjC/Swift)
// are no longer bundled inside the Gadget runtime — a hook that uses them must be
// bundled together with the bridge package (https://frida.re/docs/gadget/ §"Using the
// language bridges"). We bundle with esbuild (prebuilt binary, no C toolchain) instead
// of `frida-compile`, whose CLI hard-depends on the native `frida` bindings and tries
// to build them from source on Windows.
//
// Usage:
//   node tools/frida/build.mjs --input hook.js [--output hook.bundle.js]
//                              [--bridge auto|java|none] [--minify]
//
// Prints one JSON line on stdout: { output, bytes, bridges, source }.
// Exit 1 with an actionable message on failure.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const HERE = dirname(fileURLToPath(import.meta.url));
const BUNDLE_TAG = 'adh-frida-bundle';

// Classic-style hooks address the bridge through a global `Java`; Frida 16 and older
// provided it, 17+ does not, so we inject the import and publish the global before the
// hook body runs (single module body → ordering is guaranteed).
const BRIDGE_SHIM = {
  java: "import Java from 'frida-java-bridge';\nglobalThis.Java = Java;\n",
  none: '',
};

function fail(msg) {
  process.stderr.write(`!! ${msg}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { input: null, output: null, bridge: 'auto', minify: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--input': args.input = argv[++i]; break;
      case '--output': args.output = argv[++i]; break;
      case '--bridge': args.bridge = argv[++i]; break;
      case '--minify': args.minify = true; break;
      case '-h':
      case '--help': args.help = true; break;
      default: fail(`unknown argument: ${a}`);
    }
  }
  if (args.help || argv.length === 0) {
    process.stdout.write('usage: node tools/frida/build.mjs --input <hook.js> [--output <out.js>] [--bridge auto|java|none] [--minify]\n');
    process.exit(0);
  }
  if (!args.input) fail('--input is required');
  if (!['auto', 'java', 'none'].includes(args.bridge)) {
    fail(`--bridge must be auto|java|none (got ${args.bridge})`);
  }
  return args;
}

// A hook that already imports the bridge is a module input: bundle it verbatim.
function usesBridgeImport(src) {
  return /from\s*['"]frida-java-bridge['"]|require\(\s*['"]frida-java-bridge['"]\s*\)/.test(src);
}
function needsJavaShim(src) {
  return /\bJava\s*\./.test(src) || /\bJava\s*\[/.test(src);
}

const args = parseArgs(process.argv.slice(2));
const input = resolve(args.input);
const output = resolve(args.output ?? `${input.replace(/\.js$/, '')}.bundle.js`);

let source;
try {
  source = await readFile(input, 'utf8');
} catch (e) {
  fail(`cannot read ${input}: ${e.message}`);
}

let bridges = 'none';
let contents = source;
let alreadyBundled = source.includes(BUNDLE_TAG);

if (!alreadyBundled) {
  const wantsJava = args.bridge === 'java' || (args.bridge === 'auto' && needsJavaShim(source));
  if (usesBridgeImport(source)) {
    // Module-style hook: it imports what it needs itself.
    bridges = 'module';
  } else if (wantsJava) {
    bridges = 'java';
    contents = BRIDGE_SHIM.java + source;
  }
}

if (!alreadyBundled) {
  const banner = `/* ${BUNDLE_TAG}: src=${basename(input)} bridges=${bridges} */`;
  let result;
  try {
    result = await build({
      stdin: { contents, resolveDir: HERE, sourcefile: 'adh-hook-entry.js', loader: 'js' },
      bundle: true,
      format: 'iife',
      target: ['es2020'],
      platform: 'neutral',
      write: false,
      logLevel: 'error',
      legalComments: 'none',
      minify: args.minify,
      banner: { js: banner },
    });
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (msg.includes('frida-java-bridge')) {
      fail(`cannot resolve frida-java-bridge — install the bundler deps:\n   cd tools/frida && npm install --ignore-scripts`);
    }
    fail(`bundle failed: ${msg}`);
  }
  contents = result.outputFiles[0].text;
}

await mkdir(dirname(output), { recursive: true });
await writeFile(output, contents);

// Contract with the shell wrappers: stdout is exactly the output path (one line),
// the human-readable summary goes to stderr. (Multi-line `node -e` payloads are
// unreliable through the Volta shim under Git Bash, so callers stay dumb on purpose.)
const bytes = Buffer.byteLength(contents);
const resolvedBridges = alreadyBundled ? 'passthrough' : bridges;
process.stderr.write(`>> bundle (bridges=${resolvedBridges}, ${bytes} bytes) -> ${output}\n`);
process.stdout.write(`${output}\n`);
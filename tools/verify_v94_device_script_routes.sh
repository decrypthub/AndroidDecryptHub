#!/usr/bin/env bash
# v4.87 device-script route check (HOST-ONLY, no device, <1s).
#
# Why this exists: the device acceptance scripts talk to the daemon over HTTP, and they are the part
# of the suite that can only run when a phone is attached. A route that got renamed or removed
# therefore stays invisible until someone plugs a device in - at which point several scripts fail at
# once for the same, boring reason. This check reads every route the daemon actually declares and
# every /api/... path the scripts reference, and fails on a reference no route can serve.
#
# Prefix routes (declared with prefix: true and a trailing slash) cover their sub-paths, so
# "/api/captures/123" is matched by "/api/captures/".
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const fs = await import('node:fs');
const path = await import('node:path');
const problems = [];
const notes = [];

// ---- every path the daemon declares ----
const routePaths = new Set();
const walk = (dir) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith('.ts')) {
      const src = fs.readFileSync(p, 'utf8');
      for (const m of src.matchAll(/path:\s*'([^']+)'/g)) routePaths.add(m[1]);
    }
  }
};
const httpDir = path.join(root, 'daemon', 'src', 'http');
if (!fs.existsSync(httpDir)) problems.push(`daemon route directory missing: ${httpDir}`);
else walk(httpDir);
if (routePaths.size < 50) problems.push(`only ${routePaths.size} route paths found - did the route declaration style change?`);
// Only /api/... routes are comparable with what the scripts call, and a prefix of '/' (the static
// file / SPA route) would 'serve' every path - which would make this check pass no matter what.
const apiRoutes = new Set([...routePaths].filter((p) => p.startsWith('/api/')));
const prefixes = [...apiRoutes].filter((p) => p.endsWith('/') && p !== '/');

// ---- every /api/... the acceptance scripts reference ----
const referenced = new Map();
const toolsDir = path.join(root, 'tools');
for (const f of fs.readdirSync(toolsDir)) {
  if (!f.startsWith('verify_') || !f.endsWith('.sh')) continue;
  if (f === 'verify_all.sh' || f === 'verify_v94_device_script_routes.sh') continue;   // the runner and this scanner
  const src = fs.readFileSync(path.join(toolsDir, f), 'utf8');
  // Comments are prose, not endpoints: a header that mentions "api/settings export->import" used to
  // register a path that no route serves. Strip shell and JS comments before scanning (but keep
  // "http://" intact - that colon is what tells a URL from a comment).
  const code = src.split('\n')
    .filter((line) => !/^\s*(#|\/\/)/.test(line))
    .map((line) => line.replace(/\s#.*$/, '').replace(/(^|[^:])\/\/.*$/, '$1'))
    .join('\n');
  for (const m of code.matchAll(/\/api\/[A-Za-z0-9_/.:-]*/g)) {
    const key = m[0].replace(/[.:,-]+$/, '').split('?')[0];
    if (!referenced.has(key)) referenced.set(key, new Set());
    referenced.get(key).add(f);
  }
}
const unknown = [...referenced.entries()].filter(([p]) => !apiRoutes.has(p) && !prefixes.some((pre) => p.startsWith(pre)));
for (const [p, files] of unknown) {
  problems.push(`no route serves ${p} (referenced by ${[...files].slice(0, 3).join(', ')}${files.size > 3 ? ', ...' : ''})`);
}
notes.push(`api routes declared: ${apiRoutes.size} of ${routePaths.size} route paths (${prefixes.length} prefix routes)`);
notes.push(`api paths referenced by acceptance scripts: ${referenced.size}, unserved: ${unknown.length}`);
// Not a failure, but worth seeing: routes nothing in the suite touches yet.
const untouched = [...apiRoutes].filter((p) => !prefixes.includes(p) && !referenced.has(p));
if (untouched.length) notes.push(`routes not referenced by any acceptance script (${untouched.length}): ${untouched.slice(0, 8).join(', ')}${untouched.length > 8 ? ', ...' : ''}`);

for (const n of notes) console.log('  ' + n);
if (problems.length) {
  for (const p of problems) console.log('FAIL ' + p);
  console.log('RESULT:FAIL');
} else {
  console.log('RESULT:PASS');
}
EOF
)"
set -e
echo "$OUT"
if grep -q '^RESULT:FAIL' <<<"$OUT"; then
  echo "❌ v4.87 device-script routes FAIL"
  exit 1
fi
echo "✅ v4.87 device-script routes PASS"

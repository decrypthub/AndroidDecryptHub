#!/usr/bin/env bash
# native_look (HOST-ONLY).
#
# The front door that turns a native hook hit and its memory copy into one
# readable result. The join is pure. A device is not required: arm/read/stop
# are thin wrappers over native_hook, and the sentence the operator sees is
# what this test locks.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

if ! verify_unit_pass "native look" native_look.test.ts 5; then
  echo "RESULT:FAIL (native look unit tests did not all pass)"
  exit 1
fi

set +e
OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const fs = await import('node:fs');
const read = (rel) => fs.readFileSync(`${String(root).replace(/\\/g, '/')}/${rel}`, 'utf8');
const problems = [];
const has = (text, needle, label) => {
  if (!text.includes(needle)) problems.push(`${label}: missing ${JSON.stringify(needle)}`);
};
const mcp = read('daemon/src/mcp.ts');
const look = read('daemon/src/native_look.ts');
has(mcp, "name: 'native_look'", 'mcp tool');
has(mcp, 'nativeLookRead', 'mcp read');
has(look, 'joinNativeLook', 'join');
has(look, '还没有命中', 'quiet sentence');
if (problems.length) {
  console.log(problems.join('\n'));
  console.log('RESULT:FAIL');
} else {
  console.log('host wiring ok');
  console.log('RESULT:PASS');
}
EOF
)"
set -e
echo "$OUT"
verify_gate "v108 native look (host)" 0 && exit 0 || exit 1

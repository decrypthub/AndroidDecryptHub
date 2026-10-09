#!/usr/bin/env bash
# v4.50 agent signature scrub (HOST-ONLY, no device; SKIPs when the artifact is not built).
#
# The agent runs inside the target, so every string in its image is readable by that target. This
# accepts the stage-1 scrubs (own log tags, own messages that named the vendored frameworks, the
# fixture defaults that used to live in qbdi_trace, and our own library name in .rodata/DT_SONAME)
# and pins a budget on what stage 2 still has to remove.
#
# The important part is the negative control: the same scanner must FAIL on an artifact with a token
# planted into it. A gate that cannot fail is not evidence.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
SO="$ROOT/agent/build/libadh_agent.so"

if [ ! -f "$SO" ]; then
  echo "RESULT:SKIP agent artifact not built ($SO)"
  echo "⏭ v4.50 signature scrub SKIP (run: bash tools/build_agent.sh)"
  exit 0
fi

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const fs = await import('node:fs');
const problems = [];
const notes = [];
const scanner = `${root}/tools/scan_agent_signatures.sh`;
const so = `${root}/agent/build/libadh_agent.so`;

// 1) the shipped artifact must pass the scan
const run = spawnSync('bash', [scanner], { encoding: 'utf8' });
const text = `${run.stdout ?? ''}${run.stderr ?? ''}`;
if (run.status !== 0) {
  problems.push('scan_agent_signatures.sh reports the artifact is not clean');
  for (const line of text.split('\n').filter((l) => /LEAK|OVER|RESULT:FAIL/.test(l))) console.log('   ' + line.trim());
}
notes.push('artifact scan: ' + (/RESULT:PASS/.test(text) ? 'PASS' : 'FAIL'));

// 2) negative control: plant a stage-1 token and demand the scan catches it
const tmp = `${root}/agent/build/libadh_agent.signature-selftest.so`;
const bytes = fs.readFileSync(so);
fs.writeFileSync(tmp, Buffer.concat([bytes, Buffer.from('\nHost ADH Daemon planted\n')]));
const planted = spawnSync('bash', [scanner, tmp], { encoding: 'utf8' });
const plantedText = `${planted.stdout ?? ''}${planted.stderr ?? ''}`;
if (planted.status === 0 || !/RESULT:FAIL/.test(plantedText)) problems.push('the scanner did NOT catch a planted stage-1 token (self-certifying gate)');
else if (!/Host ADH Daemon/.test(plantedText)) problems.push('the scanner failed the planted artifact for the wrong reason');
else notes.push('negative control: a planted "Host ADH Daemon" token is caught (FAIL as expected)');
fs.unlinkSync(tmp);

// 3) source-level check: the fixture defaults must not come back as string literals
for (const rel of ['agent/src/trace/commands.c', 'agent/src/hook/got.c', 'agent/src/hook/java_lsplant.cpp', 'agent/src/bootstrap/agent_main.c']) {
  const src = fs.readFileSync(`${root}/${rel}`, 'utf8');
  for (const line of src.split('\n')) {
    const code = line.split('//')[0];
    for (const lit of ['"libadhdetect.so"', '"adh_trace_target"', '"libadh_agent.so"', '"ADH_RT"', '"lsplant::']) {
      if (code.includes(lit)) problems.push(`${rel}: string literal ${lit} is back in the code`);
    }
  }
}
notes.push('source check: no fixture names / old tags as string literals in the touched files');

// 4) the fetch step must have patched the vendored sources (a re-fetch would otherwise silently
//    reintroduce the names, and the artifact scan would only catch it on the NEXT build)
const vendor = spawnSync('bash', [`${root}/tools/patch_vendor_signatures.sh`, '--check'], { encoding: 'utf8' });
if (vendor.status !== 0) problems.push('the fetched vendor sources still carry the framework names: ' + String(vendor.stdout ?? '').trim());
else notes.push('vendor check: LSPlant sources are patched (or not fetched yet)');

// 5) report the remaining budget so drift is visible in the log
const stage2 = text.split('\n').filter((l) => /budget \d+\)/.test(l)).map((l) => l.trim());
notes.push(`stage 2 budget: ${stage2.length} entries still above zero`);

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.50 agent signature scrub (stage 1 clean + budget + negative control)" 0

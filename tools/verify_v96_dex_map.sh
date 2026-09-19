#!/usr/bin/env bash
# WS-E slice 2 (HOST-ONLY): the rebuilt dex has a map_list that describes the file.
#
# Until this slice the rebuilder appended the new code_items / class_data items past the ORIGINAL
# map_list, so the map no longer described the file: jadx/IDA could still reach the methods through
# class_defs, but anything that trusts the map (ART's verifier, other dex tooling) could not. The
# rebuild now writes every referenced item to the end of the file - code_items 4-aligned, then the
# rewritten class_data items - appends a new map_list naming those two regions, and patches every
# class_def.class_data_off plus every method's code_off to the new copies.
#
# Asserts: the untouched base dex is self-consistent; the rebuild reports mapRebuilt with a passing
# layout check whose counts match what was written; the injected method still round-trips
# byte-identically through the relocated copy; a rebuild without captures is still map-consistent;
# and the layout checker has teeth (a truncated or tampered file must fail it).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
DEX="/tmp/base.dex"
[ -s "$DEX" ] || unzip -p "$APK" classes.dex > "$DEX" 2>/dev/null
[ -s "$DEX" ] || { echo "no base dex (build the app first)"; echo "RESULT:FAIL"; exit 1; }

OUT="$(node - "$ROOT" "$DEX" <<'EOF'
const [root, dexPath] = process.argv.slice(2);
const fs = await import('node:fs');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const { parseDex, extractMethodCode, rebuildStandardDex, verifyDexLayout } = await import(`${base}/daemon/src/dex.ts`);
const problems = [];

const buf = fs.readFileSync(dexPath);
const d = parseDex(buf);
const before = verifyDexLayout(buf);
console.log(`original: mapEntries=${before.mapEntries} classData=${before.classDataItems} codeItems=${before.codeItems} ok=${before.ok}`);
if (!before.ok) problems.push(`the untouched base dex already fails the layout check: ${before.errors.join('; ')}`);

const pick = extractMethodCode(buf, d, '/').find((c) => c.tries > 0 && c.codeItemHex);
if (!pick) problems.push('no try/catch method available to inject');
const rb = rebuildStandardDex(buf, pick ? [{ midx: pick.midx, codeItemHex: pick.codeItemHex }] : []);
console.log(`rebuild: injected=${rb.injected} relocatedCodeItems=${rb.relocatedCodeItems} relocatedClassData=${rb.relocatedClassData} mapRebuilt=${rb.mapRebuilt} mapEntries=${rb.mapEntries} size=${buf.length}->${rb.dex.length}`);
if (!rb.mapRebuilt) problems.push('the rebuild did not report a rebuilt map_list');
if (rb.relocatedCodeItems < 1000) problems.push(`only ${rb.relocatedCodeItems} code_items were relocated`);
if (rb.relocatedClassData < 100) problems.push(`only ${rb.relocatedClassData} class_data items were relocated`);
if (!rb.layout.ok) problems.push(`rebuilt layout check failed: ${rb.layout.errors.join('; ')}`);
if (rb.layout.codeItems !== rb.relocatedCodeItems) problems.push(`map lists ${rb.layout.codeItems} code_items but ${rb.relocatedCodeItems} were written`);
if (rb.layout.classDataItems !== rb.relocatedClassData) problems.push(`map lists ${rb.layout.classDataItems} class_data items but ${rb.relocatedClassData} were written`);
if (rb.mapEntries < before.mapEntries) problems.push(`the new map has fewer entries (${rb.mapEntries}) than the original (${before.mapEntries})`);

if (pick) {
  const same = extractMethodCode(rb.dex, parseDex(rb.dex), '/').find((c) => c.midx === pick.midx);
  const ok = !!same && same.codeItemHex === pick.codeItemHex && same.insnsHex === pick.insnsHex;
  console.log(`roundtrip through the relocated copy: ${ok ? 'MATCH' : 'MISMATCH'} (${((same && same.codeItemHex) || '').length / 2}B)`);
  if (!ok) problems.push('the injected code_item did not round-trip through the relocated copy');
}

// a rebuild without captures still has to produce a map-consistent dex (the relocation is not
// about injection: it is what makes the map describe the file)
const plain = rebuildStandardDex(buf, []);
if (!plain.mapRebuilt || !plain.layout.ok || plain.injected !== 0) problems.push(`a rebuild without captures broke: mapRebuilt=${plain.mapRebuilt} layoutOk=${plain.layout.ok} injected=${plain.injected}`);
console.log(`no-capture rebuild: mapRebuilt=${plain.mapRebuilt} layoutOk=${plain.layout.ok} injected=${plain.injected}`);

// a truncated SOURCE map must not be reported as a successful rebuild (v5.03): the old code broke
// out of the entry loop, kept the entries it had read and still said mapRebuilt:true - the new map
// silently lost most of its types while the layout check stayed green.
let mapTruncRefused = false;
try {
  rebuildStandardDex(buf.subarray(0, buf.readUInt32LE(52) + 4 + 3 * 12), []);
} catch (e) { mapTruncRefused = /map_list is truncated/.test(String(e && e.message)); }
console.log(`truncated source map refused: ${mapTruncRefused}`);
if (!mapTruncRefused) problems.push('a truncated source map_list was not refused');

// the header's own bookkeeping is part of the layout check now
const badSize = Buffer.from(rb.dex);
badSize.writeUInt32LE(12345, 32);
const sizeCheck = verifyDexLayout(badSize);
const mentionsFileSize = sizeCheck.errors.some((e) => /file_size/.test(e));
console.log(`file_size tamper: ok=${sizeCheck.ok} mentions file_size=${mentionsFileSize}`);
if (sizeCheck.ok || !mentionsFileSize) problems.push('the layout check did not report a wrong file_size');

// the layout checker must have teeth
const truncated = verifyDexLayout(rb.dex.subarray(0, rb.dex.length - 16));
if (truncated.ok) problems.push('the layout check accepted a truncated dex');
const tampered = Buffer.from(rb.dex);
const mapOff = tampered.readUInt32LE(52);
tampered.writeUInt32LE(tampered.readUInt32LE(mapOff + 8) + 1, mapOff + 8);
const tamperCheck = verifyDexLayout(tampered);
if (tamperCheck.ok) problems.push('the layout check accepted a tampered map entry');
console.log(`negative controls: truncated=${truncated.ok ? 'ACCEPTED (bad)' : 'refused'} tampered=${tamperCheck.ok ? 'ACCEPTED (bad)' : 'refused'}`);

for (const p of problems) console.log(`PROBLEM: ${p}`);
console.log(problems.length ? 'RESULT:FAIL' : 'RESULT:PASS');
EOF
)"
echo "$OUT"
verify_gate "WS-E 第二片：重建 dex 的 map_list 真的描述文件（relocate + 自检 + 负对照）" 0 && exit 0 || exit 1

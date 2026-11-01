#!/usr/bin/env bash
# v127 — `native_symbols`: one module's dynamic symbol table, paged (HOST-ONLY, no device).
#
# Why this exists: the tool's whole value is an HONEST, BOUNDED answer, and every way it can lie is a
# way this script can catch without a phone:
#   1. Unpaged dump       - a 2 MB stripped library still carries hundreds of dynsym entries. `limit`
#                           must be clamped and `nextOffset` must actually walk to the end.
#   2. Guessed symbols    - a library mapped straight out of an APK has no standalone ELF image. It has
#                           to come back symbolSource=archive-mapped with ZERO symbols, not a guess.
#   3. Silent wrong module- an ambiguous selector must be refused with the candidates, because parsing
#                           the wrong library is a wrong answer that looks like a right one.
#   4. Registry rot       - one apostrophe in the mcp.ts description kills the whole module while
#                           `tsc` stays green (that is why verify_v71 exists); this re-checks the entry.
#   5. A second agent op  - the symbol table must come from the host dump, never from a new agent op
#                           (red line: agent_caps.test.ts parses the real C dispatch and would fail).
#
# The device half is deliberately absent: `moduleSymbols` is the host half of a path already covered on
# device by v84 (native_hook_all resolves exports through the same maps+dump+parse chain). What is new
# and testable here is the paging/filter/archive contract.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

# Step 0: the pure contract has unit tests, gate them FIRST so a failure here is not overwritten by
# the RESULT:PASS of the half below (that bug shipped in v99/v15_dumpall).
#
# The floor is 15 of 16 on purpose: the 16th case parses the REAL sandbox .so and skips itself when
# `sandbox-native/build/libadhdetect.so` is absent (a fresh clone, an ubuntu runner). Same rule the
# repo already applies to backtrace.test.ts, which is 3 pass / 1 skip on CI - a floor higher than the
# no-fixture count is a gate that is green only on the machine that built the fixture.
verify_unit_pass 'module symbol paging/filter/archive contract' module_symbols.test.ts 15 || exit 1

cd "$ROOT"
set +e
OUT="$(node --input-type=module - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const problems = [];
const notes = [];
const fs = await import('node:fs');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const read = (rel) => fs.readFileSync(`${root}/${rel}`, 'utf8');
const say = (ok, label) => { if (!ok) problems.push(label); };

// ---- 1. the tool is registered and shaped ----
const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`).catch((e) => { problems.push('import mcp.ts failed: ' + e.message); return {}; });
const tools = MCP_TOOLS ?? [];
const entry = tools.find((t) => t.name === 'native_symbols');
say(!!entry, 'MCP tool native_symbols is missing from MCP_TOOLS');
if (entry) {
  say(typeof entry.handler === 'function', 'native_symbols handler is not a function');
  const props = entry.inputSchema?.properties ?? {};
  say(entry.inputSchema?.type === 'object', 'native_symbols inputSchema.type is not object');
  for (const key of ['session', 'module', 'kind', 'contains', 'limit', 'offset']) say(!!props[key], `native_symbols does not expose ${key}`);
  say(Array.isArray(props.kind?.enum) && ['any', 'func', 'object'].every((k) => props.kind.enum.includes(k)), 'native_symbols kind enum must be any|func|object');
  say(!(entry.inputSchema?.required ?? []).includes('session'), 'session must stay optional (the daemon picks the online agent, like every other tool)');
  say((entry.inputSchema?.required ?? []).includes('module'), 'module must be required');
  // The description is the caller's only documentation: it has to state the paging contract and the
  // archive honesty rule, or an AI will page blind and read zero symbols as "stripped".
  for (const [re, why] of [[/nextOffset/, 'the description must name nextOffset'], [/total/, 'the description must name total'], [/archive-mapped/, 'the description must say archive-mapped libraries report no symbols'], [/paged|PAGED/, 'the description must say the reply is paged']]) {
    say(re.test(entry.description), `native_symbols description: ${why}`);
  }
  say(String(entry.description).length >= 200, 'native_symbols description is too thin to be useful');
  // An unescaped apostrophe here is the exact failure verify_v71 documents.
  say(!/undefined|\[object Object\]/.test(String(entry.description)), 'native_symbols description contains a value placeholder');
}
say(tools.filter((t) => t.name === 'native_symbols').length === 1, 'native_symbols is registered more than once');
const duplicateNames = tools.map((t) => t.name).filter((n, i, all) => all.indexOf(n) !== i);
say(duplicateNames.length === 0, `duplicate MCP tool names: ${duplicateNames.join(', ')}`);
notes.push(`MCP tools=${tools.length}, native_symbols registered`);

// ---- 2. the resolver lives in the Host Daemon, reusing the existing three primitives ----
const src = read('daemon/src/module_symbols.ts');
say(/export async function moduleSymbols/.test(src), 'module_symbols.ts must export moduleSymbols');
say(/export function pageModuleSymbols/.test(src), 'module_symbols.ts must export pageModuleSymbols (the pure page)');
say(/export function resolveModule/.test(src), 'module_symbols.ts must export resolveModule');
say(/from '\.\/service\.ts'/.test(src), 'module_symbols.ts must import the dump chain from service.ts');
say(/reconstructSo\(/.test(src), 'module_symbols.ts must reconstruct the module instead of reading raw memory');
say(/parseDynSymbols\(/.test(src), 'module_symbols.ts must reuse parseDynSymbols, not re-implement an ELF reader');
say(/modulesFromMaps/.test(src) || /loadModuleTable/.test(src), 'module_symbols.ts must resolve modules through the shared maps path');
say(/fromArchive\(/.test(src), 'module_symbols.ts must classify archive-mapped libraries through fromArchive');
// Paging must be real: nextOffset computed from the FILTERED length, clamped limit.
for (const m of ['total', 'returned', 'nextOffset', 'symbolsInModule']) say(new RegExp(`\\b${m}\\b`).test(src), `moduleSymbols reply lacks ${m}`);
say(/Math\.min\(5000/.test(src), 'the page limit must be clamped (unpaged dumps are the bug this tool prevents)');
// mcp.ts must delegate, never send an op of its own for this.
const mcp = read('daemon/src/mcp.ts');
const mcpImport = /import \{[^}]*\bmoduleSymbols\b[^}]*\} from '\.\/module_symbols\.ts'/.test(mcp);
say(mcpImport, 'mcp.ts must import moduleSymbols from module_symbols.ts');
say(!/sendCmd\([^,]+,\s*'(symtab|dynsym|symbols|native_symbols)'/.test(mcp), 'mcp.ts must not send a symbol op to the agent');
notes.push('host layer: service.reconstructSo + backtrace.parseDynSymbols + service.modulesFromMaps');

// The archive short-circuit is ASSERTED BY RUNNING IT below (the unit file drives it through injected
// deps); this line only makes sure the injection point still exists for that test to hook into.
say(/deps:\s*\{[^}]*loadModuleTable/.test(src), 'moduleSymbols lost its injectable dump chain, so the archive branch can no longer be executed by a test');

// ---- 3. no new agent op (the red line: agent_caps.test.ts parses the real C dispatch) ----
const agent = read('agent/src/bootstrap/agent_main.c');
const caps = /ADH_AGENT_OPS\[\]\s*=\s*\{([\s\S]*?)\};/.exec(agent)?.[1] ?? '';
const opNames = [...caps.matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1]);
for (const name of opNames) say(!!new RegExp(`strcmp\\(op, "${name}"\\)`).test(agent), `ADH_AGENT_OPS lists ${name} but the dispatch does not`);
say(!opNames.includes('native_symbols'), 'native_symbols must NOT become an agent op (symbol parsing is host-side)');
say(!opNames.includes('dynsym'), 'a dynsym agent op must not exist (red line: agent does parse work it should not)');
notes.push(`agent dispatch ops=${opNames.length} (unchanged by this slice, no symbol op)`);

// ---- 4. the behaviour, over a real ELF and a synthetic table ----
const { pageModuleSymbols, resolveModule, fromArchive } = await import(`${base}/daemon/src/module_symbols.ts`);
const { parseDynSymbols } = await import(`${base}/daemon/src/backtrace.ts`);
const { join } = await import('node:path');
const fixture = join(root, 'sandbox-native', 'build', 'libadhdetect.so');
let realRows = 0;
if (fs.existsSync(fixture)) {
  const syms = parseDynSymbols(fs.readFileSync(fixture));
  say(syms.length > 20, `fixture parsed only ${syms.length} dynamic symbols`);
  // full walk: every row exactly once, terminating, total stable
  const first = pageModuleSymbols(syms, { limit: 9 });
  say(first.total === syms.length, `total ${first.total} != parsed ${syms.length}`);
  say(first.limit === 9 && first.returned === 9 && first.nextOffset === 9, 'first page is not [0,9)');
  let cursor = 0, walked = 0, guard = 0;
  const names = [];
  while (cursor != null && guard++ < 2000) {
    const p = pageModuleSymbols(syms, { limit: 9, offset: cursor });
    walked += p.returned; names.push(...p.symbols.map((s) => s.name)); cursor = p.nextOffset;
  }
  say(walked === syms.length, `paging walked ${walked} of ${syms.length} rows`);
  say(new Set(names).size === names.length, 'paging returned a duplicate row');
  say(pageModuleSymbols(syms, { limit: 9, offset: syms.length + 5 }).nextOffset === null, 'a page past the end must not offer a next page');
  // filters partition the table: func + object == everything when nothing is dropped
  const f = pageModuleSymbols(syms, { kind: 'func', limit: 5000 });
  const o = pageModuleSymbols(syms, { kind: 'object', limit: 5000 });
  say(f.total + o.total === first.total, `kind filter lost rows: func ${f.total} + object ${o.total} != ${first.total}`);
  say(f.symbols.every((s) => s.kind === 'func') && o.symbols.every((s) => s.kind === 'object'), 'a kind filter returned the other kind');
  // contains narrows without inventing
  const sample = syms[Math.floor(syms.length / 2)].name.slice(0, 4);
  const c = pageModuleSymbols(syms, { contains: sample, limit: 5000 });
  say(c.total > 0 && c.total <= first.total, `contains="${sample}" returned ${c.total} of ${first.total}`);
  say(c.symbols.every((s) => s.name.includes(sample)), 'contains returned a name without the substring');
  realRows = syms.length;
  notes.push(`real ELF: ${syms.length} dynsym rows, walked=${walked}, func=${f.total}, object=${o.total}, fixture=${fixture.replace(root, '<repo>')}`);
} else {
  notes.push(`fixture absent (${fixture}) - the paging walk over real ELF bytes was NOT run; unit tests still cover the contract`);
}

// synthetic edge cases that a stripped library actually produces
const syn = [
  { name: 'a', addr: 0x10n, size: 4n, kind: 'func' },
  { name: 'b', addr: 0x20n, size: 0n, kind: 'object' },
];
const noSize = pageModuleSymbols(syn, {});
say(noSize.symbols[0].size === '0x4' && noSize.symbols[0].sizeBytes === 4, 'a sized symbol must report size');
say(noSize.symbols[1].size === null, 'a zero st_size must report size:null, not "0x0" as if the symbol had no bytes');
say(pageModuleSymbols(syn, { limit: 1e9 }).limit === 5000, 'limit is not clamped to 5000');
say(pageModuleSymbols(syn, { limit: 0 }).limit === 1, 'limit is not floored at 1');
say(pageModuleSymbols(syn, { offset: -3 }).offset === 0, 'a negative offset is not clamped to 0');
say(pageModuleSymbols(syn, { kind: 'FUNC' }).kind === 'any', 'an unknown kind must fall back to any, not return an empty page');
say(pageModuleSymbols([]).nextOffset === null, 'an empty table must report nextOffset null');

// archive-mapped: the classification is the same predicate the reply uses
for (const [path, want] of [['/data/app/~~x/com.a/base.apk', true], ['/system/framework/framework.jar', true], ['/data/app/~~x/com.a/lib/arm64/libfoo.so', false]]) {
  say(fromArchive(path) === want, `fromArchive(${path}) should be ${want}`);
}
// selector: exact wins, ambiguity is refused
const mods = [{ name: 'libcrypto_a.so', path: '/x/libcrypto_a.so' }, { name: 'libcrypto_b.so', path: '/x/libcrypto_b.so' }];
let refused = false;
try { const r = resolveModule(mods, 'libcrypto'); refused = r === null; } catch (e) { refused = /ambiguous/.test(e.message) && /libcrypto_a\.so/.test(e.message); }
say(refused, 'an ambiguous module selector must be refused with the candidates');
say(resolveModule(mods, 'libcrypto_a.so')?.name === 'libcrypto_a.so', 'an exact module name must resolve');
say(resolveModule(mods, 'libnope.so') === null, 'an unknown module must resolve to null');

console.log(JSON.stringify({ tools: tools.length, realDynsymRows: realRows, pagingWalked: realRows, syntheticCases: 8, agentOps: opNames.length }));
for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
RC=$?
set -e
echo "$OUT"
if [ "$RC" != 0 ]; then exit "$RC"; fi
verify_gate 'native_symbols: host symbol table, paged, archive-honest' 0

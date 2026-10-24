// verify_pick.mjs — "跑什么"由"改了什么"决定，而不是由"稳妥起见全跑一遍"决定.
//
// 为什么存在：tools/verify_all.sh 登记了 136 个脚本（40 host + 96 device），其中 9 个会重装 APK
// 或重启 App；device 脚本每个都要冷启一次沙盒。全量跑是发版/刷机前的动作，不是每次改动的动作。
// 这个工具按改动文件反查最相关的几个脚本，默认只跑 host，默认只**打印**命令（不执行）。
//
// 用法：
//   node tools/verify_pick.mjs                 # 用 git status 的改动，打印候选
//   node tools/verify_pick.mjs --files a,b     # 显式指定改动路径
//   node tools/verify_pick.mjs --device        # 把 device 候选也列出来（仍不执行）
//   node tools/verify_pick.mjs --run           # 执行选中的 host 脚本（需要能跑的 bash）
//   node tools/verify_pick.mjs --all           # 允许选出超过 12 个（默认截断并说明）
//
// 选不中时它会说"没有定向规则"，而不是让你去跑全量。
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const VERIFY_ALL = join(ROOT, 'tools', 'verify_all.sh');

// 改动部位 → 必查的 host 脚本。这些是"改了它，不跑这条就等于没验"的强规则；token 反查只是补充。
const CURATED = [
  { match: /^daemon\//, scripts: ['verify_v71_mcp_registry.sh', 'verify_v87_mcp_operability.sh'], why: 'daemon 的 MCP/REST 面与红线门禁' },
  { match: /^agent\/src\/hook\/native_hooks/, scripts: ['verify_v84_native_hook_all.sh'], why: 'native hook 基建（host 侧形状）' },
  { match: /^agent\/src\/hook\/java_lsplant/, scripts: ['verify_v83_java_trace.sh'], why: 'Java hook 的 trace/digest 装配' },
  { match: /^agent\/src\/runtime\/dlopen_watch/, scripts: ['verify_v71_mcp_registry.sh'], why: 'host 侧工具注册（load/jni_onload 面）' },
  { match: /^tools\/verify_|^tools\/lib\//, scripts: ['verify_v71_mcp_registry.sh'], why: '验收脚本自身改动，先跑一条最便宜的确认没把框架改坏' },
];

// 文档里挂着"偶发/未定因"的脚本。不是不能跑，而是**不要反复重跑**：同一条失败一次仍红，
// 就按未定因记录，别把时间耗在抖动上（这正是 AI 最容易做的浪费）。
const FLAKY = new Set([
  'verify_v72_site_hooks_cross.sh',
  'verify_v22_capture.sh',
  'verify_v08_xref.sh',
  'verify_v01.sh',
]);

// 文件名里这些词太通用，反查只会命中一大片，故不参与打分。（另外还有一层自动过滤：出现在
// 超过 1/4 脚本里的 token 也不能区分，运行时会再剔一次。）
const STOP = new Set(['state', 'index', 'main', 'util', 'utils', 'types', 'type', 'config', 'test', 'tests',
  'mcp', 'service', 'routes', 'route', 'path', 'core', 'run', 'setup', 'json', 'readme', 'map',
  'agent', 'agents', 'package', 'device', 'string', 'strings', 'module', 'modules', 'memory', 'detect',
  'detection', 'mainactivity', 'tools', 'docs', 'build', 'feature', 'status', 'progress', 'license', 'notice']);

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const valueOf = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

function changedFiles() {
  const explicit = valueOf('--files');
  if (explicit) return explicit.split(',').map((s) => s.trim()).filter(Boolean);
  const out = execFileSync('git', ['status', '--porcelain'], { cwd: ROOT, encoding: 'utf8' });
  return out.split('\n').map((line) => line.slice(3).trim()).filter(Boolean);
}

function registeredScripts() {
  const text = readFileSync(VERIFY_ALL, 'utf8');
  const map = new Map();
  for (const m of text.matchAll(/"(verify_[^"]+\.sh):(host|device)"/g)) map.set(m[1], m[2]);
  return map;
}

/** 文件名 → 用于反查的 stem。`native_hooks.cpp` → `native_hook`（脚本里通常写单数）。 */
function stemsFor(file) {
  const base = file.split('/').pop() ?? file;
  const raw = base.replace(/\.[^.]+$/, '');
  // AGENTS / MAP / LICENSE 这类全大写文件名不是代码标识，而且 "AGENTS" 会被去复数成 "agent"，
  // 直接命中所有脚本。
  if (!raw || raw === raw.toUpperCase()) return [];
  let stem = raw.toLowerCase().replace(/_test$/, '');
  // 只在足够长时才去复数：hooks → hook 有意义，map → ma 是灾难。
  if (stem.length >= 8 && stem.endsWith('s')) stem = stem.slice(0, -1);
  const parent = file.split('/').slice(-2, -1)[0] ?? '';
  const out = [];
  if (stem.length >= 5 && !STOP.has(stem)) out.push(stem);
  if (STOP.has(stem) && parent.length >= 5 && !STOP.has(parent)) out.push(parent);
  return out;
}

function main() {
  if (!existsSync(VERIFY_ALL)) {
    console.error(`verify_pick: ${VERIFY_ALL} 不存在，是否在仓库根目录运行？`);
    process.exit(2);
  }
  const files = changedFiles();
  const registered = registeredScripts();
  const texts = new Map();
  for (const [script, mode] of registered) {
    const p = join(ROOT, 'tools', script);
    if (existsSync(p)) texts.set(script, { mode, text: readFileSync(p, 'utf8').toLowerCase() });
  }

  const stemAll = new Set();
  for (const f of files) for (const s of stemsFor(f)) stemAll.add(s);
  // 文档频率过滤：一个 token 如果出现在超过 1/4 的脚本里，它无法区分任何东西（agent / package /
  // memory / device 都是这样被自动剔掉的，不用手工维护）。
  const maxDf = Math.max(3, Math.floor(texts.size * 0.25));
  const stems = [];
  const dropped = [];
  for (const s of stemAll) {
    let df = 0;
    for (const { text } of texts.values()) if (text.includes(s)) df++;
    (df <= maxDf ? stems : dropped).push(s);
  }

  // 每条脚本的得分：命中的 stem 数与次数（单 token 封顶 3）。只有一个常见词命中不算定向。
  const scores = new Map();
  for (const [script, { mode, text }] of texts) {
    let score = 0;
    const hits = [];
    for (const stem of stems) {
      const n = text.split(stem).length - 1;
      if (!n) continue;
      score += Math.min(3, n);
      hits.push(stem);
    }
    if (score >= 3 || hits.length >= 2) scores.set(script, { score, mode, hits });
  }

  const picked = new Map();   // script -> reason
  for (const rule of CURATED) {
    if (!files.some((f) => rule.match.test(f))) continue;
    for (const s of rule.scripts) {
      if (!registered.has(s)) continue;
      picked.set(s, rule.why);
    }
  }
  const ranked = [...scores.entries()]
    .filter(([s]) => registered.has(s))
    .sort((a, b) => b[1].score - a[1].score)
    .slice(0, flag('--all') ? 50 : 12);
  for (const [s, info] of ranked) {
    if (!picked.has(s)) picked.set(s, `正文命中 ${info.hits.join(',')}`);
  }

  const host = [];
  const device = [];
  for (const [s, why] of picked) (registered.get(s) === 'device' ? device : host).push({ script: s, why });

  console.log(`改动文件 ${files.length} 个:`);
  for (const f of files.slice(0, 20)) console.log(`  ${f}`);
  if (files.length > 20) console.log(`  … 其余 ${files.length - 20} 个`);
  console.log(`反查 token: ${stems.length ? stems.slice(0, 10).join(', ') + (stems.length > 10 ? ` … 共 ${stems.length} 个` : '') : '(无)'}${dropped.length ? `（自动剔掉 ${dropped.length} 个过于通用的）` : ''}`);

  console.log(`\nhost 候选（可以直接跑）: ${host.length}`);
  for (const h of host) console.log(`  ${h.script}${FLAKY.has(h.script) ? '  ⚠ 已知抖动（最多复跑一次）' : ''}  ← ${h.why}`);
  console.log(`\ndevice 候选（需要真机；每个都会重启沙盒）: ${device.length}`);
  for (const d of device) console.log(`  ${d.script}${FLAKY.has(d.script) ? '  ⚠ 已知抖动（最多复跑一次）' : ''}  ← ${d.why}`);

  if (!host.length && !device.length) {
    console.log('\n没有定向规则命中。最便宜的确认仍然是（几秒级）:');
    console.log('  cd daemon && npm run typecheck && npm test');
    console.log('别为了一次纯文档/纯样式改动去跑 verify_all.sh。');
  }

  if (!flag('--device') && device.length) {
    console.log('\n--device 未给，device 候选不执行。真机就绪时再跑命中的那几条，不要跑全量。');
  }
  if (!flag('--run')) {
    if (host.length) console.log('\n--run 才会执行上面的 host 候选；默认只打印。');
    return;
  }

  const runList = host.map((h) => h.script);
  if (!runList.length) return;
  let failed = 0;
  for (const script of runList) {
    console.log(`\n=== ${script} ===`);
    const p = spawnSync('bash', [join('tools', script)], { cwd: ROOT, stdio: 'inherit' });
    if (p.error) { console.error(`无法启动 bash: ${p.error.message}`); process.exit(2); }
    if (p.status !== 0) failed++;
  }
  console.log(`\n${runList.length - failed}/${runList.length} 通过`);
  process.exit(failed ? 1 : 0);
}

main();

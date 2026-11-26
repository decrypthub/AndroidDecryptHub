<script lang="ts">
// 模块作用域（不是 setup）：切走再切回来时组件会重新挂载，上一次的 maps 快照必须还留着，
// 否则「新增」对比永远从零开始。用容器对象而不是 let，是为了能从 setup 里改它。
export const mapBaseline: { current: { session: string; rows: Map<string, string> } | null } = { current: null };
</script>

<script setup lang="ts">
// 内存映射：/proc/self/maps 的可操作视图。
//
// 设计取舍（2026-11-27 用户明确批评后重做）：
//  1. 统计不是装饰：一行 chips 里每个数字都可点，点哪个就是筛哪个（全部/可执行/匿名/匿名可执行/新增）。
//  2. 左右分栏：左边表格单行紧凑，右边固定详情——点行立刻看到地址、权限、偏移和操作，不用往下滚。
//  3. 「新增」是核心能力：每次刷新自动和上一次加载比，新出现的段标 NEW，
//     触发一次目标行为再刷新就能看到新映射（解密载荷、VMP 解释器通常就是这么冒出来的）。
//  4. 不做行内盲转储：转储在右侧，事前明确写出「将转储多少字节」，产物落「脱壳 → 记录」。
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import { memoryMaps, memoryRead, memoryDump, dumpDownloadUrl } from '../api';
import type { MapsRegion, MapsStats } from '../api';
import { fmtSize } from '../capview';

const props = defineProps<{ session: string }>();

const regions = ref<MapsRegion[]>([]);
const stats = ref<MapsStats | null>(null);
const truncated = ref(false);
const loading = ref(false);
const loadMs = ref(0);
const error = ref('');

// ---- 与上一次加载的对比（模块作用域：切走再切回来仍保留基线，才能对比「刚才那一刻」） ----
interface MapsDiff { added: number; gone: number }
const newStarts = ref(new Set<string>());
const diff = ref<MapsDiff | null>(null);

// ---- 视图筛选 ----
type Mode = 'all' | 'exec' | 'anon' | 'anonExec' | 'new';
const mode = ref<Mode>('all');
const q = ref('');
const minSize = ref(0);
const sort = ref<'addr' | 'size'>('addr');
const page = ref(1);
const pageSize = ref(100);

function isAnon(path: string): boolean { return !path || path.startsWith('['); }
const isExec = (perms: string) => perms.length > 2 && perms[2] === 'x';
const isWritable = (perms: string) => perms.length > 1 && perms[1] === 'w';
const isAppModule = (path: string) => /^\/data\/(app|user)/.test(path);

const queryText = computed(() => q.value.trim().toLowerCase());
const queryAddr = computed<bigint | null>(() => {
  const raw = q.value.trim();
  const prefixed = /^0x/i.test(raw);
  const t = raw.replace(/^0x/i, '');
  if (!/^[0-9a-f]{1,16}$/i.test(t)) return null;
  // 裸 hex 要够长才当地址：4 位的 "dead"、"cafe" 更像模块名/路径片段
  if (!prefixed && t.length < 8) return null;
  try { return BigInt(`0x${t}`); } catch { return null; }
});

const counts = computed(() => ({
  all: regions.value.length,
  exec: stats.value?.executable ?? 0,
  anon: stats.value?.anonymous ?? 0,
  anonExec: stats.value?.anonymousExecutable ?? 0,
  new: diff.value?.added ?? 0,
}));

const filtered = computed<MapsRegion[]>(() => {
  const text = queryText.value;
  const addr = queryAddr.value;
  const m = mode.value;
  const min = minSize.value;
  const rows = regions.value.filter((r) => {
    if (m === 'exec' && !isExec(r.perms)) return false;
    if (m === 'anon' && !isAnon(r.path)) return false;
    if (m === 'anonExec' && (!isExec(r.perms) || !isAnon(r.path))) return false;
    if (m === 'new' && !newStarts.value.has(r.start)) return false;
    if (min > 0 && r.size < min) return false;
    if (addr !== null) return containsAddr(r, addr);
    if (text && !r.path.toLowerCase().includes(text)) return false;
    return true;
  });
  return sort.value === 'size' ? [...rows].sort((a, b) => b.size - a.size) : rows;
});

function containsAddr(r: MapsRegion, addr: bigint): boolean {
  try { return addr >= BigInt(r.start) && addr < BigInt(r.end); } catch { return false; }
}

const pageCount = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize.value)));
const pageRows = computed(() => {
  const p = Math.min(page.value, pageCount.value);
  const from = (p - 1) * pageSize.value;
  return filtered.value.slice(from, from + pageSize.value);
});
watch([q, mode, minSize, sort, pageSize], () => { page.value = 1; });
watch(pageCount, (n) => { if (page.value > n) page.value = n; });

// ---- 选中与操作 ----
const selected = ref<MapsRegion | null>(null);
const addrInput = ref('');
const sizeInput = ref('');
const busy = ref(false);
const actionStatus = ref('');
const noteKind = ref<'info' | 'ok'>('info');
const hexdump = ref('');
const previewBase = ref<bigint | null>(null);
const previewBytes = ref(0);
const lastDump = ref<{ sha: string; size: number; complete: boolean; dedup: boolean; recorded: boolean; name: string } | null>(null);
const detailEl = ref<HTMLElement | null>(null);

const DEFAULT_SPAN = 64 * 1024;
const PREVIEW_MAX = 16 * 1024;
const DUMP_CAP = 512 * 1024 * 1024;

const wholeTooBig = computed(() => !!selected.value && selected.value.size > DUMP_CAP);
const plannedSpan = computed(() => parseSpan(sizeInput.value));

function note(text: string, kind: 'info' | 'ok' = 'info') {
  actionStatus.value = text;
  noteKind.value = kind;
}

function selectRegion(r: MapsRegion) {
  selected.value = r;
  addrInput.value = r.start;
  // 默认取该段头部 1MB 以内：dalvik 单段 2GB，默认填整段一按就撞上限
  sizeInput.value = String(Math.min(r.size || 4096, 1024 * 1024));
  hexdump.value = '';
  previewBase.value = null;
  previewBytes.value = 0;
  lastDump.value = null;
  actionStatus.value = '';
  void nextTick(() => {
    if (detailEl.value && detailEl.value.getBoundingClientRect().top > window.innerHeight - 80) {
      detailEl.value.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  });
}

function useWhole() {
  if (!selected.value) return;
  if (wholeTooBig.value) {
    note(`该区域 ${fmtSize(selected.value.size)}，超过 ${fmtSize(DUMP_CAP)} 的转储上限。`);
    return;
  }
  sizeInput.value = String(selected.value.size);
  actionStatus.value = '';
}

function parseAddr(text: string): bigint | null {
  const t = String(text ?? '').trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]{1,16}$/i.test(t)) return null;
  try { return BigInt(`0x${t}`); } catch { return null; }
}

function parseSpan(text: string): number | null {
  const m = String(text ?? '').trim().toLowerCase().match(/^(0x[0-9a-f]+|[0-9]+)([km])?$/);
  if (!m) return null;
  let n = m[1].startsWith('0x') ? parseInt(m[1], 16) : Number(m[1]);
  if (m[2] === 'k') n *= 1024;
  if (m[2] === 'm') n *= 1024 * 1024;
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

const hexAddr = (v: bigint) => `0x${v.toString(16)}`;

function permClass(r: MapsRegion): string {
  if (isExec(r.perms) && isWritable(r.perms)) return 'perm-hot';
  if (isAnon(r.path) && isExec(r.perms)) return 'perm-anon-exec';
  return '';
}

// ---- 读取 / 转储 ----
async function preview(base?: bigint) {
  if (busy.value) { note('正在处理上一个请求，请稍候…'); return; }
  const from = base ?? parseAddr(addrInput.value);
  const span = parseSpan(sizeInput.value);
  if (from === null) { note('地址无效：需要十六进制，如 0x7f3a2c0000。'); return; }
  if (span === null) { note('长度无效：填字节数，或 64K / 1M。'); return; }
  const want = Math.min(span, PREVIEW_MAX);
  busy.value = true;
  hexdump.value = '';
  if (span > want) note(`预览一次最多 ${fmtSize(PREVIEW_MAX)}；要更多请转储。`);
  try {
    const r = await memoryRead(props.session, hexAddr(from), want);
    if (r.ok !== true) { note(r.error || '读取失败。'); return; }
    const bytes = base64ToBytes(r.b64 ?? '');
    if (!bytes.length) { note(r.error || '这一段读不到内容。'); return; }
    hexdump.value = hexdumpOf(bytes, from);
    previewBase.value = from;
    previewBytes.value = bytes.length;
    if (bytes.length < want) note(`只读到 ${fmtSize(bytes.length)}（请求 ${fmtSize(want)}），后面可能已不可读。`);
    else if (actionStatus.value.startsWith('预览一次最多')) note(actionStatus.value);
    else actionStatus.value = '';
  } catch (e) {
    note(e instanceof Error ? `读取失败：${e.message}` : '读取失败。');
  } finally { busy.value = false; }
}

function previewPage(dir: -1 | 1) {
  if (previewBase.value === null) return;
  const step = BigInt(Math.max(1, previewBytes.value || PREVIEW_MAX));
  const next = previewBase.value + (dir > 0 ? step : -step);
  if (next < 0n) return;
  addrInput.value = hexAddr(next);
  void preview(next);
}

async function dumpRange() {
  if (busy.value) { note('正在处理上一个请求，请稍候…'); return; }
  const addr = parseAddr(addrInput.value);
  const span = parseSpan(sizeInput.value);
  if (addr === null) { note('地址无效：需要十六进制，如 0x7f3a2c0000。'); return; }
  if (span === null) { note('长度无效：填字节数，或 64K / 1M。'); return; }
  if (span > DUMP_CAP) { note(`${fmtSize(span)} 超过 ${fmtSize(DUMP_CAP)} 的转储上限，请缩小长度。`); return; }
  busy.value = true;
  lastDump.value = null;
  note(`正在转储 ${fmtSize(span)}…`);
  try {
    const r = await memoryDump(props.session, hexAddr(addr), span);
    if (r.error || !r.sha256) { note(`转储失败：${r.error || '没有返回产物'}。`); return; }
    lastDump.value = {
      sha: r.sha256, size: r.size ?? 0, complete: r.complete !== false, dedup: r.dedup === true,
      // recorded=false：内容与已有产物相同，daemon 没有新增记录行——不能提示「已写入记录」
      recorded: r.recorded !== false,
      name: `${r.kind || 'bin'}-${hexAddr(addr).slice(2, 10)}-${r.sha256.slice(0, 8)}.${r.kind || 'bin'}`,
    };
    actionStatus.value = '';
    noteKind.value = 'ok';
    window.dispatchEvent(new CustomEvent('adh:dump-new', { detail: { ok: true, dump: r } }));
  } catch (e) {
    note(e instanceof Error ? `转储失败：${e.message}` : '转储失败。');
  } finally { busy.value = false; }
}

function base64ToBytes(b64: string): Uint8Array {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return new Uint8Array(0); }
}

function hexdumpOf(bytes: Uint8Array, base: bigint): string {
  const lines: string[] = [];
  const per = 16;
  for (let i = 0; i < bytes.length; i += per) {
    const addr = (base + BigInt(i)).toString(16);
    let hex = '';
    let ascii = '';
    for (let j = 0; j < per; j++) {
      if (i + j < bytes.length) {
        const b = bytes[i + j];
        hex += `${b.toString(16).padStart(2, '0')} `;
        ascii += b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
      } else {
        hex += '   ';
        ascii += ' ';
      }
      if (j === 7) hex += ' ';
    }
    lines.push(`${addr}  ${hex}|${ascii}|`);
  }
  return lines.join('\n');
}

/** maps 的偏移是定宽 hex（00000000），显示成 0x0 就够。 */
function compactOffset(offset: string): string {
  const m = String(offset ?? '').match(/^0x0*([0-9a-f]+)$/i);
  return m ? `0x${m[1]}` : offset;
}

/** 虚拟大小累加会到 G 级，用 M 显示读起来没有尺度感。 */
function fmtBig(n: number): string {
  return n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)}G` : fmtSize(n);
}

// ---- 加载（含与上次的对比） ----
function regionKey(r: MapsRegion): string { return `${r.size}:${r.perms}:${r.path}`; }

// 请求代次：会话变化后旧请求可能晚到，不能让它把新进程的地址空间覆盖回旧的。
let loadToken = 0;

function clearRows() {
  regions.value = [];
  stats.value = null;
  truncated.value = false;
  diff.value = null;
  newStarts.value = new Set();
}

async function load() {
  const token = ++loadToken;
  if (!props.session) {
    clearRows();
    error.value = '没有在线会话：先让目标应用注入并连上 agent。';
    return;
  }
  loading.value = true;
  error.value = '';
  const t0 = performance.now();
  try {
    const r = await memoryMaps(props.session);
    if (token !== loadToken) return;
    loadMs.value = performance.now() - t0;
    if (r.ok === false) { clearRows(); error.value = r.error || '内存映射读取失败。'; return; }
    const rows = r.regions ?? [];
    regions.value = rows;
    stats.value = r.stats ?? null;
    truncated.value = r.truncated === true;

    const now = new Map<string, string>();
    for (const row of rows) now.set(row.start, regionKey(row));
    const base = mapBaseline.current;
    if (base && base.session === props.session) {
      const added = [...now.keys()].filter((k) => !base.rows.has(k));
      const gone = [...base.rows.keys()].filter((k) => !now.has(k)).length;
      newStarts.value = new Set(added);
      diff.value = { added: added.length, gone };
    } else {
      newStarts.value = new Set();
      diff.value = null;
    }
    mapBaseline.current = { session: props.session, rows: now };

    if (selected.value && !rows.some((x) => x.start === selected.value!.start && x.path === selected.value!.path)) {
      selected.value = null;
      hexdump.value = '';
    }
  } catch (e) {
    if (token !== loadToken) return;
    // 读失败就把旧进程的地址空间清掉：留着它会让用户对着上一个进程的段继续转储。
    clearRows();
    error.value = e instanceof Error ? `内存映射读取失败：${e.message}` : '内存映射读取失败。';
  } finally {
    if (token === loadToken) loading.value = false;
  }
}

onMounted(() => { void load(); });
watch(() => props.session, () => {
  mapBaseline.current = null;
  clearRows();
  selected.value = null;
  hexdump.value = '';
  lastDump.value = null;
  actionStatus.value = '';
  void load();
});

const loadLabel = computed(() => (loading.value ? '读取中' : loadMs.value ? `${Math.round(loadMs.value)}ms` : '—'));
const hasBaseline = computed(() => diff.value !== null);
const EMPTY_HINT = computed(() => {
  if (!error.value && !regions.value.length) return 'agent 返回的 maps 是空的（进程可能刚开始启动，或读取被拒）。';
  if (queryAddr.value !== null) return '没有映射包含这个地址。';
  if (mode.value === 'new') return '和上一次相比没有新增的映射。';
  return '没有匹配的区域。';
});
</script>

<template>
  <div class="mempane">
    <div class="mem-toolbar">
      <input v-model="q" class="mem-input mono" type="search" aria-label="筛选路径或定位地址"
        placeholder="路径关键字；输入 0x… 地址定位所在段">
      <select v-model="sort" class="mem-select" aria-label="排序">
        <option value="addr">按地址排</option>
        <option value="size">按大小排</option>
      </select>
      <select v-model.number="minSize" class="mem-select" aria-label="最小大小">
        <option :value="0">不限大小</option>
        <option :value="4096">≥ 4K</option>
        <option :value="65536">≥ 64K</option>
        <option :value="1048576">≥ 1M</option>
        <option :value="16777216">≥ 16M</option>
      </select>
      <button type="button" class="mem-refresh" :disabled="loading" @click="load()">{{ loading ? '读取中…' : '刷新' }}</button>
    </div>

    <div class="mem-chips" role="group" aria-label="按类别筛选">
      <button type="button" :aria-pressed="mode === 'all'" @click="mode = 'all'">全部 <b>{{ counts.all }}</b></button>
      <button type="button" :aria-pressed="mode === 'exec'" @click="mode = 'exec'">可执行 <b>{{ counts.exec }}</b></button>
      <button type="button" :aria-pressed="mode === 'anon'" @click="mode = 'anon'">匿名 <b>{{ counts.anon }}</b></button>
      <button type="button" class="hot" :aria-pressed="mode === 'anonExec'" @click="mode = 'anonExec'"
        title="没有文件背衬且可执行：解压后的载荷、VMP 解释器通常在这里">
        匿名可执行 <b>{{ counts.anonExec }}</b>
      </button>
      <button type="button" :class="{ fresh: counts.new > 0 }" :aria-pressed="mode === 'new'"
        :title="hasBaseline ? `与上次加载相比新增 ${diff?.added ?? 0} 段、消失 ${diff?.gone ?? 0} 段` : '还没有基线：点一次刷新后再刷新一次即可对比'"
        :disabled="!hasBaseline" @click="mode = 'new'">
        {{ hasBaseline ? '新增' : '对比' }} <b>{{ hasBaseline ? counts.new : '—' }}</b>
      </button>
      <span class="mem-meta">{{ fmtBig(stats?.mappedBytes ?? 0) }}<template v-if="stats"> · 可写可执行 {{ stats.writableExecutable }}</template> · 读取 {{ loadLabel }}<template v-if="truncated"> · 应答被截断</template></span>
    </div>

    <div v-if="error" class="dump-callout">{{ error }}</div>

    <div class="mem-main">
      <div class="mem-left">
        <div class="mem-scroll">
          <table class="mem-table">
            <thead>
              <tr>
                <th class="w-new"></th>
                <th class="w-range">范围</th>
                <th class="w-size">大小</th>
                <th class="w-perm">权限</th>
                <th>映射 / 路径</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in pageRows" :key="`${r.start}-${r.path}`"
                :class="{ selected: selected && selected.start === r.start && selected.path === r.path }"
                @click="selectRegion(r)">
                <td class="w-new"><span v-if="newStarts.has(r.start)" class="mem-new" title="与上次加载相比是新出现的">NEW</span></td>
                <td class="mono mem-range">{{ r.start }}</td>
                <td class="mono">{{ fmtSize(r.size) }}</td>
                <td class="mono" :class="permClass(r)">{{ r.perms }}</td>
                <td class="mem-path" :title="r.path || '(匿名映射)'">{{ r.path || '(匿名映射)' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="!pageRows.length && !loading" class="empty">{{ EMPTY_HINT }}</div>

        <div class="mem-pager">
          <span class="muted">共 {{ filtered.length }} 段<template v-if="filtered.length !== regions.length"> / {{ regions.length }}</template></span>
          <span class="mem-pager-nav">
            <button type="button" :disabled="page <= 1" aria-label="第一页" @click="page = 1">«</button>
            <button type="button" :disabled="page <= 1" aria-label="上一页" @click="page--">‹</button>
            <span class="mono">{{ page }} / {{ pageCount }}</span>
            <button type="button" :disabled="page >= pageCount" aria-label="下一页" @click="page++">›</button>
            <button type="button" :disabled="page >= pageCount" aria-label="最后一页" @click="page = pageCount">»</button>
          </span>
          <select v-model.number="pageSize" class="mem-select" aria-label="每页条数">
            <option :value="50">50 行</option>
            <option :value="100">100 行</option>
            <option :value="200">200 行</option>
          </select>
        </div>
      </div>

      <aside ref="detailEl" class="mem-right" aria-label="选中区域与转储">
        <template v-if="selected">
          <div class="mem-right-head">
            <span class="mem-perm mono" :class="permClass(selected)">{{ selected.perms }}</span>
            <span class="mono mem-addr">{{ selected.start }}<template v-if="selected.path"> · {{ compactOffset(selected.offset) }}</template></span>
          </div>
          <div class="mem-kv"><span>大小</span><b>{{ fmtSize(selected.size) }}</b></div>
          <div class="mem-kv"><span>结束</span><b class="mono">{{ selected.end }}</b></div>
          <div class="mem-kv path"><span>路径</span><b>{{ selected.path || '(匿名映射)' }}</b></div>

          <div class="mem-fields">
            <label>地址<input v-model="addrInput" class="mono" @keyup.enter="preview()"></label>
            <label>长度<input v-model="sizeInput" class="mono" @keyup.enter="preview()"></label>
          </div>
          <div class="mem-btns">
            <button type="button" :disabled="busy || !session" @click="preview()">预览</button>
            <button type="button" class="primary" :disabled="busy || !session" @click="dumpRange()">
              转储{{ plannedSpan ? ` ${fmtSize(plannedSpan)}` : '' }}
            </button>
            <button type="button" :disabled="busy" :title="wholeTooBig ? '超过转储上限' : '长度设为整段'" @click="useWhole()">整段</button>
          </div>
          <p class="mem-hint">
            产物写入「脱壳 → 记录」，可下载；预览一次最多 {{ fmtSize(PREVIEW_MAX) }}。
            <template v-if="wholeTooBig">该段 {{ fmtSize(selected.size) }}，超过 {{ fmtSize(DUMP_CAP) }} 上限，请缩小长度。</template>
          </p>
        </template>
        <template v-else>
          <div class="mem-right-empty">
            <b>没有选中区域</b>
            <span>点左边任意一行，这里显示地址、权限、偏移，并可以预览或转储。</span>
            <span class="muted">也可以直接在上面输入 0x 地址定位。</span>
          </div>
        </template>

        <div v-if="noteKind === 'ok' && lastDump" class="mem-note ok">
          已转储 {{ fmtSize(lastDump.size) }}<template v-if="!lastDump.complete">（读取不完整）</template>
          · <a :href="dumpDownloadUrl(lastDump.sha, lastDump.name)" class="dl-link">下载</a>
          <template v-if="lastDump.recorded">· 已写入「脱壳」记录</template>
          <template v-else>· 内容与已有产物相同，未新增记录</template>
        </div>
        <div v-else-if="actionStatus" class="mem-note">{{ actionStatus }}</div>
      </aside>
    </div>

    <section v-if="hexdump" class="mem-hex-wrap">
      <div class="mem-hex-head">
        <b>内存预览</b>
        <span class="muted mono">{{ previewBase !== null ? hexAddr(previewBase) : '' }} · {{ fmtSize(previewBytes) }}</span>
        <span class="mem-hex-nav">
          <button type="button" :disabled="busy" @click="previewPage(-1)">‹ 上一块</button>
          <button type="button" :disabled="busy" @click="previewPage(1)">下一块 ›</button>
          <button type="button" @click="hexdump = ''">收起</button>
        </span>
      </div>
      <pre class="mem-hex">{{ hexdump }}</pre>
    </section>
  </div>
</template>

<style scoped>
.mempane { display: flex; flex-direction: column; gap: 10px; }
.mem-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.mem-input { flex: 1 1 300px; min-width: 200px; min-height: 32px; padding: 5px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--ink); font-size: 12px; }
.mem-input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); }
.mem-select { min-height: 32px; padding: 4px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--ink-2); font-size: 12px; }
.mem-refresh { min-height: 32px; padding: 0 12px; border: 1px solid var(--line); border-radius: 4px; background: transparent; color: var(--ink-2); font-size: 12px; cursor: pointer; }
.mem-refresh:hover:not(:disabled) { color: var(--ink); background: rgba(255, 255, 255, .04); border-color: var(--muted); }
.mem-refresh:disabled { opacity: .45; cursor: default; }

/* chips：既是统计也是筛选——数字可点，不再有纯装饰的统计卡 */
.mem-chips { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
.mem-chips button { display: inline-flex; align-items: center; gap: 6px; min-height: 28px; padding: 0 10px; border: 1px solid var(--line-soft); border-radius: 5px; background: var(--chrome); color: var(--muted); font-size: 11.5px; cursor: pointer; }
.mem-chips button:hover:not(:disabled) { color: var(--ink); border-color: var(--line); }
.mem-chips button[aria-pressed="true"] { color: var(--blue); border-color: var(--blue); background: var(--surface-2); }
.mem-chips button:disabled { opacity: .45; cursor: default; }
.mem-chips button b { font-weight: 600; font-variant-numeric: tabular-nums; }
.mem-chips button.hot b { color: var(--amber); }
.mem-chips button.fresh { border-color: var(--green); color: var(--green); }
.mem-chips button.fresh b { color: var(--green); }
.mem-meta { margin-left: auto; color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; white-space: nowrap; }

.mem-main { display: flex; gap: 12px; align-items: flex-start; min-width: 0; }
.mem-left { flex: 1 1 auto; min-width: 0; display: flex; flex-direction: column; gap: 8px; }
.mem-scroll { max-height: 46vh; overflow: auto; border: 1px solid var(--line-soft); border-radius: 8px; background: var(--surface); }
.mem-table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 12px; }
.mem-table th, .mem-table td { text-align: left; padding: 3px 8px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
.mem-table th { position: sticky; top: 0; z-index: 1; background: var(--surface); color: var(--muted); font-size: 11px; font-weight: 600; }
.mem-table tbody tr { cursor: pointer; }
.mem-table tbody tr:hover { background: var(--surface-2); }
.mem-table tbody tr.selected { background: var(--surface-2); box-shadow: inset 2px 0 0 var(--blue); }
.mem-table .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; font-variant-numeric: tabular-nums; }
.mem-range { white-space: nowrap; }
.mem-path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.w-new { width: 42px; padding-right: 0 !important; }
.w-range { width: 128px; }
.w-size { width: 62px; }
.w-perm { width: 54px; }
.mem-new { display: inline-block; padding: 0 4px; border-radius: 3px; background: rgba(64, 170, 110, .14); color: var(--green); font-size: 9px; font-weight: 700; letter-spacing: .02em; }

.mem-pager { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; font-size: 12px; }
.mem-pager-nav { display: inline-flex; align-items: center; gap: 6px; margin-left: auto; }
.mem-pager-nav button { min-width: 26px; min-height: 26px; padding: 0 6px; border: 1px solid var(--line-soft); border-radius: 4px; background: var(--chrome); color: var(--muted); font-size: 12px; cursor: pointer; }
.mem-pager-nav button:hover:not(:disabled) { color: var(--ink); border-color: var(--line); }
.mem-pager-nav button:disabled { opacity: .35; cursor: default; }
.mem-pager-nav span { color: var(--muted); font-size: 11px; }

/* 右栏固定：点行不用滚就能看到详情与操作 */
.mem-right { flex: 0 0 332px; display: flex; flex-direction: column; gap: 8px; padding: 11px 12px; border: 1px solid var(--line-soft); border-radius: 8px; background: var(--surface); position: sticky; top: 0; }
.mem-right-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.mem-perm { padding: 1px 6px; border: 1px solid var(--line); border-radius: 3px; color: var(--ink-2); font-size: 11px; }
.mem-addr { color: var(--ink); font-size: 11.5px; overflow-wrap: anywhere; }
.mem-kv { display: grid; grid-template-columns: 40px minmax(0, 1fr); gap: 8px; font-size: 11.5px; }
.mem-kv span { color: var(--muted); }
.mem-kv b { color: var(--ink-2); font-weight: 500; overflow-wrap: anywhere; }
.mem-kv.path { align-items: start; }
.mem-kv.path b { font-size: 11px; color: var(--ink-2); }
.mem-fields { display: flex; gap: 8px; }
.mem-fields label { flex: 1 1 0; display: flex; flex-direction: column; gap: 3px; min-width: 0; color: var(--muted); font-size: 11px; }
.mem-fields input { width: 100%; min-height: 28px; padding: 3px 7px; border: 1px solid var(--line); border-radius: 5px; background: var(--bg); color: var(--ink); font-size: 11.5px; }
.mem-fields input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); }
.mem-btns { display: flex; gap: 6px; flex-wrap: wrap; }
.mem-btns button { min-height: 30px; padding: 0 10px; border: 1px solid var(--line); border-radius: 4px; background: transparent; color: var(--ink-2); font-size: 12px; cursor: pointer; }
.mem-btns button:hover:not(:disabled) { color: var(--ink); background: rgba(255, 255, 255, .04); border-color: var(--muted); }
.mem-btns button.primary { color: var(--bg); background: var(--blue); border-color: var(--blue); font-weight: 600; }
.mem-btns button.primary:hover:not(:disabled) { background: var(--ink-2); }
.mem-btns button:disabled { opacity: .45; cursor: default; }
.mem-hint { margin: 0; color: var(--muted); font-size: 10.5px; line-height: 1.55; }
.mem-right-empty { display: flex; flex-direction: column; gap: 5px; padding: 6px 2px; }
.mem-right-empty b { color: var(--ink-2); font-size: 12.5px; }
.mem-right-empty span { color: var(--muted); font-size: 11.5px; line-height: 1.6; }
.mem-note { font-size: 11px; line-height: 1.55; color: var(--muted); }
.mem-note.ok { color: var(--green); }

.mem-hex-wrap { display: flex; flex-direction: column; gap: 6px; }
.mem-hex-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 11.5px; color: var(--ink-2); }
.mem-hex-head b { font-size: 12px; }
.mem-hex-nav { margin-left: auto; display: inline-flex; gap: 6px; }
.mem-hex-nav button { min-height: 26px; padding: 0 9px; border: 1px solid var(--line-soft); border-radius: 4px; background: var(--chrome); color: var(--muted); font-size: 11.5px; cursor: pointer; }
.mem-hex-nav button:hover:not(:disabled) { color: var(--ink); border-color: var(--line); }
.mem-hex { max-height: 240px; overflow: auto; margin: 0; padding: 9px 11px; border: 1px solid var(--line-soft); border-radius: 6px; background: var(--bg); color: var(--ink-2); white-space: pre; font: 11px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace; }

.perm-hot { color: var(--amber); }
.perm-anon-exec { color: var(--blue); }

@media (max-width: 1240px) {
  .mem-right { flex-basis: 300px; }
  .w-range { width: 140px; }
}
@media (max-width: 1060px) {
  .mem-main { flex-direction: column; }
  .mem-right { position: static; flex-basis: auto; width: 100%; }
  .mem-scroll { max-height: 40vh; }
  .mem-meta { margin-left: 0; }
}
</style>

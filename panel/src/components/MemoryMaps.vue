<script setup lang="ts">
// 内存映射：/proc/self/maps 的面板视图 + 任意范围的读取与转储。
//
// 数据来自 /api/memory/maps（服务端已规范化并给出统计），一次取全量，筛选/排序/分页都在本地，
// 所以每次输入都是即时的。读取与转储分别对应 memory_read / memory_dump 的同一实现，
// 面板和模型拿到的是同一段字节、同一份产物。
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

// ---- 筛选 / 排序 ----
type Mode = 'all' | 'exec' | 'anonExec' | 'anon' | 'file' | 'rwx';
const MODES: Array<{ key: Mode; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'exec', label: '可执行' },
  { key: 'anonExec', label: '匿名可执行' },
  { key: 'anon', label: '匿名' },
  { key: 'file', label: '文件映射' },
  { key: 'rwx', label: '可写可执行' },
];
const q = ref('');
const mode = ref<Mode>('all');
const minSize = ref(0);
const sort = ref<'addr' | 'size'>('addr');
const page = ref(1);
const pageSize = ref(100);

function isAnon(path: string): boolean { return !path || path.startsWith('['); }
const isExec = (perms: string) => perms.length > 2 && perms[2] === 'x';
const isWritable = (perms: string) => perms.length > 1 && perms[1] === 'w';

const queryText = computed(() => q.value.trim().toLowerCase());
const queryAddr = computed<bigint | null>(() => {
  const t = q.value.trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]{4,16}$/i.test(t)) return null;
  try { return BigInt(`0x${t}`); } catch { return null; }
});

const filtered = computed<MapsRegion[]>(() => {
  const text = queryText.value;
  const addr = queryAddr.value;
  const m = mode.value;
  const min = minSize.value;
  const rows = regions.value.filter((r) => {
    if (m === 'exec' && !isExec(r.perms)) return false;
    if (m === 'anonExec' && (!isExec(r.perms) || !isAnon(r.path))) return false;
    if (m === 'anon' && !isAnon(r.path)) return false;
    if (m === 'file' && isAnon(r.path)) return false;
    if (m === 'rwx' && (!isExec(r.perms) || !isWritable(r.perms))) return false;
    if (min > 0 && r.size < min) return false;
    // 十六进制输入当地址定位（含该地址的那一段）；否则按路径关键字
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

// ---- 选中区域与地址范围 ----
const selected = ref<MapsRegion | null>(null);
const addrInput = ref('');
const sizeInput = ref('');
const busy = ref(false);
const actionStatus = ref('');
const previewNote = ref('');
const hexdump = ref('');
const lastDump = ref<{ sha: string; size: number; complete: boolean; dedup: boolean; name: string } | null>(null);

const DEFAULT_SPAN = 64 * 1024;
const DUMP_CAP = 512 * 1024 * 1024;

const wholeTooBig = computed(() => !!selected.value && selected.value.size > DUMP_CAP);

const detailEl = ref<HTMLElement | null>(null);

function selectRegion(r: MapsRegion) {
  selected.value = r;
  addrInput.value = r.start;
  // 默认只取一小段：dalvik 空间单段就有 2GB，默认填整段会让人一按就撞上限
  sizeInput.value = String(Math.min(r.size || 4096, 1024 * 1024));
  hexdump.value = '';
  previewNote.value = '';
  lastDump.value = null;
  actionStatus.value = '';
  // 表格占了大半个视口，详情在它下面：选中后把它带进视野（已经可见时 nearest 不会跳）
  void nextTick(() => detailEl.value?.scrollIntoView({ block: 'nearest', behavior: 'smooth' }));
}

function useWhole() {
  if (!selected.value) return;
  if (wholeTooBig.value) {
    actionStatus.value = `该区域 ${fmtSize(selected.value.size)}，超过 ${fmtSize(DUMP_CAP)} 的转储上限。`;
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

function dumpHead(r: MapsRegion) {
  selectRegion(r);
  // 行内一键只取这一段自己的头部：跨段读会 short，产物虽然保留但 complete=false
  sizeInput.value = String(Math.min(r.size || 4096, DEFAULT_SPAN));
  void dumpRange();
}

// ---- 读取 / 转储 ----
const PREVIEW_MAX = 16 * 1024;

async function preview() {
  if (busy.value) return;
  const addr = parseAddr(addrInput.value);
  const span = parseSpan(sizeInput.value);
  if (addr === null) { previewNote.value = '地址无效：需要十六进制，如 0x7f3a2c0000。'; return; }
  if (span === null) { previewNote.value = '长度无效：填字节数，或 64K / 1M。'; return; }
  const want = Math.min(span, PREVIEW_MAX);
  busy.value = true;
  previewNote.value = span > want ? `预览最多 ${fmtSize(PREVIEW_MAX)}，本次读 ${fmtSize(want)}。` : '';
  hexdump.value = '';
  try {
    const r = await memoryRead(props.session, hexAddr(addr), want);
    if (r.ok !== true) { previewNote.value = r.error || '读取失败。'; return; }
    const bytes = base64ToBytes(r.b64 ?? '');
    if (!bytes.length) { previewNote.value = r.error || '这一段读不到内容。'; return; }
    hexdump.value = hexdumpOf(bytes, addr);
    if (bytes.length < want) {
      previewNote.value = `${previewNote.value ? `${previewNote.value} ` : ''}只读到 ${fmtSize(bytes.length)}（请求 ${fmtSize(want)}）。`;
    }
  } catch (e) {
    previewNote.value = e instanceof Error ? `读取失败：${e.message}` : '读取失败。';
  } finally { busy.value = false; }
}

async function dumpRange() {
  if (busy.value) return;
  const addr = parseAddr(addrInput.value);
  const span = parseSpan(sizeInput.value);
  if (addr === null) { actionStatus.value = '地址无效：需要十六进制，如 0x7f3a2c0000。'; return; }
  if (span === null) { actionStatus.value = '长度无效：填字节数，或 64K / 1M。'; return; }
  if (span > DUMP_CAP) {
    actionStatus.value = `${fmtSize(span)} 超过 ${fmtSize(DUMP_CAP)} 的转储上限，请缩小长度。`;
    return;
  }
  busy.value = true;
  lastDump.value = null;
  actionStatus.value = `正在转储 ${fmtSize(span)}…`;
  try {
    const r = await memoryDump(props.session, hexAddr(addr), span);
    if (r.error || !r.sha256) { actionStatus.value = `转储失败：${r.error || '没有返回产物'}。`; return; }
    lastDump.value = {
      sha: r.sha256, size: r.size ?? 0, complete: r.complete !== false,
      dedup: r.dedup === true, name: `${r.kind || 'bin'}-${hexAddr(addr).slice(2, 10)}-${r.sha256.slice(0, 8)}.${r.kind || 'bin'}`,
    };
    actionStatus.value = '';
    // 让「脱壳」段的记录表立刻能看到这条产物
    window.dispatchEvent(new CustomEvent('adh:dump-new', { detail: { ok: true, dump: r } }));
  } catch (e) {
    actionStatus.value = e instanceof Error ? `转储失败：${e.message}` : '转储失败。';
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

/** maps 的偏移是定宽 hex（00000000），表格里显示成 0x0 就够，别为前导零占一整列。 */
function compactOffset(offset: string): string {
  const m = String(offset ?? '').match(/^0x0*([0-9a-f]+)$/i);
  return m ? `0x${m[1]}` : offset;
}

/** 映射总量是按虚拟大小累加的，8G 用 M 显示（8278.3M）读起来没有尺度感。 */
function fmtBig(n: number): string {
  return n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)}G` : fmtSize(n);
}

// ---- 加载 ----
async function load() {
  if (!props.session) {
    regions.value = []; stats.value = null; error.value = '没有在线会话：先让目标应用注入并连上 agent。';
    return;
  }
  loading.value = true;
  error.value = '';
  const t0 = performance.now();
  try {
    const r = await memoryMaps(props.session);
    loadMs.value = performance.now() - t0;
    if (r.ok === false) { error.value = r.error || '内存映射读取失败。'; return; }
    regions.value = r.regions ?? [];
    stats.value = r.stats ?? null;
    truncated.value = r.truncated === true;
    if (selected.value && !regions.value.some((x) => x.start === selected.value!.start && x.path === selected.value!.path)) {
      selected.value = null;
      hexdump.value = '';
    }
  } catch (e) {
    error.value = e instanceof Error ? `内存映射读取失败：${e.message}` : '内存映射读取失败。';
  } finally { loading.value = false; }
}

onMounted(() => { void load(); });
watch(() => props.session, () => { selected.value = null; hexdump.value = ''; lastDump.value = null; void load(); });

const loadLabel = computed(() => {
  if (loading.value) return '读取中…';
  if (!loadMs.value) return '—';
  return `${Math.round(loadMs.value)}ms`;
});
</script>

<template>
  <div class="mempane">
    <div v-if="stats" class="mem-summary">
      <div class="mem-fact"><span>区域</span><b>{{ stats.total }}</b></div>
      <div class="mem-fact"><span>可执行</span><b>{{ stats.executable }}</b></div>
      <div class="mem-fact">
        <span>匿名可执行</span>
        <b :class="{ hot: stats.anonymousExecutable > 0 }" :title="`匿名可执行段合计 ${fmtSize(stats.anonymousExecutableBytes)}`">{{ stats.anonymousExecutable }}</b>
      </div>
      <div class="mem-fact">
        <span>可写可执行</span>
        <b :class="{ hot: stats.writableExecutable > 0 }">{{ stats.writableExecutable }}</b>
      </div>
      <div class="mem-fact"><span>映射总量</span><b>{{ fmtBig(stats.mappedBytes) }}</b></div>
      <div class="mem-fact"><span>读取</span><b>{{ loadLabel }}</b></div>
    </div>

    <div class="mem-controls">
      <input v-model="q" class="mem-input mono" type="search" aria-label="筛选路径或定位地址"
        placeholder="筛选路径，或输入地址定位（0x7f…）">
      <div class="system-kinds mem-modes">
        <button v-for="m in MODES" :key="m.key" type="button" :aria-pressed="mode === m.key" @click="mode = m.key">{{ m.label }}</button>
      </div>
      <select v-model.number="minSize" class="mem-select" aria-label="最小大小">
        <option :value="0">不限大小</option>
        <option :value="4096">≥ 4K</option>
        <option :value="65536">≥ 64K</option>
        <option :value="1048576">≥ 1M</option>
        <option :value="16777216">≥ 16M</option>
      </select>
      <select v-model="sort" class="mem-select" aria-label="排序">
        <option value="addr">按地址</option>
        <option value="size">按大小</option>
      </select>
      <button type="button" class="mem-refresh" :disabled="loading" @click="load">{{ loading ? '读取中…' : '刷新' }}</button>
    </div>

    <div v-if="error" class="dump-callout">{{ error }}</div>

    <div class="mem-scroll">
      <table class="mem-table">
        <thead>
          <tr>
            <th class="w-range">范围</th>
            <th class="w-size">大小</th>
            <th class="w-perm">权限</th>
            <th class="w-off">文件偏移</th>
            <th>映射 / 路径</th>
            <th class="w-act">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in pageRows" :key="`${r.start}-${r.path}`"
            :class="{ selected: selected && selected.start === r.start && selected.path === r.path }"
            @click="selectRegion(r)">
            <td class="mono mem-range">{{ r.start }}<span>{{ r.end }}</span></td>
            <td class="mono">{{ fmtSize(r.size) }}</td>
            <td class="mono" :class="permClass(r)">{{ r.perms }}</td>
            <td class="mono muted">{{ compactOffset(r.offset) }}</td>
            <td class="mem-path" :title="r.path || '(匿名映射)'">{{ r.path || '(匿名映射)' }}</td>
            <td class="mem-act">
              <button type="button" class="mem-row-btn" title="转储这一段开头的 64K；选中后可在下方改范围" @click.stop="dumpHead(r)">转储</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="!pageRows.length && !loading" class="empty">没有匹配的区域。</div>

    <div class="mem-pager">
      <span class="muted">
        共 {{ filtered.length }} 段<template v-if="filtered.length !== regions.length"> / {{ regions.length }}</template>
        <template v-if="truncated">（agent 应答截断）</template>
      </span>
      <span class="mem-pager-nav">
        <button type="button" :disabled="page <= 1" aria-label="第一页" @click="page = 1">«</button>
        <button type="button" :disabled="page <= 1" aria-label="上一页" @click="page--">‹</button>
        <span class="mono">第 {{ page }} / {{ pageCount }} 页</span>
        <button type="button" :disabled="page >= pageCount" aria-label="下一页" @click="page++">›</button>
        <button type="button" :disabled="page >= pageCount" aria-label="最后一页" @click="page = pageCount">»</button>
      </span>
      <select v-model.number="pageSize" class="mem-select" aria-label="每页条数">
        <option :value="50">50 条/页</option>
        <option :value="100">100 条/页</option>
        <option :value="200">200 条/页</option>
      </select>
    </div>

    <section ref="detailEl" class="mem-detail">
      <div class="mem-detail-head">
        <b>{{ selected ? '区域详情' : '任意范围' }}</b>
        <span class="muted">{{ selected ? '改长度后可只取这一段的一部分' : '点上面的行选中一段，或直接填地址和长度' }}</span>
      </div>
      <div v-if="selected" class="mem-region">
        <span class="mem-tag mono" :class="permClass(selected)">{{ selected.perms }}</span>
        <span class="mono">{{ selected.start }} – {{ selected.end }}</span>
        <span class="muted">{{ fmtSize(selected.size) }}</span>
        <span class="mem-region-path" :title="selected.path || '(匿名映射)'">{{ selected.path || '(匿名映射)' }}</span>
      </div>
      <div class="mem-fields">
        <label>地址<input v-model="addrInput" class="mono" placeholder="0x7f00000000" @keyup.enter="preview"></label>
        <label>长度<input v-model="sizeInput" class="mono" placeholder="4096 / 64K / 1M" @keyup.enter="preview"></label>
        <button type="button" :disabled="busy || !session" @click="preview">预览</button>
        <button type="button" class="primary" :disabled="busy || !session" @click="dumpRange">转储</button>
        <button type="button" :disabled="busy || !selected" :title="wholeTooBig ? '超过转储上限' : '把长度设为整段'" @click="useWhole">整段</button>
      </div>
      <div v-if="previewNote" class="mem-note">{{ previewNote }}</div>
      <div v-if="actionStatus" class="mem-note">{{ actionStatus }}</div>
      <div v-if="lastDump" class="mem-note ok">
        已转储 {{ fmtSize(lastDump.size) }}<template v-if="!lastDump.complete">（读取不完整）</template>
        <template v-if="lastDump.dedup">（内容与已有产物相同，已复用）</template>
        · <a :href="dumpDownloadUrl(lastDump.sha, lastDump.name)" class="dl-link">下载</a>
        · <span class="muted">已写入「脱壳」记录</span>
      </div>
      <pre v-if="hexdump" class="mem-hex">{{ hexdump }}</pre>
    </section>
  </div>
</template>

<style scoped>
.mempane { display: flex; flex-direction: column; gap: 12px; }
.mem-summary { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; }
.mem-fact { min-width: 0; padding: 9px 11px; border: 1px solid var(--line-soft); border-radius: 6px; background: var(--surface-2); }
.mem-fact span { display: block; color: var(--muted); font-size: 11px; }
.mem-fact b { display: block; margin-top: 3px; color: var(--ink-2); font-size: 13px; font-weight: 600; font-variant-numeric: tabular-nums; }
.mem-fact b.hot { color: var(--amber); }

.mem-controls { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.mem-input { flex: 1 1 260px; min-width: 190px; min-height: 32px; padding: 5px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--ink); font-size: 12px; }
.mem-input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); }
.mem-select { min-height: 32px; padding: 4px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--ink-2); font-size: 12px; }
.mem-refresh { min-height: 32px; padding: 0 12px; border: 1px solid var(--line); border-radius: 4px; background: transparent; color: var(--ink-2); font-size: 12px; cursor: pointer; }
.mem-refresh:hover { color: var(--ink); background: rgba(255, 255, 255, .04); border-color: var(--muted); }
.mem-refresh:disabled { opacity: .45; cursor: default; }

.mem-scroll { max-height: 48vh; overflow: auto; border: 1px solid var(--line-soft); border-radius: 8px; background: var(--surface); }
.mem-table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 12px; }
.mem-table th, .mem-table td { text-align: left; padding: 5px 9px; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
.mem-table th { position: sticky; top: 0; z-index: 1; background: var(--surface); color: var(--muted); font-size: 11px; font-weight: 600; }
.mem-table tbody tr { cursor: pointer; }
.mem-table tbody tr:hover { background: var(--surface-2); }
.mem-table tbody tr.selected { background: var(--surface-2); box-shadow: inset 2px 0 0 var(--blue); }
.mem-table .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; font-variant-numeric: tabular-nums; }
.mem-range { white-space: nowrap; }
.mem-range span { display: block; color: var(--muted); }
.mem-path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink-2); }
.mem-act { text-align: right; }
.w-range { width: 152px; }
.w-size { width: 66px; }
.w-perm { width: 58px; }
.w-off { width: 82px; }
.w-act { width: 62px; text-align: right !important; }
.perm-hot { color: var(--amber); }
.perm-anon-exec { color: var(--blue); }
.mem-row-btn { min-height: 24px; padding: 0 8px; border: 1px solid var(--line); border-radius: 4px; background: transparent; color: var(--muted); font-size: 11px; cursor: pointer; }
.mem-row-btn:hover { color: var(--ink); border-color: var(--muted); }

.mem-pager { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 12px; }
.mem-pager-nav { display: inline-flex; align-items: center; gap: 6px; }
.mem-pager-nav button { min-width: 26px; min-height: 26px; padding: 0 6px; border: 1px solid var(--line-soft); border-radius: 4px; background: var(--chrome); color: var(--muted); font-size: 12px; cursor: pointer; }
.mem-pager-nav button:hover:not(:disabled) { color: var(--ink); border-color: var(--line); }
.mem-pager-nav button:disabled { opacity: .35; cursor: default; }
.mem-pager-nav span { color: var(--muted); font-size: 11px; }

.mem-detail { display: flex; flex-direction: column; gap: 8px; padding: 12px; border: 1px solid var(--line-soft); border-radius: 8px; background: var(--surface); scroll-margin-bottom: 14px; }
.mem-detail-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.mem-detail-head b { color: var(--ink-2); font-size: 13px; }
.mem-detail-head .muted { font-size: 11px; }
.mem-region { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 11px; color: var(--ink-2); }
.mem-tag { padding: 1px 6px; border: 1px solid var(--line); border-radius: 3px; color: var(--muted); }
.mem-region-path { overflow-wrap: anywhere; color: var(--muted); }
.mem-fields { display: flex; align-items: flex-end; gap: 8px; flex-wrap: wrap; }
.mem-fields label { display: flex; flex-direction: column; gap: 4px; color: var(--muted); font-size: 11px; }
.mem-fields input { width: 168px; min-height: 30px; padding: 4px 8px; border: 1px solid var(--line); border-radius: 5px; background: var(--bg); color: var(--ink); font-size: 12px; }
.mem-fields input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); }
.mem-fields button { min-height: 30px; padding: 0 12px; border: 1px solid var(--line); border-radius: 4px; background: transparent; color: var(--ink-2); font-size: 12px; cursor: pointer; }
.mem-fields button:hover:not(:disabled) { color: var(--ink); background: rgba(255, 255, 255, .04); border-color: var(--muted); }
.mem-fields button.primary { color: var(--bg); background: var(--blue); border-color: var(--blue); font-weight: 600; }
.mem-fields button.primary:hover:not(:disabled) { background: var(--ink-2); }
.mem-fields button:disabled { opacity: .45; cursor: default; }
.mem-note { font-size: 11.5px; line-height: 1.6; color: var(--muted); }
.mem-note.ok { color: var(--green); }
.mem-note.ok .muted { color: var(--muted); }
.mem-hex { max-height: 300px; overflow: auto; margin: 0; padding: 10px 12px; border: 1px solid var(--line-soft); border-radius: 6px; background: var(--bg); color: var(--ink-2); white-space: pre; font: 11px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; }

@media (max-width: 1200px) {
  .mem-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .w-off { display: none; }
}
@media (max-width: 760px) {
  .mem-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .w-range { width: 118px; }
  .w-size, .w-perm { width: 54px; }
  .mem-fields input { width: 132px; }
  .mem-scroll { max-height: 40vh; }
}
</style>

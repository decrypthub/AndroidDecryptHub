<script setup lang="ts">
import { computed, reactive, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, belongsToApp, capRemoveWhere, capVisible, capDisplayCap, DISPLAY_CAPS, panelDisplay, savePanelDisplay, toast } from '../store';
import { getCaptures, getExchanges, getCaptureDetail, type Cap } from '../api';
import { catClass, cryptoView, captureLengths, rowLens, fmtTime, CATLABEL, type CatKey } from '../capview';
import { SearchOutline } from '@vicons/ionicons5';
import CapDetail from './CapDetail.vue';
import ExchangeDetail from './ExchangeDetail.vue';

const props = defineProps<{ kind: 'crypto' | 'system' | 'net' }>();

interface ExchangePart {
  startLine?: string; headerText?: string; bodyText?: string; bodyBytes?: number;
  bodyHex?: string; binary?: boolean; complete?: boolean; decoded?: boolean;
  contentEncoding?: string; note?: string;
}
interface Exchange {
  id: string; seq?: number; label?: string; status?: string; conn?: string; ts?: number; tsNs?: number;
  captureIds?: number[]; note?: string; request?: ExchangePart; response?: ExchangePart;
}

const filter = reactive({
  q: '', min: null as number | null, max: null as number | null,
  cat: -2, paused: false, kind: 'all',
});
const advOpen = ref(false);
const sel = ref<number | string | null>(null);
const selDetail = ref<Record<string, unknown> | null>(null);
const selExchange = ref<Exchange | null>(null);
const exchanges = ref<Exchange[]>([]);
const exNotes = ref<string[]>([]);
const scrollTop = ref(0);
const newCount = ref(0);
// null means live; an empty snapshot is still a valid paused view.
const frozenCaptures = ref<Cap[] | null>(null);
const frozenExchanges = ref<Exchange[] | null>(null);

// ---- 分页与时间窗口状态 ----
const cursorStack = ref<Array<number | null>>([]);
const currentBeforeId = ref<number | null>(null);
const pagedItems = ref<Cap[] | null>(null);
const pagedHasMore = ref(false);
const pageLoading = ref(false);
const netPage = ref(1);

// 时间范围：毫秒时间戳，n-date-picker 直接绑定
const fromMs = ref<number | null>(null);
const toMs = ref<number | null>(null);
const fromTs = computed(() => fromMs.value);
const toTs = computed(() => toMs.value);
const hasTimeRange = computed(() => fromTs.value !== null || toTs.value !== null);
const isHistoricalMode = computed(() => pagedItems.value !== null);

const CATS: Record<string, CatKey[]> = {
  crypto: ['digest', 'hmac', 'sym', 'asym', 'aead'],
  system: ['sys', 'file'],
  net: ['net'],
};
const CAT_BY_SEL: Record<number, CatKey> = { 0: 'digest', 1: 'hmac', 2: 'sym', 3: 'asym', 4: 'aead' };
const SYS_KINDS: Array<[string, string]> = [['all', '全部活动'], ['system', '系统调用'], ['file', '文件读写']];
const LIST_ID: Record<string, string> = { crypto: 'cc-list', system: 'sy-list', net: 'nt-list' };
const HEAD_LABELS: Record<string, [string, string, string]> = {
  crypto: ['算法', '内容预览', '输入 → 输出'],
  system: ['函数', '内容预览', '操作'],
  net: ['请求', '响应', '状态'],
};

function panelCats(): string[] {
  if (props.kind === 'crypto') return ['crypto'];
  if (props.kind === 'system') return ['system', 'file'];
  return ['net'];
}
function matchesPanel(c: Cap): boolean {
  if (!panelCats().includes(c.category)) return false;
  if (props.kind === 'system' && filter.kind !== 'all') return c.category === filter.kind;
  return true;
}

function serverCategory(): string {
  if (props.kind === 'crypto') return 'crypto';
  if (props.kind === 'system') return filter.kind === 'all' ? 'system,file' : filter.kind;
  return 'net';
}

function applyClientFilter(source: Cap[]): Cap[] {
  let items = source.filter(c => matchesPanel(c) && belongsToApp(c) && capVisible(c));
  if (props.kind === 'crypto') items = items.filter(c => cryptoView(c).show !== false);
  if (fromTs.value != null) items = items.filter(c => c.ts >= fromTs.value!);
  if (toTs.value != null) items = items.filter(c => c.ts <= toTs.value!);
  const q = filter.q.trim().toLowerCase();
  if (q) {
    items = items.filter(c => {
      if (/^#\d+$/.test(q)) return String(c.id) === q.slice(1);
      const v = c.category === 'crypto' ? cryptoView(c) : null;
      return ((c.algo || '') + ' ' + (c.op || '') + ' ' + (c.func || '') + ' ' + (c.path || '') + ' ' +
        (c.preview || '') + ' ' + (v?.title || '') + ' ' + (v?.hook || '') + ' ' + (v?.direction || ''))
        .toLowerCase().includes(q);
    });
  }
  if (filter.min != null) items = items.filter(c => {
    const n = captureLengths(c).input.bytes; return n != null && n >= filter.min!;
  });
  if (filter.max != null) items = items.filter(c => {
    const n = captureLengths(c).input.bytes; return n != null && n <= filter.max!;
  });
  if (props.kind === 'crypto' && filter.cat >= 0) {
    const want = CAT_BY_SEL[filter.cat];
    items = items.filter(c => catClass(c) === want);
  }
  return items;
}

// 本板块归属当前应用的记录（过滤前）
const scoped = computed(() => store.capItems.filter(c => matchesPanel(c) && belongsToApp(c)));

const visible = computed(() => applyClientFilter(pagedItems.value ??
  (filter.paused ? frozenCaptures.value ?? [] : store.capItems)));

async function loadServerPage(beforeId: number | null) {
  if (!store.chosenPkg || props.kind === 'net') return;
  const pkg = store.chosenPkg;
  pageLoading.value = true;
  try {
    const qTrim = filter.q.trim();
    const r = await getCaptures({
      package: pkg,
      category: serverCategory(),
      beforeId,
      fromTs: fromTs.value,
      toTs: toTs.value,
      q: qTrim && !/^#\d+$/.test(qTrim) ? qTrim : undefined,
      limit: capDisplayCap.value,
    });
    if (store.chosenPkg !== pkg) return;
    const list = r.captures ?? r.items ?? [];
    for (const c of list) if (c.sessionId && c.package) store.sessionPkg.set(c.sessionId, c.package);
    pagedItems.value = list;
    pagedHasMore.value = !!r.hasMore;
    currentBeforeId.value = beforeId;
    const el = document.getElementById(LIST_ID[props.kind]);
    el?.scrollTo({ top: 0 });
  } catch {
    toast('读取分页记录失败');
  } finally {
    pageLoading.value = false;
  }
}

// ---- 网络板块：重组交换 ----
const exLoadedOnce = ref(false);
async function loadExchanges() {
  if (props.kind !== 'net' || !store.chosenPkg) { exchanges.value = []; return; }
  const pkg = store.chosenPkg;
  try {
    const r = await getExchanges(pkg, { fromTs: fromTs.value, toTs: toTs.value }) as {
      exchanges?: Exchange[]; http2Idle?: number;
    };
    if (store.chosenPkg !== pkg) return; // 竞态：响应回来时包已换
    exchanges.value = r.exchanges ?? [];
    const notes: string[] = [];
    if (r.http2Idle) notes.push(`${r.http2Idle} 条 HTTP/2 连接还没有完整请求`);
    exNotes.value = notes;
  } catch { /* 保旧数据 */ } finally { exLoadedOnce.value = true; }
}
let exTimer = 0;
function scheduleExchanges() {
  clearTimeout(exTimer);
  exTimer = window.setTimeout(() => void loadExchanges(), 250);
}

const matchedExchangesAll = computed(() => {
  if (props.kind !== 'net') return [];
  const q = filter.q.trim().toLowerCase();
  const bySeq = /^#\d+$/.test(q) ? q.slice(1) : '';
  return (filter.paused ? frozenExchanges.value ?? [] : exchanges.value).filter(ex => {
    if (fromTs.value != null && (ex.ts ?? 0) < fromTs.value) return false;
    if (toTs.value != null && (ex.ts ?? 0) > toTs.value) return false;
    if (bySeq) {
      if (String(ex.seq ?? '') !== bySeq) return false;
    } else if (q) {
      const blob = [ex.label, ex.status, ex.note,
        ex.request?.startLine, ex.request?.headerText, ex.request?.bodyText,
        ex.response?.startLine, ex.response?.headerText, ex.response?.bodyText]
        .join(' ').toLowerCase();
      if (!blob.includes(q)) return false;
    }
    const n = (ex.request?.bodyBytes ?? 0) + (ex.response?.bodyBytes ?? 0);
    if (filter.min != null && n < filter.min) return false;
    if (filter.max != null && n > filter.max) return false;
    return true;
  }).sort((a, b) =>
    // 主键用 host 墙钟 ts（跨会话/设备/重启可比）；tsNs 是设备开机相对时钟，只在
    // 同一批次内当精度用，跨基准排序会错。同一记录上的多条请求再按 seq 保持原顺序。
    ((b.ts ?? 0) - (a.ts ?? 0)) || ((b.tsNs ?? 0) - (a.tsNs ?? 0)) || ((b.seq ?? 0) - (a.seq ?? 0)));
});

const matchedExchanges = computed(() => {
  const start = (netPage.value - 1) * capDisplayCap.value;
  return matchedExchangesAll.value.slice(start, start + capDisplayCap.value);
});

const liveOrPagedRows = computed(() => props.kind === 'net' ? [] : visible.value.slice(-capDisplayCap.value).reverse());
const rows = liveOrPagedRows;
watch(() => filter.paused, p => {
  // Freeze the input, not an already-filtered page. Search, filters and page size remain usable.
  frozenCaptures.value = p ? store.capItems.filter(belongsToApp).map(c => ({ ...c })) : null;
  frozenExchanges.value = p ? exchanges.value.map(ex => ({
    ...ex, captureIds: ex.captureIds ? [...ex.captureIds] : undefined,
    request: ex.request ? { ...ex.request } : undefined,
    response: ex.response ? { ...ex.response } : undefined,
  })) : null;
  if (!p) newCount.value = 0;
}, { flush: 'sync' });

const pageNumber = computed(() => props.kind === 'net' ? netPage.value : cursorStack.value.length + 1);
const canPrevPage = computed(() => {
  if (pageLoading.value) return false;
  if (props.kind === 'net') return netPage.value * capDisplayCap.value < matchedExchangesAll.value.length;
  if (isHistoricalMode.value) return pagedHasMore.value && rows.value.length > 0;
  const bucketKey = props.kind === 'crypto' ? 'crypto' : 'system';
  return rows.value.length > 0 && (visible.value.length > capDisplayCap.value || store.capHasOlder[bucketKey]);
});
const canNextPage = computed(() => {
  if (pageLoading.value) return false;
  if (props.kind === 'net') return netPage.value > 1;
  return cursorStack.value.length > 0;
});

async function prevPage() {
  if (!canPrevPage.value) return;
  if (props.kind === 'net') { netPage.value++; return; }
  const oldestShown = rows.value.at(-1)?.id;
  if (oldestShown == null) return;
  cursorStack.value.push(currentBeforeId.value);
  await loadServerPage(oldestShown);
}
async function nextPage() {
  if (!canNextPage.value) return;
  if (props.kind === 'net') { netPage.value = Math.max(1, netPage.value - 1); return; }
  const prevCursor = cursorStack.value.pop() ?? null;
  if (cursorStack.value.length === 0 && prevCursor === null && !hasTimeRange.value) {
    currentBeforeId.value = null;
    pagedItems.value = null;
    const el = document.getElementById(LIST_ID[props.kind]);
    el?.scrollTo({ top: 0 });
    return;
  }
  await loadServerPage(prevCursor);
}

function setQuickMinutes(mins: number) {
  fromMs.value = Date.now() - mins * 60_000;
  toMs.value = null;
  applyTimeRange();
}
function clearTimeRange() {
  fromMs.value = null;
  toMs.value = null;
  cursorStack.value = [];
  currentBeforeId.value = null;
  pagedItems.value = null;
  netPage.value = 1;
  if (props.kind === 'net') void loadExchanges();
}
function applyTimeRange() {
  cursorStack.value = [];
  currentBeforeId.value = null;
  netPage.value = 1;
  if (props.kind === 'net') { void loadExchanges(); return; }
  if (hasTimeRange.value) void loadServerPage(null);
  else pagedItems.value = null;
}
function onPageCapChange(val: number) {
  if (DISPLAY_CAPS.includes(val)) {
    savePanelDisplay({ ...panelDisplay, limit: val });
    if (isHistoricalMode.value) void loadServerPage(currentBeforeId.value);
  }
}

// 新记录横幅：暂停或滚离顶部时累计
watch(() => props.kind === 'net' ? exchanges.value.map(ex => ex.id) :
  store.capItems.filter(c => panelCats().includes(c.category) && belongsToApp(c)).map(c => c.id), (ids, previous = []) => {
  if ((filter.paused || scrollTop.value > 48) && !isHistoricalMode.value) {
    const seen = new Set<string | number>(previous);
    newCount.value += ids.filter(id => !seen.has(id)).length;
  } else newCount.value = 0;
});

const countText = computed(() => {
  const n = props.kind === 'net' ? matchedExchanges.value.length : rows.value.length;
  const pg = pageNumber.value > 1 ? ` · 第${pageNumber.value}页` : '';
  return `${n} 条${pg}`;
});

async function selectRow(c: Cap) {
  sel.value = c.id; selExchange.value = null;
  selDetail.value = { _loading: true };
  try {
    const d = await getCaptureDetail(c.id, store.chosenPkg || undefined);
    if (sel.value === c.id) selDetail.value = d;
  } catch {
    if (sel.value === c.id) selDetail.value = { _error: '读取详情失败', cap: c };
  }
}
function selectExchange(ex: Exchange) {
  sel.value = ex.id; selDetail.value = null; selExchange.value = ex;
}
function closeDetail() { sel.value = null; selDetail.value = null; selExchange.value = null; }
function onCapDeleted(id: number) {
  capRemoveWhere(c => c.id === id);
  if (frozenCaptures.value) frozenCaptures.value = frozenCaptures.value.filter(c => c.id !== id);
  if (pagedItems.value) pagedItems.value = pagedItems.value.filter(c => c.id !== id);
  closeDetail();
}

function onScroll(e: Event) {
  scrollTop.value = (e.target as HTMLElement).scrollTop;
  if (scrollTop.value <= 48) newCount.value = 0;
}
function jumpLatest() {
  filter.paused = false;
  cursorStack.value = [];
  currentBeforeId.value = null;
  netPage.value = 1;
  if (hasTimeRange.value) void loadServerPage(null);
  else pagedItems.value = null;
  scrollTop.value = 0; newCount.value = 0;
  const el = document.getElementById(LIST_ID[props.kind]);
  el?.scrollTo({ top: 0 });
}

// ---- 筛选徽标：只算高级筛选项（搜索词在框里可见）----
const advCount = computed(() => {
  let n = 0;
  if (filter.min != null || filter.max != null) n++;
  if (props.kind === 'crypto' && filter.cat >= 0) n++;
  if (props.kind === 'system' && filter.kind !== 'all') n++;
  if (hasTimeRange.value) n++;
  return n;
});
const filterActive = computed(() => !!(filter.q.trim() || advCount.value));
function resetFilter() {
  filter.q = ''; filter.min = null; filter.max = null; filter.cat = -2; filter.kind = 'all';
  clearTimeRange();
}
function downloadView() {
  const items = props.kind === 'net' ? matchedExchanges.value : rows.value;
  const pkg = store.chosenPkg || 'all';
  const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `adh-${props.kind}-${pkg}-filtered.json`;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  toast(`已下载 ${items.length} 条`);
}
function clearView() {
  const pkg = store.chosenPkg;
  if (!confirm(`清空本页列表？（不删磁盘）\n${pkg ? '当前应用 ' + pkg : '全部应用'}`)) return;
  const n = capRemoveWhere(c => matchesPanel(c) && belongsToApp(c));
  if (frozenCaptures.value) frozenCaptures.value = frozenCaptures.value.filter(c => !matchesPanel(c));
  closeDetail();
  toast(`已清空本页 ${n} 条`);
}

const MORE_OPTS = [
  { label: '下载本页', key: 'dl' },
  { label: '清空本页', key: 'clear', props: { style: 'color:#f87171' } },
];
function onMoreSelect(k: string) { if (k === 'dl') downloadView(); else clearView(); }

// 系统页只留事件列表；指纹摘要不在面板展示。

// ---- 分栏拖动 ----
const listWidth = ref(0); // 0 = CSS 默认宽度
const dragging = ref(false);
function startDrag(e: MouseEvent) {
  e.preventDefault();
  const ws = (e.target as HTMLElement).parentElement!;
  const rect = ws.getBoundingClientRect();
  const move = (ev: MouseEvent) => {
    dragging.value = true;
    let w = ev.clientX - rect.left;
    w = Math.max(220, Math.min(Math.floor(rect.width * 0.7), rect.width - 260, w));
    listWidth.value = w;
  };
  const up = () => {
    document.removeEventListener('mousemove', move);
    document.removeEventListener('mouseup', up);
    dragging.value = false;
  };
  document.addEventListener('mousemove', move);
  document.addEventListener('mouseup', up);
}

let poll = 0;
onMounted(() => {
  if (props.kind === 'net') void loadExchanges();
  poll = window.setInterval(() => {
    if (props.kind === 'net') scheduleExchanges();
  }, 5000);
});
onUnmounted(() => {
  clearInterval(poll);
});
watch([() => store.selectedDeviceKey, () => store.chosenPkg, () => props.kind], () => {
  filter.paused = false;
  newCount.value = 0;
  sel.value = null; selDetail.value = null; selExchange.value = null;
  cursorStack.value = []; currentBeforeId.value = null; pagedItems.value = null; netPage.value = 1;
  // 切应用必须清掉上一个应用的交换并重新进入加载态：否则列表会继续显示别人的请求，也不会有加载光标。
  exLoadedOnce.value = false;
  exchanges.value = [];
  exNotes.value = [];
  void loadExchanges();
});
watch(() => store.capItems.length, () => { if (props.kind === 'net' && !hasTimeRange.value) scheduleExchanges(); });

// 列表加载中（不铺骨架）：只用来把列表区光标切成加载态、压住空态文案。
// 列表里已经有行时一律保留旧行，不做任何占位，避免每次刷新整块闪一下。
const listLoading = computed(() => {
  if (!store.chosenPkg) return false;
  if (props.kind === 'net') return !exLoadedOnce.value && !matchedExchanges.value.length;
  if (store.capLoading || pageLoading.value) return !rows.value.length;
  return false;
});
const emptyText = computed(() => {
  if (!store.chosenPkg) return '先在顶部选择应用。';
  if (pageLoading.value) return '正在读取分页记录…';
  if (props.kind === 'net')
    return exchanges.value.length ? '没有符合筛选条件的网络记录。' :
      scoped.value.length ? `有 ${scoped.value.length} 条 TLS，尚未拼成 HTTP。` : '还没有网络记录。';
  if (filterActive.value && scoped.value.length) return '没有符合筛选条件的记录。';
  if (props.kind === 'crypto') return '还没有加解密记录。';
  return '还没有系统事件。';
});
// 页脚回答两个问题：一共多少条、现在是第几页。原来只说「实时刷新中」，把当前页当成了全部。
// 数字来自服务端按同一筛选算出的命中数（`matched`，分页游标不影响），保留窗口之外的记录
// 已被淘汰，采集期丢弃另计——这些都要在提示里说清楚，不能用一个数字暗示「全部都在这里」。
const bucketTotal = computed(() => {
  if (props.kind === 'net') return matchedExchangesAll.value.length;
  const key = props.kind === 'crypto' ? 'crypto' : 'system';
  return Math.max(store.capTotal[key] || 0, visible.value.length);
});
const footHint = computed(() => {
  const bits = [`保留窗口内共 ${bucketTotal.value} 条（更早的已按保留上限淘汰）`, '上一页/下一页按页向更早读取'];
  if (store.capDropped > 0) bits.push(`采集期丢弃 ${store.capDropped} 条`);
  if (!store.capComplete) bits.push('最近一次采集不完整');
  return bits.join(' · ');
});
const listFootLeft = computed(() => {
  if (pageLoading.value) return '读取中…';
  const parts = [`共 ${bucketTotal.value.toLocaleString('zh-CN')} 条`, `第 ${pageNumber.value} 页`];
  if (hasTimeRange.value) parts.push('时间段筛选');
  else if (isHistoricalMode.value) parts.push('历史记录');
  else if (filter.paused) parts.push('已暂停刷新');
  else parts.push(store.wsState === 'live' ? '实时刷新中' : '等待连接');
  return parts.join(' · ');
});

function cryptoRow(c: Cap) {
  const v = cryptoView(c);
  return { ...v, cc: catClass(c) };
}
// 页面内不再画标题（侧栏高亮 + Tab 标题表达当前板块），但保留一个视觉隐藏的 h1：
// 读屏和大纲仍能拿到板块名。
const BOARD_LABEL: Record<string, string> = { crypto: '加解密', system: '系统', net: '网络' };
const searchPlaceholder = computed(() =>
  props.kind === 'crypto' ? '搜索 #序号、算法、Hook 或预览' : '搜索 #序号、操作、Hook 或预览');
</script>

<template>
  <div class="cap-view">
    <h1 class="sr-only">{{ BOARD_LABEL[kind] }}</h1>
    <div class="filters">
      <div class="toolbar-main">
        <div class="toolbar-search">
          <n-input v-model:value="filter.q" size="small" clearable :placeholder="searchPlaceholder"
            class="toolbar-search-input">
            <template #prefix><n-icon :component="SearchOutline" class="search-ico" /></template>
          </n-input>
        </div>
        <div class="toolbar-actions">
          <n-button size="small" :secondary="!advCount" :type="advCount ? 'primary' : 'default'"
            :aria-expanded="advOpen" @click="advOpen = true">
            筛选<template v-if="advCount"> · {{ advCount }}</template>
          </n-button>
          <span id="count">{{ countText }}</span>
          <n-button size="small" :type="filter.paused ? 'warning' : 'default'" secondary
            :title="filter.paused ? '恢复列表刷新' : '只停列表刷新'"
            @click="filter.paused = !filter.paused">{{ filter.paused ? '继续' : '暂停刷新' }}</n-button>
          <n-dropdown trigger="click" :options="MORE_OPTS" @select="onMoreSelect">
            <n-button quaternary size="small" title="更多">⋯</n-button>
          </n-dropdown>
        </div>
      </div>
    </div>

    <n-modal v-model:show="advOpen" preset="card" title="筛选" size="small" content-scrollable
      style="width:min(430px, calc(100vw - 28px))">
      <div class="filter-modal-body">
        <fieldset v-if="kind === 'system'" class="system-filter">
          <legend>活动类型</legend>
          <n-radio-group v-model:value="filter.kind" size="small">
            <n-radio-button v-for="[k, l] in SYS_KINDS" :key="k" :value="k">{{ l }}</n-radio-button>
          </n-radio-group>
        </fieldset>
        <label v-if="kind === 'crypto'" class="filter-field">分类
          <n-select v-model:value="filter.cat" size="small" class="cat-select" :options="[
              { label: '全部', value: -2 }, { label: '摘要', value: 0 }, { label: 'HMAC', value: 1 },
              { label: '对称', value: 2 }, { label: '非对称', value: 3 }, { label: 'AEAD', value: 4 },
            ]" />
        </label>
        <div class="size-filter">
          <label>输入大小</label>
          <n-input-number v-model:value="filter.min" size="small" :min="0" placeholder="0" class="size-num" />
          <span class="sep">—</span>
          <n-input-number v-model:value="filter.max" size="small" :min="0" placeholder="不限" class="size-num" />
          <span class="unit">B</span>
        </div>
        <fieldset class="time-filter">
          <legend>时间范围</legend>
          <div class="time-quick">
            <n-button size="tiny" @click="setQuickMinutes(1)">近 1 分钟</n-button>
            <n-button size="tiny" @click="setQuickMinutes(5)">近 5 分钟</n-button>
            <n-button size="tiny" @click="setQuickMinutes(30)">近 30 分钟</n-button>
            <n-button v-if="hasTimeRange" size="tiny" tertiary @click="clearTimeRange">清除</n-button>
          </div>
          <div class="time-inputs">
            <n-date-picker v-model:value="fromMs" type="datetime" size="small" clearable
              placeholder="开始时间" @update:value="applyTimeRange" />
            <span class="sep">至</span>
            <n-date-picker v-model:value="toMs" type="datetime" size="small" clearable
              placeholder="结束时间" @update:value="applyTimeRange" />
          </div>
        </fieldset>
      </div>
      <template #footer>
        <div class="filter-modal-footer">
          <n-button text size="small" type="primary" :disabled="!filterActive" @click="resetFilter">重置筛选</n-button>
          <n-button size="small" type="primary" @click="advOpen = false">完成</n-button>
        </div>
      </template>
    </n-modal>

    <div class="workspace capture-workspace" :class="{ 'compact-captures': panelDisplay.density === 'compact', 'detail-open': sel !== null, 'no-results': !listLoading && sel === null && !(kind === 'net' ? matchedExchanges.length : rows.length) }">
      <div class="list-pane" :style="listWidth ? { width: listWidth + 'px' } : undefined">
        <div class="new-banner" :class="{ show: newCount > 0 }">
          <span>{{ newCount }} 条新记录</span>
          <n-button text size="tiny" type="primary" @click="jumpLatest">跳到最新</n-button>
        </div>

        <div v-if="sel === null && (kind === 'net' ? matchedExchanges.length : rows.length)" class="ledger-head adh-grid" aria-hidden="true"><span>序号</span><span>{{ HEAD_LABELS[kind][0] }}</span><span>{{ HEAD_LABELS[kind][1] }}</span><span>{{ HEAD_LABELS[kind][2] }}</span><span>时间</span></div>
        <div class="cap-list" :class="{ loading: listLoading }" :id="LIST_ID[kind]" tabindex="0" :aria-busy="listLoading" @scroll="onScroll">
          <div v-if="hasTimeRange" class="ex-note time-banner">
            <span>时间筛选已启用</span>
            <n-button text size="small" type="primary" @click="clearTimeRange">切回实时</n-button>
          </div>
          <div v-for="n in exNotes" :key="n" class="ex-note">{{ n }}</div>
          <template v-if="kind === 'net'">
            <div v-for="ex in matchedExchanges" :key="ex.id" class="row cat-net" :class="{ selected: sel === ex.id }"
              role="button" tabindex="0" @keydown.enter.prevent="selectExchange(ex)" @keydown.space.prevent="selectExchange(ex)" @click="selectExchange(ex)">
              <div class="top">
                <span class="seq">#{{ ex.seq ?? '—' }}</span>
                <span class="pill net">网络</span>
                <span class="algo">{{ ex.label }}</span>
                <span v-if="ex.status" class="op">{{ ex.status }}</span>
                <span class="ts">{{ fmtTime(ex.ts) }}</span>
              </div>
              <div class="lens">{{ ex.response?.startLine || ex.request?.startLine || ex.note }}</div>
            </div>
            <p v-if="!matchedExchanges.length && !listLoading" class="empty-row" role="status">{{ emptyText }}</p>
          </template>

          <template v-else>
            <div v-for="c in rows" :key="c.id" class="row"
              :class="[`cat-${catClass(c)}`, { selected: sel === c.id, 'crypto-row': c.category === 'crypto' }]"
              role="button" tabindex="0" @keydown.enter.prevent="selectRow(c)" @keydown.space.prevent="selectRow(c)" @click="selectRow(c)">
              <template v-if="c.category === 'crypto'">
                <div class="top">
                  <span class="seq">#{{ c.id }}</span>
                  <span class="algo">{{ cryptoRow(c).title }}</span>
                  <span v-if="cryptoRow(c).direction" class="op">{{ cryptoRow(c).direction }}</span>
                  <span v-if="cryptoRow(c).sizeLabel" class="sizes">{{ cryptoRow(c).sizeLabel }}</span>
                  <span v-if="cryptoRow(c).hasKey" class="mark">有密钥</span>
                  <span class="ts">{{ fmtTime(c.ts) }}</span>
                </div>
                <div v-if="cryptoRow(c).preview || cryptoRow(c).hook" class="subline">
                  <span v-if="cryptoRow(c).preview" class="preview">{{ cryptoRow(c).preview }}</span>
                  <span v-if="cryptoRow(c).hook" class="hook">{{ cryptoRow(c).hook }}</span>
                </div>
              </template>
              <template v-else>
                <div class="top">
                  <span class="seq">#{{ c.id }}</span>
                  <span class="pill" :class="catClass(c)">{{ CATLABEL[catClass(c)] }}</span>
                  <span class="algo">{{ c.algo }}</span>
                  <span class="op">{{ c.op }}</span>
                  <span class="ts">{{ fmtTime(c.ts) }}</span>
                </div>
                <div class="lens">{{ rowLens(c) }}</div>
                <div v-if="c.preview && c.category !== 'net' && c.category !== 'file' && c.category !== 'system'"
                  class="preview">{{ c.preview }}</div>
              </template>
            </div>
            <p v-if="!rows.length && !listLoading" class="empty-row" role="status">{{ emptyText }}</p>
          </template>
        </div>
        <div v-if="canPrevPage || canNextPage || rows.length || matchedExchanges.length || isHistoricalMode" class="capture-list-foot">
          <span :title="footHint">{{ listFootLeft }}</span>
          <div class="pager-controls">
            <n-select :value="capDisplayCap" size="small" class="page-cap-select" title="单页返回条数上限"
              :options="DISPLAY_CAPS.map(cap => ({ label: `${cap} 条/页`, value: cap }))"
              @update:value="onPageCapChange" />
            <n-button v-if="canPrevPage || canNextPage" size="small" :disabled="!canPrevPage" title="读取更早一页" @click="prevPage">上一页</n-button>
            <n-button v-if="canPrevPage || canNextPage" size="small" :disabled="!canNextPage" title="读取更新一页" @click="nextPage">下一页</n-button>
            <n-button v-if="isHistoricalMode || netPage > 1" size="small" tertiary @click="jumpLatest">最新</n-button>
          </div>
        </div>
      </div>

      <div class="splitter" :class="{ dragging }" @mousedown="startDrag"></div>

      <section class="capture-detail-shell">
        <div class="capture-detail-nav">
          <n-button quaternary size="small" @click="closeDetail">‹ 返回列表</n-button>
        </div>
        <div class="detail-pane">
          <ExchangeDetail v-if="selExchange" :ex="selExchange" />
          <CapDetail v-else-if="selDetail" :detail="selDetail" @deleted="onCapDeleted" />
          <div v-else class="detail-empty detail-placeholder">
            选择一条记录查看详情
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.cap-list { outline: none; }
.cap-empty { padding: 48px 16px; }
/* 加载中不铺骨架：列表为空时只把光标切成加载态，数据来了直接出现，不再有骨架→内容的跳动。 */
.cap-list.loading, .cap-list.loading .row { cursor: progress; }
.detail-placeholder { min-height: 62vh; display: grid; place-items: center; padding: 0; }
.ph-title { font-size: 15px; font-weight: 600; color: var(--ink-2); }
.ph-desc { margin-top: 6px; font-size: 12.5px; color: var(--muted); }
.toolbar-search-input { flex: 1; min-width: 160px; }
.search-ico { font-size: 14px; opacity: 0.55; }
.pager-controls {
  display: flex;
  align-items: center;
  gap: 6px;
}
.page-cap-select { width: 96px; }
.filter-modal-body { display: grid; gap: 12px; }
.filter-modal-footer { width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.cat-select { width: 110px; }
.size-num { width: 88px; }
.time-filter {
  border: 0;
  padding: 0;
  margin: 10px 0 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.time-filter legend {
  font-size: 12px;
  opacity: 0.78;
  margin-bottom: 2px;
}
.time-quick {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.time-inputs {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.time-inputs :deep(.n-date-picker) { flex: 1; min-width: 150px; }
.time-banner {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>

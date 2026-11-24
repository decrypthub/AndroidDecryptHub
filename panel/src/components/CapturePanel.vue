<script setup lang="ts">
import { computed, reactive, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, belongsToApp, capRemoveWhere, capVisible, capDisplayCap, panelDisplay, toast } from '../store';
import { getCaptures, getExchanges, getCaptureDetail, getDetectSummary, type Cap, perfMs } from '../api';
import { catClass, cryptoView, rowLens, fmtTime, CATLABEL, type CatKey } from '../capview';
import CapDetail from './CapDetail.vue';
import ExchangeDetail from './ExchangeDetail.vue';

const props = defineProps<{ kind: 'crypto' | 'system' | 'net' }>();

interface ExchangePart {
  startLine?: string; headerText?: string; bodyText?: string; bodyBytes?: number;
  bodyHex?: string; binary?: boolean; complete?: boolean; decoded?: boolean;
  contentEncoding?: string; note?: string;
}
interface Exchange {
  id: string; label?: string; status?: string; conn?: string; ts?: number;
  captureIds?: number[]; note?: string; request?: ExchangePart; response?: ExchangePart;
}

const filter = reactive({ q: '', min: null as number | null, max: null as number | null, cat: -2, paused: false, kind: 'all' });
const advOpen = ref(false);
const moreOpen = ref(false);
const sel = ref<number | string | null>(null);
const selDetail = ref<Record<string, unknown> | null>(null);
const selExchange = ref<Exchange | null>(null);
const exchanges = ref<Exchange[]>([]);
const exNotes = ref<string[]>([]);
const scrollTop = ref(0);
const newCount = ref(0);
const radarText = ref('');
let lastShown = 0;

const CATS: Record<string, CatKey[]> = {
  crypto: ['digest', 'hmac', 'sym', 'asym', 'aead'],
  system: ['sys', 'file'],
  net: ['net'],
};
const CAT_BY_SEL: Record<number, CatKey> = { 0: 'digest', 1: 'hmac', 2: 'sym', 3: 'asym', 4: 'aead' };
const SYS_KINDS: Array<[string, string]> = [['all', '全部活动'], ['system', '系统调用'], ['file', '文件读写']];
const LIST_ID: Record<string, string> = { crypto: 'cc-list', system: 'sy-list', net: 'nt-list' };
const PLACEHOLDER: Record<string, [string, string]> = {
  crypto: ['记录详情', '从列表选择一条记录，查看对应的调用详情。'],
  system: ['系统活动详情', '从左侧选择一条系统调用或文件读写记录。'],
  net: ['记录详情', '从列表选择一条记录，查看对应的请求和响应。'],
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

// 本板块归属当前应用的记录（过滤前）
const scoped = computed(() => store.capItems.filter(c => matchesPanel(c) && belongsToApp(c)));

const visible = computed(() => {
  let items = scoped.value.filter(capVisible);
  if (props.kind === 'crypto') items = items.filter(c => cryptoView(c).show !== false);
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
  if (filter.min != null) items = items.filter(c => (c.inl ?? 0) >= filter.min!);
  if (filter.max != null) items = items.filter(c => (c.inl ?? 0) <= filter.max!);
  if (props.kind === 'crypto' && filter.cat >= 0) {
    const want = CAT_BY_SEL[filter.cat];
    items = items.filter(c => catClass(c) === want);
  }
  return items;
});

// ---- 网络板块：重组交换 ----
const rawSkipped = ref(0);
async function loadExchanges() {
  if (props.kind !== 'net' || !store.chosenPkg) { exchanges.value = []; return; }
  const pkg = store.chosenPkg;
  try {
    const r = await getExchanges(pkg) as { exchanges?: Exchange[]; http2Idle?: number; consumedIds?: number[] };
    if (store.chosenPkg !== pkg) return; // 竞态：响应回来时包已换
    const all = r.exchanges ?? [];
    const localIds = new Set(scoped.value.map(c => c.id));
    exchanges.value = all.filter(ex => (ex.captureIds ?? []).some(id => localIds.has(id)));
    const used = new Set([...all.flatMap(ex => ex.captureIds ?? []), ...(r.consumedIds ?? [])]);
    rawSkipped.value = visible.value.filter(c => !used.has(c.id)).length;
    const notes: string[] = [];
    if (r.http2Idle) notes.push(`${r.http2Idle} 条 HTTP/2 连接还没有完整请求`);
    if (rawSkipped.value) notes.push(`${rawSkipped.value} 条 TLS 记录不是 HTTP 请求（连接控制帧或拼不回去），已略过`);
    exNotes.value = notes;
  } catch { /* 保旧数据 */ }
}
let exTimer = 0;
function scheduleExchanges() {
  clearTimeout(exTimer);
  exTimer = window.setTimeout(() => void loadExchanges(), 250);
}

const matchedExchanges = computed(() => {
  if (props.kind !== 'net') return [];
  const q = filter.q.trim().toLowerCase();
  return exchanges.value.filter(ex => {
    if (q) {
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
  }).sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0));
});

const rows = computed(() => props.kind === 'net' ? [] : visible.value.slice(-capDisplayCap.value).reverse());

// 新记录横幅：暂停或滚离顶部时累计
watch(rows, () => {
  if (filter.paused || scrollTop.value > 48) newCount.value += rows.value.length - lastShown;
  else newCount.value = 0;
  lastShown = rows.value.length;
});

const countText = computed(() => {
  const n = props.kind === 'net' ? matchedExchanges.value.length : rows.value.length;
  const ms = perfMs(`GET /api/${props.kind === 'net' ? 'http/exchanges' : 'captures'}`);
  return `${n} 条${ms ? ` · ${Math.round(ms)}ms` : ''}`;
});

async function selectRow(c: Cap) {
  sel.value = c.id; selExchange.value = null;
  selDetail.value = { _loading: true };
  try {
    const d = await getCaptureDetail(c.id);
    if (sel.value === c.id) selDetail.value = d;
  } catch {
    if (sel.value === c.id) selDetail.value = { _error: '读取详情失败', cap: c };
  }
}
function selectExchange(ex: Exchange) {
  sel.value = ex.id; selDetail.value = null; selExchange.value = ex;
}
function closeDetail() { sel.value = null; selDetail.value = null; selExchange.value = null; }

function onScroll(e: Event) {
  scrollTop.value = (e.target as HTMLElement).scrollTop;
  if (scrollTop.value <= 48) newCount.value = 0;
}
function jumpLatest() { filter.paused = false; scrollTop.value = 0; newCount.value = 0; const el = document.getElementById(LIST_ID[props.kind]); el?.scrollTo({ top: 0 }); }

// ---- 筛选徽标：只算高级筛选项（搜索词在框里可见）----
const advCount = computed(() => {
  let n = 0;
  if (filter.min != null || filter.max != null) n++;
  if (props.kind === 'crypto' && filter.cat >= 0) n++;
  if (props.kind === 'system' && filter.kind !== 'all') n++;
  return n;
});
const filterActive = computed(() => !!(filter.q.trim() || advCount.value));
function resetFilter() {
  filter.q = ''; filter.min = null; filter.max = null; filter.cat = -2; filter.kind = 'all';
}
function downloadView() {
  moreOpen.value = false;
  const items = props.kind === 'net' ? matchedExchanges.value : rows.value;
  const pkg = store.chosenPkg || 'all';
  const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `adh-${props.kind}-${pkg}-filtered.json`;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  toast(`已下载 ${items.length} 条`);
}
function clearView() {
  moreOpen.value = false;
  const pkg = store.chosenPkg;
  if (!confirm(`清空本页列表？（不删磁盘）\n${pkg ? '当前应用 ' + pkg : '全部应用'}`)) return;
  const n = capRemoveWhere(c => matchesPanel(c) && belongsToApp(c));
  closeDetail();
  toast(`已清空本页 ${n} 条`);
}

// 弹层外部点击关闭
function onDocClick(e: MouseEvent) {
  if (!(e.target as HTMLElement).closest('.filter-wrap')) advOpen.value = false;
  if (!(e.target as HTMLElement).closest('.menu-wrap.more')) moreOpen.value = false;
}

// ---- 系统板块：检测摘要（对齐旧 sy-radar）----
async function loadRadar() {
  if (props.kind !== 'system' || !store.chosenPkg) { radarText.value = ''; return; }
  try {
    const r = await getDetectSummary(store.chosenPkg) as {
      armed?: boolean; kinds?: Array<{ label: string; count: number }>;
    };
    if (r.armed === false) { radarText.value = '系统检测：未开'; return; }
    if (r.armed == null) { radarText.value = '系统检测：摘要未上报'; return; }
    const hit = (r.kinds ?? []).filter(k => (k.count ?? 0) > 0).map(k => `${k.label} ${k.count}`);
    radarText.value = '系统检测：' + (hit.length ? `已开 · ${hit.join(' · ')}` : '已开 · 暂无');
  } catch { radarText.value = '系统检测：摘要读取失败'; }
}

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
  if (props.kind === 'system') void loadRadar();
  document.addEventListener('click', onDocClick);
  poll = window.setInterval(() => { if (props.kind === 'net') scheduleExchanges(); }, 5000);
});
onUnmounted(() => {
  clearInterval(poll);
  document.removeEventListener('click', onDocClick);
});
watch(() => store.chosenPkg, () => {
  sel.value = null; selDetail.value = null; selExchange.value = null;
  void loadExchanges(); void loadRadar();
});
watch(() => store.capItems.length, () => { if (props.kind === 'net') scheduleExchanges(); });

const emptyText = computed(() => {
  if (!store.chosenPkg) return '先在顶部选择应用。';
  if (props.kind === 'net')
    return exchanges.value.length ? '没有符合筛选条件的网络记录。' :
      scoped.value.length ? `有 ${scoped.value.length} 条 TLS，尚未拼成 HTTP。` : '还没有网络记录。';
  if (props.kind === 'crypto') return '还没有加解密记录。';
  return '还没有系统事件。';
});
const listFootLeft = computed(() =>
  filter.paused ? '已暂停刷新' : (store.wsState === 'live' ? '列表刷新中' : '等待连接'));

function cryptoRow(c: Cap) {
  const v = cryptoView(c);
  return { ...v, cc: catClass(c) };
}
const searchPlaceholder = computed(() =>
  props.kind === 'crypto' ? '搜索 #序号、算法、Hook 或预览' : '搜索 #序号、操作、Hook 或预览');
</script>

<template>
  <div class="cap-view">
    <div class="filters">
      <div class="toolbar-main">
        <div class="toolbar-search">
          <label class="search-field">
            <svg viewBox="0 0 20 20"><circle cx="8.5" cy="8.5" r="5" /><path d="m12.2 12.2 4.2 4.2" /></svg>
            <input v-model="filter.q" type="search" :placeholder="searchPlaceholder" />
          </label>
          <div class="menu-wrap filter-wrap">
            <button type="button" class="filter-toggle" :aria-expanded="advOpen" @click="advOpen = !advOpen">
              筛选<span class="filter-badge">{{ advCount || '' }}</span>
              <span class="menu-chevron"><svg viewBox="0 0 12 12" width="10" height="10" fill="none"
                  stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M2.5 4.5l3.5 3.5 3.5-3.5" /></svg></span>
            </button>
            <section class="advanced-filters" :hidden="!advOpen">
              <div class="advanced-filter-head">
                <strong>事件筛选</strong>
                <button type="button" :disabled="!filterActive" @click="resetFilter">重置筛选</button>
              </div>
              <fieldset v-if="kind === 'system'" class="system-filter">
                <legend>活动类型</legend>
                <div class="system-kinds">
                  <button v-for="[k, l] in SYS_KINDS" :key="k" type="button"
                    :aria-pressed="filter.kind === k" @click="filter.kind = k">{{ l }}</button>
                </div>
                <p v-if="radarText" class="detect-radar">{{ radarText }}</p>
              </fieldset>
              <label v-if="kind === 'crypto'" class="filter-field">分类
                <select v-model.number="filter.cat">
                  <option :value="-2">全部</option>
                  <option :value="0">摘要</option><option :value="1">HMAC</option>
                  <option :value="2">对称</option><option :value="3">非对称</option>
                  <option :value="4">AEAD</option>
                </select>
              </label>
              <div class="size-filter">
                <label>输入大小</label>
                <input v-model.number="filter.min" type="number" min="0" step="1" placeholder="0" />
                <span class="sep">—</span>
                <input v-model.number="filter.max" type="number" min="0" step="1" placeholder="不限" />
                <span class="unit">B</span>
              </div>
            </section>
          </div>
        </div>
        <div class="toolbar-actions">
          <span id="count">{{ countText }}</span>
          <button type="button" class="pause-btn" :class="{ 'is-paused': filter.paused }"
            :title="filter.paused ? '恢复列表刷新' : '只停列表刷新'"
            @click="filter.paused = !filter.paused">{{ filter.paused ? '继续' : '暂停刷新' }}</button>
          <div class="menu-wrap more">
            <button type="button" class="icon-button" :aria-expanded="moreOpen" title="更多"
              @click="moreOpen = !moreOpen">⋯</button>
            <div class="popover menu-popover" :class="{ show: moreOpen }">
              <button type="button" title="当前筛选（内存）" @click="downloadView">下载本页</button>
              <button type="button" class="menu-danger" title="不删磁盘" @click="clearView">清空本页</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="workspace capture-workspace" :class="{ 'compact-captures': panelDisplay.density === 'compact', 'detail-open': sel !== null }">
      <div class="list-pane" :style="listWidth ? { width: listWidth + 'px' } : undefined">
        <div class="new-banner" :class="{ show: newCount > 0 }">
          <span>{{ newCount }} 条新记录</span>
          <button type="button" @click="jumpLatest">跳到最新</button>
        </div>

        <div class="cap-list" :id="LIST_ID[kind]" tabindex="0" @scroll="onScroll">
          <div v-if="!store.capComplete || store.capDropped" class="dump-callout" style="margin:8px 12px">
            环形缓冲有丢弃（dropped={{ store.capDropped }}），列表可能不完整。
          </div>
          <div v-for="n in exNotes" :key="n" class="ex-note">{{ n }}</div>
          <template v-if="kind === 'net'">
            <div v-for="ex in matchedExchanges" :key="ex.id" class="row cat-net" :class="{ selected: sel === ex.id }"
              @click="selectExchange(ex)">
              <div class="top">
                <span class="pill net">网络</span>
                <span class="algo">{{ ex.label }}</span>
                <span v-if="ex.status" class="op">{{ ex.status }}</span>
                <span class="ts">{{ fmtTime(ex.ts) }}</span>
              </div>
              <div class="lens">{{ ex.response?.startLine || ex.request?.startLine || ex.note }}</div>
            </div>
            <div v-if="!matchedExchanges.length" class="empty">{{ emptyText }}</div>
          </template>

          <template v-else>
            <div v-for="c in rows" :key="c.id" class="row"
              :class="[`cat-${catClass(c)}`, { selected: sel === c.id, 'crypto-row': c.category === 'crypto' }]"
              @click="selectRow(c)">
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
            <div v-if="!rows.length" class="empty">{{ emptyText }}</div>
          </template>
        </div>
        <div class="capture-list-foot"><span>{{ listFootLeft }}</span><span>最新优先</span></div>
      </div>

      <div class="splitter" :class="{ dragging }" @mousedown="startDrag"></div>

      <section class="capture-detail-shell">
        <div class="capture-detail-nav">
          <button type="button" class="compact-action" @click="closeDetail">‹ 返回列表</button>
        </div>
        <div class="detail-pane">
          <ExchangeDetail v-if="selExchange" :ex="selExchange" />
          <CapDetail v-else-if="selDetail" :detail="selDetail" />
          <div v-else class="detail-empty">
            <strong>{{ PLACEHOLDER[kind][0] }}</strong><span>{{ PLACEHOLDER[kind][1] }}</span>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.cap-list { outline: none; }
</style>

<script setup lang="ts">
import { computed, reactive, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, belongsToApp, capRemoveWhere, capVisible, capDisplayCap, panelDisplay, toast } from '../store';
import { getCaptures, getExchanges, getCaptureDetail, type Cap, perfMs } from '../api';
import { catClass, cryptoView, rowLens, httpListPreview, fmtTime, CATLABEL, type CatKey } from '../capview';
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
const sel = ref<number | string | null>(null);
const selDetail = ref<Record<string, unknown> | null>(null);
const selExchange = ref<Exchange | null>(null);
const exchanges = ref<Exchange[]>([]);
const exNotes = ref<string[]>([]);
const loadedMs = ref(0);
const scrollTop = ref(0);
const newCount = ref(0);
let lastShown = 0;

const CATS: Record<string, CatKey[]> = {
  crypto: ['digest', 'hmac', 'sym', 'asym', 'aead'],
  system: ['sys', 'file'],
  net: ['net'],
};
const CAT_BY_SEL: Record<number, CatKey> = { 0: 'digest', 1: 'hmac', 2: 'sym', 3: 'asym', 4: 'aead' };
const KIND_LABELS: Record<string, string> = { all: '系统调用或文件读写', system: '系统调用', file: '文件读写' };

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

// crypto 板块只显示有实体的（clientCryptoView.show）
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
const rawSkipped = ref(0);
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
function jumpLatest() { filter.paused = false; scrollTop.value = 0; newCount.value = 0; }

const filterActive = computed(() => !!(filter.q.trim() || filter.min != null || filter.max != null ||
  (props.kind === 'crypto' && filter.cat >= 0) || (props.kind === 'system' && filter.kind !== 'all')));
function resetFilter() {
  filter.q = ''; filter.min = null; filter.max = null; filter.cat = -2; filter.kind = 'all';
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
  closeDetail();
  toast(`已清空本页 ${n} 条`);
}

let poll = 0;
onMounted(() => {
  if (props.kind === 'net') void loadExchanges();
  poll = window.setInterval(() => { if (props.kind === 'net') scheduleExchanges(); }, 5000);
});
onUnmounted(() => clearInterval(poll));
watch(() => store.chosenPkg, () => { sel.value = null; selDetail.value = null; selExchange.value = null; void loadExchanges(); });
watch(() => store.capItems.length, () => { if (props.kind === 'net') scheduleExchanges(); });

const emptyText = computed(() => {
  if (!store.chosenPkg) return '先在顶部选择应用。';
  if (props.kind === 'net')
    return exchanges.value.length ? '没有符合筛选条件的网络记录。' :
      scoped.value.length ? `有 ${scoped.value.length} 条 TLS，尚未拼成 HTTP。` : '还没有网络记录。';
  if (props.kind === 'crypto') return '还没有加解密记录。';
  return '还没有系统事件。';
});

function cryptoRow(c: Cap) {
  const v = cryptoView(c);
  return { ...v, cc: catClass(c) };
}
</script>

<template>
  <div class="cap-panel" :class="{ 'detail-open': sel !== null }">
    <div class="cap-list-wrap">
      <div class="cap-toolbar">
        <input v-model="filter.q" class="cap-search" placeholder="搜索 / #id" />
        <select v-if="kind === 'crypto'" v-model.number="filter.cat" class="cap-cat">
          <option :value="-2">全部类别</option>
          <option :value="0">摘要</option><option :value="1">HMAC</option><option :value="2">对称</option>
          <option :value="3">非对称</option><option :value="4">AEAD</option>
        </select>
        <select v-if="kind === 'system'" v-model="filter.kind" class="cap-cat">
          <option v-for="(l, k) in KIND_LABELS" :key="k" :value="k">{{ l }}</option>
        </select>
        <span class="size-filter">
          <input v-model.number="filter.min" type="number" placeholder="min" /> <span class="sep">~</span>
          <input v-model.number="filter.max" type="number" placeholder="max" /> <span class="unit">B</span>
        </span>
        <button class="btn sm" :class="{ on: filter.paused }" @click="filter.paused = !filter.paused">
          {{ filter.paused ? '继续' : '暂停' }}
        </button>
        <button class="btn sm" :disabled="!filterActive" @click="resetFilter">重置筛选</button>
        <button class="btn sm" @click="downloadView">下载本页</button>
        <button class="btn sm danger" @click="clearView">清空本页</button>
        <span class="cap-count muted">{{ countText }}</span>
      </div>

      <div v-if="!store.capComplete || store.capDropped" class="cap-warn">
        环形缓冲有丢弃（dropped={{ store.capDropped }}），列表可能不完整。
      </div>
      <div v-for="n in exNotes" :key="n" class="ex-note">{{ n }}</div>

      <div class="cap-list" :class="{ compact: panelDisplay.density === 'compact' }" @scroll="onScroll">
        <div v-if="newCount > 0" class="new-banner show" @click="jumpLatest">{{ newCount }} 条新记录</div>

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
          <div v-for="c in rows" :key="c.id" class="row" :class="[`cat-${catClass(c)}`, { selected: sel === c.id, 'crypto-row': c.category === 'crypto' }]"
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
              <div v-if="c.preview && c.category !== 'net' && c.category !== 'file' && c.category !== 'system'" class="preview">{{ c.preview }}</div>
            </template>
          </div>
          <div v-if="!rows.length" class="empty">{{ emptyText }}</div>
        </template>
      </div>
    </div>

    <div class="cap-detail" v-if="sel !== null">
      <button class="btn sm detail-back" @click="closeDetail">‹ 返回</button>
      <ExchangeDetail v-if="selExchange" :ex="selExchange" />
      <CapDetail v-else-if="selDetail" :detail="selDetail" />
    </div>
  </div>
</template>

<style scoped>
.cap-panel { display: flex; min-height: 0; flex: 1; }
.cap-list-wrap { flex: 1; display: flex; flex-direction: column; min-width: 0; }
.detail-open .cap-list-wrap { flex: 0 0 42%; border-right: 1px solid var(--line-soft); }
.cap-toolbar { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--line-soft); flex-wrap: wrap; }
.cap-search { flex: 1; min-width: 140px; }
.cap-count { margin-left: auto; font-size: 12px; }
.cap-warn { padding: 6px 14px; color: var(--amber); font-size: 12px; }
.ex-note { padding: 4px 14px; color: var(--muted); font-size: 12px; }
.cap-list { flex: 1; overflow: auto; position: relative; }
.cap-list.compact :deep(.row) { min-height: 0; padding: 5px 12px; }
.cap-list.compact :deep(.row .subline) { margin-top: 2px; }
.new-banner { position: sticky; top: 8px; z-index: 5; margin: 8px auto; width: fit-content; padding: 5px 14px; background: var(--blue); color: #061020; border-radius: 999px; font-size: 12px; cursor: pointer; display: none; }
.new-banner.show { display: block; }
.cap-detail { flex: 1; min-width: 0; overflow: auto; padding: 12px 16px; }
.detail-back { margin-bottom: 10px; }
.empty { padding: 28px; color: var(--muted); text-align: center; }
</style>

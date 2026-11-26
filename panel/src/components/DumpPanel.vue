<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, liveSession } from '../store';
import { unpackRun, unpackInventory, unpackHistory, getDumpEvents, unpackPullSo, unpackDumpSoOne, dumpDownloadUrl, moduleWatch } from '../api';
import type { ModuleLoadRec } from '../api';
import { fmtSize, fmtTime } from '../capview';

const tab = ref<'records' | 'loaded' | 'pkg'>('records');
const status = ref('');
const running = ref(false);

interface SoItem { name?: string; path?: string; base?: string; size?: number; savedSize?: number; sha256?: string }
const loaded = ref<SoItem[]>([]);
const packaged = ref<SoItem[]>([]);
const invError = ref('');
const records = ref<Array<Record<string, unknown>>>([]);
const history = ref<Array<Record<string, unknown>>>([]);
const invMs = ref(0);

// ---- so 加载监视（dlopen / android_dlopen_ext） ----
const watching = ref(false);
const watchInstalled = ref(false);
const watchBusy = ref(false);
const loadEvents = ref<ModuleLoadRec[]>([]);

async function refreshWatch() {
  if (!sid.value) { watching.value = false; loadEvents.value = []; return; }
  try {
    const [st, li] = await Promise.all([
      moduleWatch(sid.value, 'status'),
      moduleWatch(sid.value, 'list', 200),
    ]);
    watching.value = st.watching === true;
    watchInstalled.value = st.installed === true;
    const mods = (li.modules ?? []).filter(m => !m.unparsed);
    mods.sort((a, b) => (b.at ?? 0) - (a.at ?? 0));
    loadEvents.value = mods;
  } catch { /* 保旧 */ }
}
async function toggleWatch() {
  if (!sid.value || watchBusy.value) return;
  watchBusy.value = true;
  try {
    const r = await moduleWatch(sid.value, watching.value ? 'stop' : 'start');
    if (r.error) status.value = `监视失败：${r.error}`;
    watching.value = r.watching === true;
    watchInstalled.value = r.installed === true;
    void refreshWatch();
  } catch { status.value = '监视请求失败。'; }
  watchBusy.value = false;
}

const sid = computed(() => liveSession.value?.sessionId ?? '');

async function refreshInventory() {
  if (!sid.value) { loaded.value = []; packaged.value = []; invError.value = '没有在线会话。'; return; }
  const t0 = performance.now();
  try {
    const r = await unpackInventory(sid.value);
    invMs.value = performance.now() - t0;
    if (r.error) { invError.value = r.error; return; }
    loaded.value = r.loaded ?? [];
    packaged.value = r.packaged ?? [];
    invError.value = '';
  } catch {
    invError.value = 'SO 清单读取失败。';
  }
}
async function refreshRecords() {
  if (!store.chosenPkg) { records.value = []; history.value = []; return; }
  try {
    const [ev, hi] = await Promise.all([getDumpEvents(store.chosenPkg), unpackHistory(store.chosenPkg)]);
    records.value = (ev.events ?? ev.items ?? []).map(e => ((e as { data?: Record<string, unknown> }).data ?? e));
    history.value = hi.runs ?? hi.records ?? hi.items ?? [];
  } catch { /* 保旧 */ }
}

// ---- 脱壳记录：run 与独立转储产物合并成可下载行 ----
interface RecRow {
  key: string; at: number; kind: string; label: string; sub?: string;
  size?: number; sha?: string; name?: string;
}
interface UnpackRunFile { sha256?: string; name?: string; size?: number; carrier?: boolean }
interface UnpackRun {
  runId?: string; capturedAt?: number; dexCount?: number; size?: number; processes?: number;
  bundleSha256?: string; files?: UnpackRunFile[];
}
const base = (p?: string) => (p ?? '').split(/[\\/]/).pop() ?? '';

const recRows = computed<RecRow[]>(() => {
  const rows: RecRow[] = [];
  const inRuns = new Set<string>();
  for (const r of history.value as unknown as UnpackRun[]) {
    const runId = r.runId ?? '';
    const at = r.capturedAt ?? 0;
    const files = r.files ?? [];
    for (const f of files) if (f.sha256) inRuns.add(f.sha256);
    if (r.bundleSha256) {
      inRuns.add(r.bundleSha256);
      const names = files.map(f => base(f.name)).filter(Boolean);
      rows.push({
        key: `run_${runId}`, at, kind: '脱壳包',
        label: `${r.dexCount ?? files.length} 个 DEX${r.processes ? ` · ${r.processes} 进程` : ''}`,
        sub: names.length ? `${names.slice(0, 2).join('、')}${names.length > 2 ? ` 等 ${names.length} 个文件` : ''}` : undefined,
        size: r.size, sha: r.bundleSha256,
        name: `${store.chosenPkg || 'unpack'}-${runId}-bundle.zip`,
      });
    } else {
      for (const f of files) {
        rows.push({
          key: `runf_${f.sha256}`, at, kind: 'DEX',
          label: base(f.name) || `${(f.sha256 ?? '').slice(0, 8)}.dex`,
          sub: runId ? `脱壳 ${runId}` : undefined,
          size: f.size, sha: f.sha256, name: base(f.name) || undefined,
        });
      }
    }
  }
  for (const r of records.value) {
    const sha = String(r.sha256 ?? '');
    const tag = String(r.tag ?? '');
    if (!sha || inRuns.has(sha) || tag === 'unpack-dex' || tag === 'unpack-bundle') continue;
    const kind = String(r.kind ?? '');
    const label = String(r.note ?? '') || base(String(r.path ?? '')) || `${sha.slice(0, 8)}`;
    rows.push({
      key: `ev_${sha}`, at: Number(r.capturedAt ?? r.ts ?? 0) || 0,
      kind: kind === 'so' ? 'SO' : kind === 'dex' ? 'DEX' : kind === 'zip' ? 'ZIP' : (kind || '转储').toUpperCase(),
      label, size: Number(r.size) || undefined, sha,
      name: `${sha.slice(0, 12)}.${kind || 'bin'}`,
    });
  }
  rows.sort((a, b) => b.at - a.at);
  return rows;
});

async function run() {
  if (!store.chosenPkg || running.value) return;
  running.value = true;
  status.value = '正在脱壳…';
  try {
    const r = await unpackRun(store.chosenPkg);
    running.value = false;
    status.value = r.ok === false ? (r.error ?? '脱壳失败') : `脱壳完成：${r.included?.length ?? 0} 个 DEX 已打包。`;
  } catch {
    status.value = '脱壳请求未确认，结果以脱壳记录为准。';
    running.value = false;
  }
}
async function pullSo(item: SoItem) {
  if (!item.path) return;
  status.value = `正在提取 ${item.name || item.path}…`;
  try {
    const r = await unpackPullSo(store.chosenPkg, item.path) as { saved?: boolean; error?: string };
    status.value = r?.saved === false ? (r.error ?? '提取失败') : `已提取 ${item.name || item.path}`;
    void refreshInventory();
  } catch { status.value = '提取失败。'; }
}
async function dumpOne(item: SoItem) {
  if (!item.name || !item.base || !sid.value) return;
  status.value = `正在转储 ${item.name}…`;
  try {
    const r = await unpackDumpSoOne(sid.value, item.base, item.name) as { saved?: boolean; error?: string };
    status.value = r?.saved === false ? (r.error ?? '转储失败') : `已转储 ${item.name}`;
    void refreshInventory();
  } catch { status.value = '转储失败。'; }
}

function onDumpNew(ev?: Event) {
  void refreshRecords(); void refreshInventory();
  const d = (ev as CustomEvent | undefined)?.detail as Record<string, unknown> | undefined;
  if (!d || typeof d.runId !== 'string') return;
  if (typeof d.dexCount === 'number') {
    status.value = `脱壳完成：${d.dexCount} 个 DEX 已打包。`;
    running.value = false;
  } else if (d.ok === false && d.error) {
    status.value = `脱壳失败：${String(d.error)}`;
    running.value = false;
  }
}
let poll = 0;
onMounted(() => {
  void refreshRecords(); void refreshInventory(); void refreshWatch();
  window.addEventListener('adh:dump-new', onDumpNew);
  window.addEventListener('adh:unpack-done', onDumpNew);
  poll = window.setInterval(() => { void refreshInventory(); if (watching.value) void refreshWatch(); }, 10000);
});
onUnmounted(() => {
  window.removeEventListener('adh:dump-new', onDumpNew);
  window.removeEventListener('adh:unpack-done', onDumpNew);
  clearInterval(poll);
});
watch(() => store.chosenPkg, () => { void refreshRecords(); void refreshInventory(); });
watch(sid, () => { void refreshInventory(); void refreshWatch(); });
</script>

<template>
  <div class="dumppane">
    <div class="dumpwrap">
      <div v-if="invError" class="dump-callout">{{ invError }}</div>
      <div class="dump-actions">
        <button type="button" class="primary" :disabled="running || !store.chosenPkg" @click="run">一键脱壳</button>
        <button type="button" @click="refreshRecords(); refreshInventory(); refreshWatch()">刷新</button>
        <span class="muted">{{ status || (invMs ? `SO 清单 ${Math.round(invMs)}ms` : '') }}</span>
      </div>
      <div class="dump-subtabs system-kinds">
        <button type="button" :aria-pressed="tab === 'records'" @click="tab = 'records'">脱壳记录</button>
        <button type="button" :aria-pressed="tab === 'loaded'" @click="tab = 'loaded'">已加载 SO</button>
        <button type="button" :aria-pressed="tab === 'pkg'" @click="tab = 'pkg'">包内 / 私有目录 SO</button>
      </div>

      <section v-if="tab === 'records'" class="dump-col">
        <table class="dump-table">
          <thead><tr><th>时间</th><th>类型</th><th>产物</th><th class="dump-size">大小</th><th></th></tr></thead>
          <tbody>
            <tr v-for="r in recRows" :key="r.key">
              <td class="dump-time">{{ fmtTime(r.at) }}</td>
              <td><span class="rec-kind" :data-k="r.kind">{{ r.kind }}</span></td>
              <td class="dump-path full" :title="r.sub ? `${r.label} · ${r.sub}` : r.label">
                {{ r.label }}<span v-if="r.sub" class="muted rec-sub">{{ r.sub }}</span>
              </td>
              <td class="dump-size">{{ fmtSize(r.size) }}</td>
              <td><a v-if="r.sha" :href="dumpDownloadUrl(r.sha, r.name)" class="dl-link">下载</a><span v-else
                  class="muted">—</span></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!recRows.length" class="empty">还没有脱壳记录。</div>
      </section>

      <section v-else-if="tab === 'loaded'" class="dump-col">
        <div class="watch-bar">
          <button type="button" class="compact-action" :disabled="watchBusy || !sid" @click="toggleWatch">
            {{ watching ? '停止监视' : '监视 so 加载' }}
          </button>
          <span class="muted watch-state" :class="{ on: watching }">
            {{ watching ? `监视中 · 已记录 ${loadEvents.length} 次加载` : '未监视' }}
          </span>
        </div>
        <table v-if="watching || loadEvents.length" class="dump-table watch-events">
          <thead><tr><th>时间</th><th>路径</th><th>基址</th><th class="dump-size">大小</th></tr></thead>
          <tbody>
            <tr v-for="(e, i) in loadEvents" :key="e.captureId ?? i">
              <td class="dump-time">{{ fmtTime(e.at) }}</td>
              <td class="dump-path full" :title="e.path">{{ e.path }}</td>
              <td class="mono muted">{{ e.base || '—' }}</td>
              <td class="dump-size">{{ fmtSize(e.size) }}</td>
            </tr>
          </tbody>
        </table>
        <table class="dump-table">
          <thead><tr><th>状态</th><th>模块</th><th class="dump-size">大小</th><th></th><th></th></tr></thead>
          <tbody>
            <tr v-for="m in loaded" :key="m.path ?? m.name">
              <td><span :class="m.sha256 ? 'dump-status ok' : 'muted'">{{ m.sha256 ? '已导出' : '内存中' }}</span></td>
              <td class="dump-path full" :title="m.path ?? m.name">
                {{ m.name }}<span v-if="m.path && m.path !== m.name" class="muted rec-sub">{{ m.path }}</span>
              </td>
              <td class="dump-size">{{ fmtSize(m.savedSize ?? m.size) }}</td>
              <td><a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256, m.name)" class="dl-link">下载</a><span v-else
                  class="muted">—</span></td>
              <td><button v-if="!m.sha256" type="button" class="compact-action" @click="dumpOne(m)">转储</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!loaded.length" class="empty">没有已加载的应用 SO。</div>
      </section>

      <section v-else class="dump-col">
        <table class="dump-table pkg-so">
          <thead><tr><th>文件</th><th class="dump-size">大小</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="m in packaged" :key="m.path ?? m.name">
              <td class="dump-path full" :title="m.path">
                {{ m.name || base(m.path) }}<span v-if="m.path" class="muted rec-sub">{{ m.path }}</span>
              </td>
              <td class="dump-size">{{ fmtSize(m.size) }}</td>
              <td>
                <a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256, m.name || base(m.path))" class="dl-link">下载</a>
                <button v-else type="button" class="compact-action" @click="pullSo(m)">提取</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="!packaged.length" class="empty">包内没有 SO。</div>
      </section>
    </div>
  </div>
</template>

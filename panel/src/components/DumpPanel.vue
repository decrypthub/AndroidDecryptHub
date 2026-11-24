<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, liveSession } from '../store';
import { unpackRun, unpackInventory, unpackHistory, getDumpEvents, unpackPullSo, unpackDumpSoOne, dumpDownloadUrl, perfMs } from '../api';
import { fmtSize, fmtTime } from '../capview';

const tab = ref<'records' | 'loaded' | 'pkg'>('records');
const status = ref('');
const running = ref(false);

interface SoItem { name?: string; path?: string; size?: number; savedSize?: number; sha256?: string }
const loaded = ref<SoItem[]>([]);
const packaged = ref<SoItem[]>([]);
const invError = ref('');
const records = ref<Array<Record<string, unknown>>>([]);
const history = ref<Array<Record<string, unknown>>>([]);
const invMs = ref(0);

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
    records.value = ev.items ?? [];
    history.value = hi.items ?? [];
  } catch { /* 保旧 */ }
}
async function run() {
  if (!store.chosenPkg || running.value) return;
  running.value = true;
  status.value = '正在脱壳…';
  try {
    const r = await unpackRun(store.chosenPkg);
    status.value = r.ok === false ? (r.error ?? '脱壳失败') : '已提交脱壳任务。';
  } catch { status.value = '脱壳请求失败。'; }
  running.value = false;
}
async function pullSo(item: SoItem) {
  if (!item.path) return;
  status.value = `正在提取 ${item.name || item.path}…`;
  try {
    const r = await unpackPullSo(store.chosenPkg, item.path) as { ok?: boolean; error?: string };
    status.value = r?.ok === false ? (r.error ?? '提取失败') : `已提取 ${item.name || item.path}`;
    void refreshInventory();
  } catch { status.value = '提取失败。'; }
}
async function dumpOne(item: SoItem) {
  if (!item.name) return;
  status.value = `正在转储 ${item.name}…`;
  try {
    const r = await unpackDumpSoOne(store.chosenPkg, item.name) as { ok?: boolean; error?: string };
    status.value = r?.ok === false ? (r.error ?? '转储失败') : `已转储 ${item.name}`;
    void refreshInventory();
  } catch { status.value = '转储失败。'; }
}

function onDumpNew() { void refreshRecords(); void refreshInventory(); }
let poll = 0;
onMounted(() => {
  void refreshRecords(); void refreshInventory();
  window.addEventListener('adh:dump-new', onDumpNew);
  window.addEventListener('adh:unpack-done', onDumpNew);
  poll = window.setInterval(() => { void refreshInventory(); }, 10000);
});
onUnmounted(() => {
  window.removeEventListener('adh:dump-new', onDumpNew);
  window.removeEventListener('adh:unpack-done', onDumpNew);
  clearInterval(poll);
});
watch(() => store.chosenPkg, () => { void refreshRecords(); void refreshInventory(); });
watch(sid, () => void refreshInventory());
</script>

<template>
  <div class="dump-panel">
    <div class="dump-toolbar">
      <div class="dump-tabs">
        <button v-for="[k, l] in [['records', '脱壳记录'], ['loaded', '已加载 SO'], ['pkg', '包内·私有目录 SO']] as const"
          :key="k" class="chip" :class="{ on: tab === k }" @click="tab = k">{{ l }}</button>
      </div>
      <div class="dump-actions">
        <button class="btn sm primary" :disabled="running || !store.chosenPkg" @click="run">一键脱壳</button>
        <button class="btn sm" @click="refreshRecords(); refreshInventory()">刷新</button>
        <span class="muted">{{ status || (invMs ? `SO 清单 ${Math.round(invMs)}ms` : '') }}</span>
      </div>
    </div>

    <div v-if="tab === 'records'" class="dump-body">
      <table class="dump-table">
        <thead><tr><th>时间</th><th>事件</th><th>详情</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in [...records, ...history]" :key="i">
            <td class="mono">{{ fmtTime((r.ts ?? r.time) as number) }}</td>
            <td>{{ (r.type ?? r.event ?? 'dump') as string }}</td>
            <td class="mono rec-detail">{{ JSON.stringify(r).slice(0, 200) }}</td>
          </tr>
        </tbody>
      </table>
      <div v-if="!records.length && !history.length" class="empty">还没有脱壳记录。</div>
    </div>

    <div v-else-if="tab === 'loaded'" class="dump-body">
      <div v-if="invError" class="muted pad">{{ invError }}</div>
      <table v-else class="dump-table">
        <thead><tr><th>状态</th><th>模块</th><th>大小</th><th>下载</th><th></th></tr></thead>
        <tbody>
          <tr v-for="m in loaded" :key="m.name">
            <td :class="m.sha256 ? 'ok-text' : 'muted'">{{ m.sha256 ? '已导出' : '内存中' }}</td>
            <td class="mono" :title="m.name">{{ m.name }}</td>
            <td>{{ fmtSize(m.savedSize ?? m.size) }}</td>
            <td><a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256)" class="dl">下载</a><span v-else class="muted">—</span></td>
            <td><button v-if="!m.sha256" class="btn sm" @click="dumpOne(m)">转储</button></td>
          </tr>
        </tbody>
      </table>
      <div v-if="!invError && !loaded.length" class="empty">没有已加载的应用 SO。</div>
    </div>

    <div v-else class="dump-body">
      <div v-if="invError" class="muted pad">{{ invError }}</div>
      <table v-else class="dump-table">
        <thead><tr><th>路径</th><th>大小</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="m in packaged" :key="m.path ?? m.name">
            <td class="mono" :title="m.path">{{ m.path ?? m.name }}</td>
            <td>{{ fmtSize(m.size) }}</td>
            <td>
              <a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256)" class="dl">下载</a>
              <button v-else class="btn sm" @click="pullSo(m)">提取</button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="!invError && !packaged.length" class="empty">包内没有 SO。</div>
    </div>
  </div>
</template>

<style scoped>
.dump-panel { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.dump-toolbar { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--line-soft); flex-wrap: wrap; }
.dump-tabs { display: flex; gap: 6px; }
.dump-actions { margin-left: auto; display: flex; align-items: center; gap: 8px; }
.dump-body { flex: 1; overflow: auto; padding: 8px 14px; }
.dump-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.dump-table th { text-align: left; color: var(--muted); font-weight: 500; font-size: 12px; padding: 6px 10px 6px 0; border-bottom: 1px solid var(--line-soft); position: sticky; top: 0; background: var(--bg); }
.dump-table td { padding: 7px 10px 7px 0; border-bottom: 1px solid var(--line-soft); color: var(--ink-2); }
.rec-detail { max-width: 480px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: 11px; }
.ok-text { color: var(--green); }
.dl { color: var(--blue); text-decoration: none; }
.dl:hover { text-decoration: underline; }
.empty, .pad { padding: 24px; color: var(--muted); text-align: center; }
</style>

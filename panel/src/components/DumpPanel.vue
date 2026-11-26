<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted } from 'vue';
import { store, liveSession } from '../store';
import { unpackRun, unpackInventory, unpackHistory, getDumpEvents, unpackPullSo, unpackDumpSoOne, dumpDownloadUrl } from '../api';
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
  <div class="dumppane">
    <div class="dumpwrap">
      <h2>脱壳</h2>
      <div v-if="invError" class="dump-callout">{{ invError }}</div>
      <div class="dump-actions">
        <button type="button" class="primary" :disabled="running || !store.chosenPkg" @click="run">一键脱壳</button>
        <button type="button" @click="refreshRecords(); refreshInventory()">刷新</button>
        <span class="muted">{{ status || (invMs ? `SO 清单 ${Math.round(invMs)}ms` : '') }}</span>
      </div>
      <div class="dump-subtabs system-kinds">
        <button type="button" :aria-pressed="tab === 'records'" @click="tab = 'records'">脱壳记录</button>
        <button type="button" :aria-pressed="tab === 'loaded'" @click="tab = 'loaded'">已加载 SO</button>
        <button type="button" :aria-pressed="tab === 'pkg'" @click="tab = 'pkg'">包内 / 私有目录 SO</button>
      </div>

      <section v-if="tab === 'records'" class="dump-col">
        <table class="dump-table">
          <thead><tr><th>时间</th><th>事件</th><th>详情</th></tr></thead>
          <tbody>
            <tr v-for="(r, i) in [...records, ...history]" :key="i">
              <td class="dump-path">{{ fmtTime((r.ts ?? r.time) as number) }}</td>
              <td>{{ (r.type ?? r.event ?? 'dump') as string }}</td>
              <td class="dump-path">{{ JSON.stringify(r).slice(0, 200) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="!records.length && !history.length" class="empty">还没有脱壳记录。</div>
      </section>

      <section v-else-if="tab === 'loaded'" class="dump-col">
        <table class="dump-table">
          <thead><tr><th>状态</th><th>模块</th><th class="dump-size">大小</th><th></th><th></th></tr></thead>
          <tbody>
            <tr v-for="m in loaded" :key="m.name">
              <td><span :class="m.sha256 ? 'dump-status ok' : 'muted'">{{ m.sha256 ? '已导出' : '内存中' }}</span></td>
              <td class="symname" :title="m.name">{{ m.name }}</td>
              <td class="dump-size">{{ fmtSize(m.savedSize ?? m.size) }}</td>
              <td><a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256)" class="dl-link">下载</a><span v-else
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
              <td class="dump-path" :title="m.path">{{ m.path ?? m.name }}</td>
              <td class="dump-size">{{ fmtSize(m.size) }}</td>
              <td>
                <a v-if="m.sha256" :href="dumpDownloadUrl(m.sha256)" class="dl-link">下载</a>
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

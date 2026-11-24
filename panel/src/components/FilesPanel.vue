<script setup lang="ts">
import { computed, ref, watch, onMounted } from 'vue';
import { store, toast } from '../store';
import { fsList, fsRead, type FsEntry, perfMs } from '../api';
import { fmtSize } from '../capview';

const path = ref('');
const pathInput = ref('');
const entries = ref<FsEntry[]>([]);
const limited = ref(false);
const state = ref<'idle' | 'loading' | 'ready' | 'error'>('idle');
const message = ref('');

interface Preview { name: string; text?: string; truncated?: boolean; binary?: boolean; size?: number; message?: string; b64?: string; fullPath?: string }
const preview = ref<Preview | null>(null);

const crumbs = computed(() => {
  const parts = path.value.split('/').filter(Boolean);
  const out: Array<{ name: string; p: string }> = [{ name: '/', p: '' }];
  parts.forEach((n, i) => out.push({ name: n, p: '/' + parts.slice(0, i + 1).join('/') }));
  return out;
});

async function load(p: string) {
  const pkg = store.chosenPkg;
  if (!pkg) { message.value = '先选择应用。'; return; }
  state.value = 'loading';
  const norm = p || `/data/data/${pkg}`;
  try {
    const r = await fsList(pkg, norm);
    if (r.error) { state.value = 'error'; message.value = r.error; return; }
    entries.value = (r.entries ?? []).slice().sort((a, b) =>
      (a.type === 'd' ? 0 : 1) - (b.type === 'd' ? 0 : 1) || a.name.localeCompare(b.name));
    limited.value = !!r.limited;
    path.value = norm;
    pathInput.value = norm;
    preview.value = null;
    state.value = 'ready';
  } catch (e) {
    state.value = 'error';
    message.value = e instanceof Error ? e.message : '读取目录失败';
  }
}
async function openEntry(e: FsEntry) {
  const p = e.path ?? `${path.value}/${e.name}`;
  if (e.type === 'd') { void load(p); return; }
  preview.value = { name: e.name, fullPath: p, message: '正在读取…' };
  try {
    const r = await fsRead(store.chosenPkg, p);
    if (r.error) { preview.value = { name: e.name, fullPath: p, message: r.error }; return; }
    preview.value = {
      name: e.name,
      text: r.text ?? (r.base64 ? `[base64] ${r.base64.slice(0, 4096)}` : undefined),
      truncated: r.truncated, binary: r.binary, size: r.size ?? e.size,
      b64: r.base64, fullPath: p,
      message: r.truncated ? '仅预览前部，未读完整文件。' : `${fmtSize(r.size ?? e.size)}${r.binary ? ' · 二进制' : ''}`,
    };
  } catch {
    preview.value = { name: e.name, fullPath: p, message: '读取失败' };
  }
}
function downloadPreview() {
  const pv = preview.value;
  if (!pv?.b64) return;
  const bin = Uint8Array.from(atob(pv.b64), ch => ch.charCodeAt(0));
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bin]));
  a.download = pv.name;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  toast(`已下载 ${pv.name}`);
}
function copyPreview() {
  const t = preview.value?.text;
  if (t == null) return;
  void navigator.clipboard?.writeText(t).then(() => toast('已复制'), () => toast('复制失败'));
}
function go(p: string) { void load(p); }
function submitPath() { void load(pathInput.value.trim()); }

const statText = computed(() => {
  const ms = perfMs('GET /api/fs/list');
  if (state.value === 'loading') return '正在读取目录…';
  if (state.value === 'error') return message.value;
  if (!store.chosenPkg) return '先选择应用。';
  if (state.value === 'idle') return '输入路径或点击目录开始浏览。';
  return `${Math.round(ms)}ms · ${entries.value.length} 项${limited.value ? ' · 目录过大已截断' : ''}`;
});
const fmtMtime = (m?: number) => {
  if (!m) return '';
  const ms = m < 1e12 ? m * 1000 : m;
  return new Date(ms).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};

watch(() => store.chosenPkg, () => { path.value = ''; entries.value = []; preview.value = null; state.value = 'idle'; void load(''); });
onMounted(() => { if (store.chosenPkg) void load(''); });
</script>

<template>
  <section class="app-directory">
    <div class="app-directory-inner">
      <p v-if="!store.chosenPkg" class="directory-unavailable">选择注入范围里的应用后浏览它的私有目录。</p>
      <div v-else class="directory-workspace">
        <aside class="directory-list">
          <div class="directory-list-head">
            <div class="directory-pane-head">
              <h3>目录</h3>
              <button type="button" class="compact-action" @click="load(path)">刷新</button>
            </div>
            <input v-model="pathInput" class="directory-root mono" placeholder="/data/data/<pkg>"
              @keyup.enter="submitPath" />
            <nav class="directory-path">
              <template v-for="(c, i) in crumbs" :key="c.p || 'root'">
                <button type="button" class="directory-crumb" :aria-current="i === crumbs.length - 1 ? 'page' : undefined"
                  @click="go(c.p)">{{ c.name }}</button>
              </template>
            </nav>
            <p class="set-status">{{ statText }}</p>
          </div>
          <div class="directory-rows">
            <table class="directory-list-table">
              <thead>
                <tr><th>名称</th><th>大小</th><th>修改时间</th></tr>
              </thead>
              <tbody>
                <tr v-if="path && path !== '/'" @click="go(path.replace(/\/[^/]*$/, '') || '/')">
                  <td colspan="3"><button type="button" class="directory-entry" data-directory="true">..</button></td>
                </tr>
                <tr v-for="e in entries" :key="e.name" :class="{ selected: preview?.fullPath === e.path }"
                  @click="openEntry(e)">
                  <td><button type="button" class="directory-entry" :data-directory="e.type === 'd'">
                      {{ e.name }}{{ e.type === 'd' ? '/' : '' }}</button></td>
                  <td>{{ e.type === 'd' ? '' : fmtSize(e.size) }}</td>
                  <td class="muted">{{ fmtMtime(e.mtime) }}</td>
                </tr>
              </tbody>
            </table>
            <div v-if="state === 'ready' && !entries.length" class="empty">空目录。</div>
          </div>
        </aside>
        <section class="directory-preview">
          <div class="directory-pane-head">
            <h3>{{ preview?.name || '文件内容' }}</h3>
            <div class="directory-preview-actions">
              <span class="directory-readonly">只读</span>
              <button type="button" class="compact-action" :disabled="!preview?.b64" @click="downloadPreview">下载</button>
              <button type="button" class="compact-action" :disabled="preview?.text == null" @click="copyPreview">复制</button>
            </div>
          </div>
          <p class="set-status">{{ preview?.message || (preview ? '' : '从左侧选择一个文件。') }}</p>
          <pre v-if="preview?.text != null">{{ preview.text }}</pre>
        </section>
      </div>
    </div>
  </section>
</template>

<style scoped>
.directory-rows tbody tr { cursor: pointer; }
.directory-rows tbody tr td { font-size: 12px; }
</style>

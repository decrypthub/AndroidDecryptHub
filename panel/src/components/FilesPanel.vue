<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { store } from '../store';
import { fsList, fsRead, type FsEntry, perfMs } from '../api';
import { fmtSize } from '../capview';

const path = ref('');
const pathInput = ref('');
const entries = ref<FsEntry[]>([]);
const limited = ref(false);
const state = ref<'idle' | 'loading' | 'ready' | 'error'>('idle');
const message = ref('');

interface Preview { name: string; text?: string; truncated?: boolean; binary?: boolean; size?: number; message?: string }
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
  preview.value = { name: e.name, message: '正在读取…' };
  try {
    const r = await fsRead(store.chosenPkg, p);
    if (r.error) { preview.value = { name: e.name, message: r.error }; return; }
    preview.value = {
      name: e.name,
      text: r.text ?? (r.base64 ? `[base64] ${r.base64.slice(0, 4096)}` : undefined),
      truncated: r.truncated, binary: r.binary, size: r.size ?? e.size,
      message: r.truncated ? '仅预览前部，未读完整文件。' : `${fmtSize(r.size ?? e.size)}${r.binary ? ' · 二进制' : ''}`,
    };
  } catch (err) {
    preview.value = { name: e.name, message: '读取失败' };
  }
}
function go(p: string) { void load(p); }
function submitPath() { void load(pathInput.value.trim()); }

const statText = computed(() => {
  const ms = perfMs('GET /api/fs/list');
  if (state.value === 'loading') return '正在读取目录…';
  if (state.value === 'error') return message.value;
  if (!store.chosenPkg) return '先选择应用。';
  return `${Math.round(ms)}ms · ${entries.value.length} 项${limited.value ? ' · 目录过大已截断' : ''}`;
});

watch(() => store.chosenPkg, () => { path.value = ''; entries.value = []; preview.value = null; state.value = 'idle'; void load(''); });
</script>

<template>
  <div class="files-panel">
    <div class="files-head">
      <input v-model="pathInput" class="path-input mono" placeholder="/data/data/<pkg>" @keyup.enter="submitPath" />
      <button class="btn sm" @click="submitPath">前往</button>
      <button class="btn sm" @click="load(path)">刷新</button>
      <span class="muted fs-state">{{ statText }}</span>
    </div>

    <div class="crumbs">
      <template v-for="(c, i) in crumbs" :key="c.p">
        <span v-if="i" class="crumb-sep">/</span>
        <button class="crumb" @click="go(c.p)">{{ c.name }}</button>
      </template>
    </div>

    <div class="files-body">
      <div class="files-list">
        <button v-if="path" class="files-row" @click="go(path.replace(/\/[^/]*$/, ''))">
          <span class="name">..</span>
        </button>
        <button v-for="e in entries" :key="e.name" class="files-row" :class="{ dir: e.type === 'd' }" @click="openEntry(e)">
          <span class="fname">{{ e.name }}<span v-if="e.type === 'd'" class="muted">/</span></span>
          <span class="fsize muted">{{ e.type === 'd' ? '' : fmtSize(e.size) }}</span>
        </button>
        <div v-if="state === 'ready' && !entries.length" class="empty">空目录。</div>
      </div>

      <div v-if="preview" class="files-preview">
        <div class="files-preview-head">
          <span class="path mono">{{ preview.name }}</span>
          <span class="muted">{{ preview.message }}</span>
          <button class="btn sm" @click="preview = null">✕</button>
        </div>
        <pre v-if="preview.text != null" class="preview-text mono">{{ preview.text }}</pre>
      </div>
    </div>
  </div>
</template>

<style scoped>
.files-panel { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.files-head { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--line-soft); }
.path-input { flex: 1; }
.fs-state { font-size: 12px; }
.crumbs { display: flex; align-items: center; flex-wrap: wrap; gap: 2px; padding: 6px 14px; font-size: 12px; border-bottom: 1px solid var(--line-soft); }
.crumb { border: 0; background: none; color: var(--blue); cursor: pointer; padding: 2px 3px; border-radius: 4px; }
.crumb:hover { background: var(--surface-2); }
.crumb-sep { color: var(--muted); }
.files-body { flex: 1; display: flex; min-height: 0; }
.files-list { flex: 1; overflow: auto; padding: 6px; }
.files-row { display: flex; align-items: center; gap: 10px; width: 100%; padding: 7px 10px; border: 0; background: none; border-radius: 7px; color: var(--ink-2); cursor: pointer; text-align: left; font-size: 13px; }
.files-row:hover { background: var(--surface-2); }
.fname { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, monospace; font-size: 12.5px; }
.dir .fname { color: var(--blue); }
.fsize { font-size: 11px; font-variant-numeric: tabular-nums; }
.files-preview { flex: 0 0 46%; border-left: 1px solid var(--line-soft); display: flex; flex-direction: column; min-width: 0; }
.files-preview-head { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--line-soft); }
.files-preview-head .path { flex: 1; font-size: 12px; word-break: break-all; }
.preview-text { flex: 1; overflow: auto; margin: 0; padding: 12px 14px; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
.empty { padding: 24px; color: var(--muted); text-align: center; }
</style>

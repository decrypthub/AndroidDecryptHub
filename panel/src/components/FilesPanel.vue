<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch, type Component } from 'vue';
import {
  AlertCircleOutline,
  ArchiveOutline,
  ArrowUpOutline,
  ChevronDownOutline,
  ChevronUpOutline,
  CopyOutline,
  CubeOutline,
  DocumentOutline,
  DocumentTextOutline,
  DownloadOutline,
  FolderOpenOutline,
  FolderOutline,
  ImageOutline,
  KeyOutline,
  LinkOutline,
  OpenOutline,
  RefreshOutline,
  SearchOutline,
} from '@vicons/ionicons5';
import { store, toast } from '../store';
import { fsList, fsRead, type FsEntry, perfMs } from '../api';
import { fmtSize } from '../capview';

type SortKey = 'name' | 'size' | 'mtime';
type PreviewMode = 'text' | 'hex';
type EntryKind = 'dir' | 'link' | 'text' | 'image' | 'key' | 'db' | 'binary' | 'file';

interface Preview {
  name: string;
  text?: string;
  truncated?: boolean;
  binary?: boolean;
  size?: number;
  fsize?: number;
  message?: string;
  b64?: string;
  bytes?: Uint8Array;
  fullPath?: string;
  loading?: boolean;
  error?: boolean;
}

const path = ref('');
const pathInput = ref('');
const entries = ref<FsEntry[]>([]);
const limited = ref(false);
const state = ref<'idle' | 'loading' | 'ready' | 'error'>('idle');
const message = ref('');
const filter = ref('');
const sortKey = ref<SortKey>('name');
const sortDir = ref<1 | -1>(1);
const preview = shallowRef<Preview | null>(null);
const previewMode = ref<PreviewMode>('text');

let listSeq = 0;
let readSeq = 0;
const collator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' });
const utf8 = new TextDecoder('utf-8');

const sandboxRoot = computed(() => store.chosenPkg ? `/data/data/${store.chosenPkg}` : '');


const parentPath = computed(() => {
  if (!path.value || path.value === '/' || path.value === sandboxRoot.value) return '';
  const clean = path.value.replace(/\/+$/, '');
  return clean.replace(/\/[^/]+$/, '') || '/';
});

const filteredEntries = computed(() => {
  const q = filter.value.trim().toLowerCase();
  const list = (q ? entries.value.filter(e => e.name.toLowerCase().includes(q)) : entries.value).slice();
  return list.sort((a, b) => {
    const rank = (a.type === 'd' ? 0 : 1) - (b.type === 'd' ? 0 : 1);
    if (rank) return rank;
    let cmp = 0;
    if (sortKey.value === 'name') cmp = collator.compare(a.name, b.name);
    else if (sortKey.value === 'size') cmp = (a.size ?? 0) - (b.size ?? 0);
    else cmp = (a.mtime ?? 0) - (b.mtime ?? 0);
    return cmp * sortDir.value || collator.compare(a.name, b.name);
  });
});

const dirCount = computed(() => entries.value.filter(e => e.type === 'd').length);
const fileCount = computed(() => entries.value.length - dirCount.value);
const countText = computed(() => `${dirCount.value} 个目录 · ${fileCount.value} 个文件`);
const statText = computed(() => {
  const ms = perfMs('GET /api/fs/list');
  if (state.value === 'loading') return '正在读取目录';
  if (state.value === 'error') return message.value;
  if (!store.chosenPkg) return '未选择应用';
  if (state.value === 'idle') return '等待读取';
  return `${countText.value} · ${Math.round(ms)}ms${limited.value ? ' · 已截断' : ''}`;
});

function joinPath(parent: string, name: string) {
  const base = parent.replace(/\/+$/, '');
  return `${base}/${name}` || '/';
}

function entryPath(e: FsEntry) {
  return e.path || joinPath(path.value, e.name);
}

function extension(name: string) {
  if (!name.includes('.') || name.startsWith('.') && name.indexOf('.') === name.lastIndexOf('.')) return '';
  return name.split('.').pop()?.toLowerCase() ?? '';
}

function entryKind(e: FsEntry): EntryKind {
  if (e.type === 'd') return 'dir';
  if (e.type === 'l') return 'link';
  const ext = extension(e.name);
  if (['png', 'jpg', 'jpeg', 'webp', 'gif', 'bmp', 'svg'].includes(ext)) return 'image';
  if (['key', 'pem', 'crt', 'cer', 'der', 'p12', 'pfx', 'keystore', 'jks'].includes(ext)) return 'key';
  if (['db', 'sqlite', 'sqlite3', 'realm'].includes(ext)) return 'db';
  if (['txt', 'log', 'xml', 'json', 'js', 'ts', 'java', 'kt', 'c', 'h', 'cc', 'cpp', 'md', 'properties', 'conf', 'cfg', 'ini', 'yaml', 'yml', 'html', 'css', 'sh', 'proto'].includes(ext)) return 'text';
  if (['so', 'dex', 'odex', 'vdex', 'apk', 'aar', 'jar', 'bin', 'dat', 'elf'].includes(ext)) return 'binary';
  return 'file';
}

function iconFor(e: FsEntry): Component {
  const kind = entryKind(e);
  if (kind === 'dir') return FolderOutline;
  if (kind === 'link') return LinkOutline;
  if (kind === 'text') return DocumentTextOutline;
  if (kind === 'image') return ImageOutline;
  if (kind === 'key') return KeyOutline;
  if (kind === 'db') return ArchiveOutline;
  if (kind === 'binary') return CubeOutline;
  return DocumentOutline;
}

function kindLabel(e: FsEntry) {
  const kind = entryKind(e);
  if (kind === 'dir') return '目录';
  if (kind === 'link') return '链接';
  if (kind === 'text') return '文本';
  if (kind === 'image') return '图片';
  if (kind === 'key') return '证书';
  if (kind === 'db') return '数据库';
  if (kind === 'binary') return '二进制';
  return '文件';
}

function modeText(e: FsEntry) {
  if (e.mode == null || !Number.isFinite(Number(e.mode))) return '';
  const m = Number(e.mode);
  const chars: string[] = [];
  for (const shift of [6, 3, 0]) {
    const bits = (m >> shift) & 7;
    chars.push(bits & 4 ? 'r' : '-', bits & 2 ? 'w' : '-', bits & 1 ? 'x' : '-');
  }
  if (m & 0o4000) chars[2] = m & 0o100 ? 's' : 'S';
  if (m & 0o2000) chars[5] = m & 0o010 ? 's' : 'S';
  if (m & 0o1000) chars[8] = m & 0o001 ? 't' : 'T';
  const type = e.type === 'd' ? 'd' : e.type === 'l' ? 'l' : '-';
  return type + chars.join('');
}

function modeTitle(e: FsEntry) {
  if (e.mode == null || !Number.isFinite(Number(e.mode))) return '权限未知';
  const octal = (Number(e.mode) & 0o7777).toString(8).padStart(4, '0');
  return `${modeText(e)} · ${octal}`;
}

async function load(p: string) {
  const pkg = store.chosenPkg;
  if (!pkg) { message.value = '先选择应用。'; return; }
  const token = ++listSeq;
  state.value = 'loading';
  message.value = '';
  const norm = (p || sandboxRoot.value).trim() || sandboxRoot.value;
  try {
    const r = await fsList(pkg, norm);
    if (token !== listSeq) return;
    if (r.error) {
      state.value = 'error';
      message.value = r.error;
      return;
    }
    entries.value = (r.entries ?? []).map(e => ({ ...e, path: e.path || joinPath(norm, e.name) }));
    limited.value = !!r.limited;
    path.value = norm;
    pathInput.value = norm;
    filter.value = '';
    preview.value = null;
    state.value = 'ready';
  } catch (e) {
    if (token !== listSeq) return;
    state.value = 'error';
    message.value = e instanceof Error ? e.message : '读取目录失败';
  }
}

function decodeBase64(b64: string) {
  try {
    return Uint8Array.from(atob(b64), ch => ch.charCodeAt(0));
  } catch {
    throw new Error('文件字节不是有效的 base64');
  }
}

function detectBinary(bytes: Uint8Array) {
  const len = Math.min(bytes.length, 4096);
  if (!len) return false;
  let control = 0;
  for (let i = 0; i < len; i++) {
    const b = bytes[i];
    if (b === 0) return true;
    if (b < 32 && b !== 9 && b !== 10 && b !== 13) control++;
  }
  return control / len > 0.08;
}

async function openEntry(e: FsEntry) {
  const p = entryPath(e);
  if (e.type === 'd') { void load(p); return; }
  const token = ++readSeq;
  preview.value = { name: e.name, fullPath: p, loading: true, message: '正在读取文件' };
  try {
    const r = await fsRead(store.chosenPkg, p);
    if (token !== readSeq) return;
    if (r.error) {
      preview.value = { name: e.name, fullPath: p, error: true, message: r.error };
      return;
    }
    const b64 = r.b64 ?? r.base64 ?? '';
    const bytes = decodeBase64(b64);
    const binary = r.binary ?? detectBinary(bytes);
    const text = r.text ?? utf8.decode(bytes);
    previewMode.value = binary ? 'hex' : 'text';
    preview.value = {
      name: e.name,
      text,
      truncated: r.truncated,
      binary,
      size: r.size ?? e.size,
      fsize: r.fsize,
      b64,
      bytes,
      fullPath: p,
      message: r.truncated ? '只读到文件前部' : undefined,
    };
  } catch (err) {
    if (token !== readSeq) return;
    preview.value = {
      name: e.name,
      fullPath: p,
      error: true,
      message: err instanceof Error ? err.message : '读取失败',
    };
  }
}

function hexDump(bytes: Uint8Array, maxBytes = 32768) {
  const len = Math.min(bytes.length, maxBytes);
  const lines: string[] = [];
  for (let off = 0; off < len; off += 16) {
    const slice = bytes.subarray(off, Math.min(off + 16, len));
    const hex = Array.from(slice, b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = Array.from(slice, b => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.').join('');
    lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
  }
  if (bytes.length > len) lines.push(`… 已省略 ${fmtSize(bytes.length - len)}，下载可取得本次读取的完整内容`);
  return lines.join('\n');
}

const previewText = computed(() => {
  const pv = preview.value;
  if (!pv) return '';
  if (pv.text != null) return pv.text;
  return pv.bytes ? utf8.decode(pv.bytes) : '';
});
const previewHex = computed(() => preview.value?.bytes ? hexDump(preview.value.bytes) : '');
const currentPreviewContent = computed(() => previewMode.value === 'hex' ? previewHex.value : previewText.value);
const canDownload = computed(() => typeof preview.value?.b64 === 'string' && !preview.value.loading && !preview.value.error);
const canCopy = computed(() => !!currentPreviewContent.value && !preview.value?.loading && !preview.value?.error);
const previewSizeText = computed(() => {
  const pv = preview.value;
  if (!pv) return '';
  const full = pv.fsize ?? pv.size;
  if (pv.truncated && pv.size != null && full != null) return `${fmtSize(full)} · 已读 ${fmtSize(pv.size)}`;
  return fmtSize(full);
});
const previewTypeText = computed(() => {
  const pv = preview.value;
  if (!pv) return '';
  return pv.binary ? '二进制' : '文本';
});

function downloadPreview() {
  const pv = preview.value;
  if (!pv || typeof pv.b64 !== 'string') return;
  const bytes = pv.bytes ?? decodeBase64(pv.b64);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([bytes]));
  a.download = pv.name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
  toast(`已下载 ${pv.name}`);
}

function copyPreview() {
  const text = currentPreviewContent.value;
  if (!text) return;
  void navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败'));
}

function toggleSort(key: SortKey) {
  if (sortKey.value === key) sortDir.value = sortDir.value === 1 ? -1 : 1;
  else {
    sortKey.value = key;
    sortDir.value = key === 'name' ? 1 : -1;
  }
}

function sortIcon(key: SortKey) {
  if (sortKey.value !== key) return null;
  return sortDir.value === 1 ? ChevronUpOutline : ChevronDownOutline;
}

function retryLoad() {
  void load(pathInput.value.trim() || path.value);
}
function go(p: string) { void load(p); }
function goUp() { if (parentPath.value) void load(parentPath.value); }
function submitPath() { void load(pathInput.value.trim()); }

const fmtMtime = (m?: number) => {
  if (!m) return '';
  const ms = m < 1e12 ? m * 1000 : m;
  return new Date(ms).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
};

watch(() => store.chosenPkg, () => {
  path.value = '';
  pathInput.value = '';
  entries.value = [];
  preview.value = null;
  filter.value = '';
  state.value = 'idle';
  void load('');
});
onMounted(() => { if (store.chosenPkg) void load(''); });
</script>

<template>
  <section class="fs-board">
    <div v-if="!store.chosenPkg" class="fs-unavailable">
      <n-icon size="34" :component="FolderOpenOutline" />
      <strong>选择一个应用后浏览文件</strong>
    </div>

    <div v-else class="fs-shell">
      <header class="fs-toolbar">
        <div class="fs-path-control">
          <button type="button" class="fs-icon-btn" title="上一级" aria-label="上一级" :disabled="!parentPath" @click="goUp">
            <n-icon size="17" :component="ArrowUpOutline" />
          </button>
          <input v-model="pathInput" class="fs-path-input mono" placeholder="/data/data/<pkg>" aria-label="文件路径"
            @keyup.enter="submitPath" />
          <button type="button" class="fs-command-btn" title="打开路径" aria-label="打开路径" @click="submitPath">
            <n-icon size="16" :component="OpenOutline" />
            <span>打开</span>
          </button>
          <button type="button" class="fs-command-btn" title="刷新目录" aria-label="刷新目录" @click="load(path)">
            <n-icon size="16" :component="RefreshOutline" />
            <span>刷新</span>
          </button>
        </div>
        <label class="fs-filter">
          <n-icon size="15" :component="SearchOutline" />
          <input v-model="filter" type="search" placeholder="筛选当前目录" aria-label="筛选当前目录" />
        </label>
        <span class="fs-list-stat" :title="statText">{{ statText }}</span>
      </header>

      <div class="fs-split" :class="{ 'with-preview': !!preview }">
        <aside class="fs-list-pane">
          <div class="fs-column-head" aria-label="排序方式">
            <button type="button" @click="toggleSort('name')">
              <span>名称</span><n-icon v-if="sortIcon('name')" size="12" :component="sortIcon('name')" />
            </button>
            <button type="button" @click="toggleSort('size')">
              <span>大小</span><n-icon v-if="sortIcon('size')" size="12" :component="sortIcon('size')" />
            </button>
            <span class="fs-static-head">权限</span>
            <button type="button" class="fs-time-head" @click="toggleSort('mtime')">
              <span>修改时间</span><n-icon v-if="sortIcon('mtime')" size="12" :component="sortIcon('mtime')" />
            </button>
          </div>

          <!-- 读取目录时不铺骨架：保留上一屏内容，只把光标切成加载态（见 .fs-rows.loading）。 -->
          <div class="fs-rows" :class="{ loading: state === 'loading' }" :aria-busy="state === 'loading'">
            <button v-if="parentPath && state === 'ready'" type="button" class="fs-row fs-parent" @click="goUp">
              <span class="fs-file">
                <span class="fs-kind dir"><n-icon size="17" :component="ArrowUpOutline" /></span>
                <span class="fs-name"><strong>..</strong><small>上一级</small></span>
              </span>
              <span class="fs-size"></span>
              <span class="fs-perm"></span>
              <span class="fs-time"></span>
            </button>

            <button v-for="e in filteredEntries" :key="entryPath(e)" type="button" class="fs-row"
              :class="{ selected: preview?.fullPath === entryPath(e) }" :title="entryPath(e)" @click="openEntry(e)">
              <span class="fs-file">
                <span class="fs-kind" :class="entryKind(e)"><n-icon size="17" :component="iconFor(e)" /></span>
                <span class="fs-name">
                  <strong>{{ e.name }}{{ e.type === 'd' ? '/' : '' }}</strong>
                  <small>{{ kindLabel(e) }}</small>
                </span>
              </span>
              <span class="fs-size">{{ e.type === 'd' ? '' : fmtSize(e.size) }}</span>
              <span class="fs-perm mono" :title="modeTitle(e)">{{ modeText(e) }}</span>
              <span class="fs-time">{{ fmtMtime(e.mtime) }}</span>
            </button>

            <div v-if="state === 'error'" class="fs-state error">
              <n-icon size="28" :component="AlertCircleOutline" />
              <strong>目录读取失败</strong>
              <span>{{ message }}</span>
              <button type="button" @click="retryLoad">重试</button>
            </div>

            <div v-if="state === 'ready' && !filteredEntries.length" class="fs-state">
              <n-icon size="28" :component="FolderOpenOutline" />
              <strong>{{ filter ? '当前目录没有匹配项' : '空目录' }}</strong>
            </div>
          </div>
        </aside>

        <section v-if="preview" class="fs-preview-pane">
          <header class="fs-preview-head">
              <span class="fs-preview-icon" :class="{ binary: preview.binary }">
                <n-icon size="22" :component="preview.binary ? CubeOutline : DocumentTextOutline" />
              </span>
              <div class="fs-preview-id">
                <h3>{{ preview.name }}</h3>
                <p class="mono">{{ preview.fullPath }}</p>
              </div>
              <div class="fs-preview-actions">
                <button type="button" class="fs-action" :disabled="!canDownload" @click="downloadPreview">
                  <n-icon size="15" :component="DownloadOutline" /><span>下载</span>
                </button>
                <button type="button" class="fs-action" :disabled="!canCopy" @click="copyPreview">
                  <n-icon size="15" :component="CopyOutline" /><span>复制</span>
                </button>
              </div>
            </header>

            <div v-if="preview.loading" class="fs-preview-state">
              <span class="fs-spinner"></span>
              <span>正在读取文件</span>
            </div>
            <div v-else-if="preview.error" class="fs-preview-state error">
              <n-icon size="25" :component="AlertCircleOutline" />
              <strong>文件读取失败</strong>
              <span>{{ preview.message }}</span>
            </div>
            <template v-else>
              <div class="fs-preview-meta">
                <span>{{ previewSizeText }}</span>
                <span>{{ previewTypeText }}</span>
                <span v-if="preview.truncated" class="warn">截断</span>
                <span v-if="preview.message">{{ preview.message }}</span>
              </div>
              <div class="fs-viewbar">
                <div class="fs-view-toggle" role="group" aria-label="预览格式">
                  <button type="button" :aria-pressed="previewMode === 'text'" @click="previewMode = 'text'">文本</button>
                  <button type="button" :aria-pressed="previewMode === 'hex'" @click="previewMode = 'hex'">Hex</button>
                </div>
              </div>
              <pre class="fs-content" :class="{ hex: previewMode === 'hex' }">{{ currentPreviewContent }}</pre>
            </template>
        </section>
      </div>
    </div>
  </section>
</template>

<style scoped>
.fs-board { flex: 1; min-width: 0; min-height: 0; display: flex; overflow: auto; padding: 16px; background: var(--bg); }
.fs-unavailable { flex: 1; display: grid; place-content: center; justify-items: center; gap: 10px; color: var(--muted); border: 1px dashed var(--line); border-radius: 12px; background: var(--surface); }
.fs-unavailable strong { color: var(--ink-2); font-size: 14px; font-weight: 600; }
.fs-shell { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; overflow: hidden; border: 1px solid var(--line-soft); border-radius: 12px; background: var(--surface); box-shadow: 0 1px 2px rgba(17, 19, 21, .025); }
.fs-toolbar { display: grid; grid-template-columns: minmax(420px, 1fr) minmax(170px, 250px) auto; gap: 10px; align-items: center; padding: 10px 12px; border-bottom: 1px solid var(--line-soft); background: var(--surface); }
.fs-path-control { display: grid; grid-template-columns: 34px minmax(0, 1fr) auto auto; gap: 7px; align-items: center; min-width: 0; }
.fs-icon-btn, .fs-command-btn, .fs-action { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 34px; border: 1px solid var(--line); border-radius: 6px; color: var(--ink-2); background: var(--surface); cursor: pointer; transition: background .16s ease, border-color .16s ease, color .16s ease, transform .08s ease; }
.fs-icon-btn { width: 34px; padding: 0; }
.fs-command-btn { padding: 0 11px; font-size: 12px; white-space: nowrap; }
.fs-action { padding: 0 10px; font-size: 12px; }
.fs-icon-btn:hover, .fs-command-btn:hover, .fs-action:hover { color: var(--ink); background: var(--surface-2); border-color: var(--muted); }
.fs-icon-btn:active, .fs-command-btn:active, .fs-action:active { transform: translateY(1px); }
.fs-icon-btn:disabled, .fs-action:disabled { opacity: .42; cursor: default; transform: none; }
.fs-path-input { width: 100%; min-width: 0; min-height: 34px; padding: 5px 10px; border: 1px solid var(--line); border-radius: 6px; color: var(--ink); background: var(--bg); font-size: 12px; }
.fs-path-input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); outline-offset: 0; }
.fs-split { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(0, 1fr); }
.fs-split.with-preview { grid-template-columns: minmax(430px, 1.08fr) minmax(0, .92fr); }
.fs-list-pane { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--bg); }
.fs-split.with-preview .fs-list-pane { border-right: 1px solid var(--line-soft); }
.fs-filter { position: relative; display: flex; align-items: center; min-width: 0; color: var(--muted); }
.fs-filter > .n-icon { position: absolute; left: 9px; z-index: 1; }
.fs-filter input { width: 100%; min-width: 0; min-height: 34px; padding: 5px 9px 5px 29px; border: 1px solid var(--line); border-radius: 6px; color: var(--ink); background: var(--bg); font-size: 12px; }
.fs-filter input:focus { border-color: var(--ink); outline: 2px solid rgba(17, 19, 21, .08); }
.fs-list-stat { justify-self: end; max-width: 220px; overflow: hidden; color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; text-overflow: ellipsis; white-space: nowrap; }
.fs-column-head { display: grid; grid-template-columns: minmax(0, 1fr) 68px 102px 106px; gap: 8px; align-items: center; min-height: 34px; padding: 0 12px; border-bottom: 1px solid var(--line-soft); color: var(--muted); background: var(--chrome); font-size: 11px; }
.fs-column-head button { display: inline-flex; align-items: center; gap: 3px; min-width: 0; padding: 0; border: 0; color: inherit; background: transparent; font-size: inherit; font-weight: 600; text-align: left; cursor: pointer; }
.fs-column-head button:first-child { padding-left: 39px; }
.fs-column-head button:nth-child(2), .fs-column-head .fs-time-head { justify-content: flex-end; text-align: right; }
.fs-static-head { overflow: hidden; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.fs-column-head button:hover { color: var(--ink); }
.fs-rows { flex: 1; min-height: 0; overflow: auto; padding: 4px 0; }
.fs-row { display: grid; grid-template-columns: minmax(0, 1fr) 68px 102px 106px; gap: 8px; align-items: center; width: 100%; min-height: 40px; padding: 3px 12px; border: 0; border-bottom: 1px solid var(--line-soft); color: var(--ink); background: transparent; text-align: left; cursor: pointer; transition: background .14s ease, box-shadow .14s ease; }
.fs-row:hover { background: var(--surface-2); }
.fs-row.selected { background: var(--surface-2); box-shadow: inset 2px 0 0 var(--ink); }
.fs-file { display: flex; align-items: center; gap: 9px; min-width: 0; }
.fs-kind { display: inline-grid; width: 30px; height: 30px; place-items: center; flex: none; border-radius: 7px; color: var(--muted); background: var(--surface-2); }
.fs-kind.dir { color: var(--ink); background: var(--surface-3); }
.fs-kind.link { color: var(--cyan); }
.fs-kind.text { color: var(--teal); }
.fs-kind.image { color: var(--lilac); }
.fs-kind.key { color: var(--amber); }
.fs-kind.db { color: var(--coral); }
.fs-kind.binary { color: var(--ink-2); }
.fs-name { display: flex; align-items: baseline; gap: 7px; min-width: 0; }
.fs-name strong { min-width: 0; overflow: hidden; color: var(--ink); font-size: 13px; font-weight: 560; text-overflow: ellipsis; white-space: nowrap; }
.fs-name small { flex: none; color: var(--muted); font-size: 10px; }
.fs-parent .fs-name strong { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.fs-size, .fs-perm, .fs-time { overflow: hidden; color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; text-overflow: ellipsis; white-space: nowrap; }
.fs-size { color: var(--ink-2); text-align: right; }
.fs-perm { color: var(--ink-2); font-size: 10px; letter-spacing: -.015em; }
.fs-time { text-align: right; }
/* 读取中不铺骨架：上一屏的行保持可见，只把列表区光标换成加载态（cursor: progress）。
   这样目录内容不会在每次刷新/切目录时整块闪掉，也不会出现“骨架消失→内容出现”的跳动。 */
.fs-rows.loading { cursor: progress; }
.fs-rows.loading .fs-row { cursor: progress; }
.fs-state { display: grid; place-content: center; justify-items: center; gap: 8px; min-height: 220px; padding: 24px; color: var(--muted); text-align: center; }
.fs-state strong { color: var(--ink-2); font-size: 14px; font-weight: 600; }
.fs-state span { max-width: 420px; overflow-wrap: anywhere; font-size: 12px; line-height: 1.55; }
.fs-state button { min-height: 30px; padding: 0 12px; border: 1px solid var(--line); border-radius: 6px; color: var(--ink-2); background: var(--surface); cursor: pointer; }
.fs-state.error { color: var(--danger); }
.fs-preview-pane { display: flex; flex-direction: column; min-width: 0; min-height: 0; background: var(--surface); }
.fs-preview-head { display: flex; align-items: center; gap: 11px; padding: 14px 16px 12px; border-bottom: 1px solid var(--line-soft); }
.fs-preview-icon { display: grid; width: 42px; height: 42px; place-items: center; flex: none; border-radius: 10px; color: var(--teal); background: var(--surface-2); }
.fs-preview-icon.binary { color: var(--ink); }
.fs-preview-id { min-width: 0; flex: 1; }
.fs-preview-id h3 { margin: 0; overflow: hidden; color: var(--ink); font-size: 16px; font-weight: 650; letter-spacing: -.012em; text-overflow: ellipsis; white-space: nowrap; }
.fs-preview-id p { margin: 3px 0 0; overflow: hidden; color: var(--muted); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.fs-preview-actions { display: flex; gap: 7px; flex: none; }
.fs-preview-meta { display: flex; flex-wrap: wrap; gap: 6px; padding: 10px 16px 0; color: var(--muted); font-size: 11px; }
.fs-preview-meta span { padding: 3px 7px; border: 1px solid var(--line-soft); border-radius: 5px; background: var(--bg); font-variant-numeric: tabular-nums; }
.fs-preview-meta .warn { color: var(--amber); border-color: var(--amber); }
.fs-viewbar { display: flex; justify-content: flex-end; padding: 10px 16px 8px; }
.fs-view-toggle { display: inline-flex; padding: 2px; border: 1px solid var(--line); border-radius: 7px; background: var(--bg); }
.fs-view-toggle button { min-width: 62px; min-height: 27px; padding: 0 10px; border: 0; border-radius: 5px; color: var(--muted); background: transparent; font-size: 12px; cursor: pointer; }
.fs-view-toggle button[aria-pressed="true"] { color: var(--ink); background: var(--surface); box-shadow: 0 1px 3px rgba(17, 19, 21, .12); font-weight: 650; }
.fs-content { flex: 1; min-height: 0; margin: 0 16px 16px; padding: 13px 14px; overflow: auto; border: 1px solid var(--line-soft); border-radius: 8px; color: var(--ink-2); background: var(--bg); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; line-height: 1.68; white-space: pre-wrap; word-break: normal; overflow-wrap: anywhere; }
.fs-content.hex { white-space: pre; overflow-wrap: normal; }
.fs-preview-state { flex: 1; display: grid; place-content: center; justify-items: center; gap: 10px; padding: 30px; color: var(--muted); text-align: center; }
.fs-preview-state strong { color: var(--ink-2); font-size: 14px; font-weight: 600; }
.fs-preview-state.error { color: var(--danger); }
.fs-preview-state span { max-width: 520px; overflow-wrap: anywhere; }
.fs-spinner { width: 22px; height: 22px; border: 2px solid var(--line); border-top-color: var(--ink); border-radius: 50%; animation: fs-spin .8s linear infinite; }
@keyframes fs-spin { to { transform: rotate(360deg); } }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }

@media (max-width: 980px) {
  .fs-toolbar { grid-template-columns: minmax(0, 1fr) minmax(150px, 220px); padding: 9px 10px; }
  .fs-list-stat { display: none; }
  .fs-split.with-preview { grid-template-columns: minmax(350px, 1.04fr) minmax(0, .96fr); }
  .fs-time, .fs-column-head .fs-time-head { display: none; }
  .fs-column-head, .fs-row { grid-template-columns: minmax(0, 1fr) 64px 92px; }
}

@media (max-width: 700px) {
  .fs-board { display: block; padding: 10px; }
  .fs-shell { min-height: calc(100dvh - 96px); }
  .fs-toolbar { grid-template-columns: minmax(0, 1fr); gap: 7px; padding: 8px; }
  .fs-path-control { grid-template-columns: 34px minmax(0, 1fr) 34px 34px; gap: 5px; }
  .fs-command-btn span { display: none; }
  .fs-command-btn { width: 34px; padding: 0; }
  .fs-split { display: flex; flex-direction: column; }
  .fs-list-pane { flex: 0 0 auto; max-height: 45dvh; border-right: 0; border-bottom: 1px solid var(--line-soft); }
  .fs-rows { min-height: 150px; }
  .fs-preview-pane { flex: 1; min-height: 360px; }
  .fs-preview-head { flex-wrap: wrap; }
  .fs-preview-actions { margin-left: auto; }
}

@media (prefers-reduced-motion: reduce) {
  .fs-spinner { animation: none; }
  .fs-icon-btn, .fs-command-btn, .fs-action, .fs-row { transition: none; }
}
</style>

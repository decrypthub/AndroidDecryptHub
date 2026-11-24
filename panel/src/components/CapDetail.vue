<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { Cap } from '../api';
import { deleteCapture } from '../api';
import { catClass, cryptoView, CATLABEL } from '../capview';
import { store, toast } from '../store';

const props = defineProps<{ detail: Record<string, unknown> }>();
const emit = defineEmits<{ deleted: [id: number] }>();
const c = computed(() => props.detail as unknown as Cap & { text?: string; hex?: string; tid?: number; callStack?: string; hasKey?: boolean; source?: string });
type FmtMode = 'auto' | 'utf8' | 'hex' | 'b64' | 'hexdump';
const FMTS: [FmtMode, string][] = [['auto', '自动'], ['utf8', 'UTF-8'], ['hex', 'Hex'], ['b64', 'Base64'], ['hexdump', 'Hexdump']];
const ioTab = ref<'in' | 'out'>('in');
const fmtIn = ref<FmtMode>('auto');
const fmtOut = ref<FmtMode>('auto');
const menuOpen = ref(false);
const confirming = ref(false);
const infoOpen = ref(false);

function hexToBytes(h: string): Uint8Array {
  const clean = h.length % 2 === 0 ? h : h.slice(0, -1);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hexToBase64(h: string): string {
  if (!h) return '';
  const b = hexToBytes(h);
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

function tryUtf8(h?: string): { text: string; readable: boolean } {
  if (!h) return { text: '', readable: false };
  try {
    const bytes = hexToBytes(h);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    let ctrl = 0;
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 32 && code !== 9 && code !== 10 && code !== 13) ctrl++;
    }
    return { text, readable: text.length > 0 && ctrl / text.length < 0.05 };
  } catch {
    return { text: '', readable: false };
  }
}

function hexdump(hexStr: string): string {
  let out = '';
  for (let i = 0; i < hexStr.length; i += 32) {
    const row = hexStr.slice(i, i + 32);
    const off = (i / 2).toString(16).padStart(8, '0');
    let hp = '', ascii = '';
    for (let j = 0; j < row.length; j += 2) {
      const b = parseInt(row.slice(j, j + 2), 16);
      hp += row.slice(j, j + 2) + ' ';
      if (j / 2 === 7) hp += ' ';
      ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
    }
    out += `${off}: ${hp.padEnd(50)} |${ascii}|\n`;
  }
  return out;
}

function resolveMode(mode: FmtMode, rawHex?: string): Exclude<FmtMode, 'auto'> {
  if (mode !== 'auto') return mode;
  return tryUtf8(rawHex).readable ? 'utf8' : 'hexdump';
}

function formatBlock(mode: FmtMode, rawHex?: string, fallbackText?: string): { display: string; copyVal: string; mono: boolean } {
  if (!rawHex) {
    const t = fallbackText || '';
    return { display: t || '（未捕获字节）', copyVal: t, mono: false };
  }
  const m = resolveMode(mode, rawHex);
  if (m === 'hex') return { display: rawHex, copyVal: rawHex, mono: true };
  if (m === 'b64') {
    const b = hexToBase64(rawHex);
    return { display: b, copyVal: b, mono: true };
  }
  if (m === 'utf8') {
    const u = tryUtf8(rawHex);
    if (u.text) return { display: u.text, copyVal: u.text, mono: false };
    const lossy = new TextDecoder('utf-8', { fatal: false }).decode(hexToBytes(rawHex));
    return { display: lossy, copyVal: lossy, mono: false };
  }
  const u = tryUtf8(rawHex);
  return { display: hexdump(rawHex), copyVal: u.readable ? u.text : rawHex, mono: true };
}

function formatKey(mode: FmtMode, rawHex: string): { display: string; copyVal: string } {
  if (mode === 'b64') {
    const b = hexToBase64(rawHex);
    return { display: b, copyVal: b };
  }
  if (mode === 'utf8') {
    const u = tryUtf8(rawHex);
    if (u.readable) return { display: u.text, copyVal: u.text };
  }
  if (mode === 'hex') return { display: rawHex, copyVal: rawHex };
  return { display: hexdump(rawHex), copyVal: rawHex };
}

const isCrypto = computed(() => c.value.category === 'crypto');
const isFile = computed(() => c.value.category === 'file' || c.value.category === 'system');
const isNet = computed(() => c.value.category === 'net');
const cv = computed(() => (isCrypto.value ? cryptoView(c.value) : null));

const inLabel = computed(() => (isNet.value ? (/write/i.test(String(c.value.func || c.value.op || '')) ? '发送' : '接收') : '输入'));
const outLabel = computed(() => (isNet.value ? '响应' : '输出'));
const hasStack = computed(() => !!c.value.callStack);
const hasFileCards = computed(() => isFile.value && !!(c.value.text || c.value.preview || c.value.func || c.value.path));
const hasInBlock = computed(() => !!(c.value.hex || (!isFile.value && c.value.text) || (c.value.inl ?? 0) > 0));
const hasInput = computed(() => hasFileCards.value || hasInBlock.value || !!c.value.keyHex || !!c.value.ivHex);
const hasOutput = computed(() => !!(c.value.outHex || (c.value.outl ?? 0) > 0));
const curHasData = computed(() => (ioTab.value === 'in' ? hasInput.value : hasOutput.value));
const activeFmt = computed(() => (ioTab.value === 'in' ? fmtIn.value : fmtOut.value));
function setFmt(k: FmtMode) { if (ioTab.value === 'in') fmtIn.value = k; else fmtOut.value = k; }
const bytes = (n?: number) => (n == null ? '未记录' : `${n} B`);
const outBytes = computed(() => c.value.outl ?? (c.value.outHex ? c.value.outHex.length / 2 : undefined));

watch(() => c.value.id, () => {
  menuOpen.value = false;
  confirming.value = false;
  infoOpen.value = false;
  ioTab.value = hasInput.value ? 'in' : 'out';
});

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败'));
}
function closeMenu() { menuOpen.value = false; confirming.value = false; }
function toggleInfo() { infoOpen.value = !infoOpen.value; closeMenu(); }
function askDelete() {
  if (!confirming.value) { confirming.value = true; return; }
  void doDelete();
}
async function doDelete() {
  const id = Number(c.value.id);
  closeMenu();
  try {
    const r = await deleteCapture(id, String(c.value.package || store.chosenPkg || '') || undefined);
    if (r?.ok === false) throw new Error(r.error || 'delete failed');
  } catch { toast('删除失败'); return; }
  toast(`已删除记录 #${id}`);
  emit('deleted', id);
}
</script>

<template>
  <div v-if="detail._loading" class="detail-empty"><strong>正在读取记录…</strong></div>
  <div v-else-if="detail._error" class="detail-empty"><strong>{{ detail._error }}</strong></div>
  <template v-else>
    <div class="detail-head">
      <div class="detail-head-main">
        <h2>
          <span class="cat-dot" :class="catClass(c)"></span>
          <template v-if="isCrypto">{{ cv?.title }}<template v-if="cv?.direction"> · {{ cv.direction }}</template></template>
          <template v-else>#{{ c.id }} {{ c.algo || c.func }}</template>
        </h2>
        <div class="sub">
          {{ [cv?.hook, new Date(c.ts).toLocaleString(), c.tid ? `tid ${c.tid}` : '', cv?.truncated ? '输入已截断' : ''].filter(Boolean).join(' · ') }}
        </div>
      </div>
      <div class="detail-menu">
        <button type="button" class="menu-btn" :aria-expanded="menuOpen" title="记录操作"
          @click="menuOpen = !menuOpen; confirming = false">⋯</button>
        <div v-if="menuOpen" class="menu-pop">
          <button type="button" @click="toggleInfo">事件信息</button>
          <button type="button" class="danger" @click="askDelete">{{ confirming ? '确认删除这条记录？' : '删除记录' }}</button>
        </div>
      </div>
    </div>
    <div v-if="menuOpen" class="menu-backdrop" @click="closeMenu"></div>

    <div v-if="infoOpen" class="capture-overview">
      <h3>事件信息</h3>
      <dl class="capture-facts">
        <div><dt>事件编号</dt><dd>#{{ c.id ?? '未记录' }}</dd></div>
        <div><dt>类别</dt><dd>{{ CATLABEL[catClass(c)] }}</dd></div>
        <div><dt>输入大小</dt><dd>{{ bytes(c.inl) }}</dd></div>
        <div><dt>输出大小</dt><dd>{{ bytes(c.outl) }}</dd></div>
        <div><dt>线程 ID</dt><dd>{{ c.tid ? String(c.tid) : '未记录' }}</dd></div>
        <div><dt>时间</dt><dd>{{ new Date(c.ts).toLocaleString() }}</dd></div>
        <div v-if="c.sessionId"><dt>会话</dt><dd class="mono">{{ c.sessionId }}</dd></div>
      </dl>
      <div v-if="hasStack" class="stack-box">
        <pre>{{ c.callStack }}</pre>
        <button type="button" class="blk-copy" title="复制" @click="copy(c.callStack || '')"><svg viewBox="0 0 16 16">
            <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
            <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
      </div>
    </div>

    <div class="io-toolbar">
      <div class="seg">
        <button type="button" :class="{ on: ioTab === 'in' }" @click="ioTab = 'in'">
          {{ inLabel }}<span v-if="c.inl != null" class="seg-meta"> {{ bytes(c.inl) }}</span></button>
        <button type="button" :class="{ on: ioTab === 'out' }" @click="ioTab = 'out'">
          {{ outLabel }}<span v-if="hasOutput" class="seg-meta"> {{ bytes(outBytes) }}</span></button>
      </div>
      <div v-if="curHasData" class="seg seg-fmt">
        <button v-for="[k, lbl] in FMTS" :key="k" type="button"
          :class="{ on: activeFmt === k }" @click="setFmt(k)">{{ lbl }}</button>
      </div>
    </div>

    <div v-if="ioTab === 'in'" class="io-panel">
      <template v-if="hasFileCards">
        <div class="io-field">
          <div class="io-field-label">路径</div>
          <div class="io-data">
            <pre>{{ c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview : '') || '未记录' }}</pre>
            <button type="button" class="blk-copy" title="复制"
              @click="copy(c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview || '' : '') || '')"><svg
                viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
        <div class="io-field">
          <div class="io-field-label">详情</div>
          <div class="io-data">
            <pre>{{ [c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n') }}</pre>
            <button type="button" class="blk-copy" title="复制"
              @click="copy([c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n'))"><svg
                viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>

      <template v-if="c.keyHex">
        <div class="io-field">
          <div class="io-field-label">KEY · {{ c.keyHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.keyHex).display }}</pre>
            <button type="button" class="blk-copy" title="复制" @click="copy(formatKey(fmtIn, c.keyHex).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>
      <template v-if="c.ivHex">
        <div class="io-field">
          <div class="io-field-label">IV · {{ c.ivHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.ivHex).display }}</pre>
            <button type="button" class="blk-copy" title="复制" @click="copy(formatKey(fmtIn, c.ivHex).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>

      <template v-if="hasInBlock">
        <div class="io-data main">
          <pre :class="{ mono: formatBlock(fmtIn, c.hex, c.text).mono }">{{ formatBlock(fmtIn, c.hex, c.text).display }}</pre>
          <button type="button" class="blk-copy" title="复制内容"
            @click="copy(formatBlock(fmtIn, c.hex, c.text).copyVal)"><svg viewBox="0 0 16 16">
              <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
              <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
        </div>
      </template>
      <div v-if="!hasInput" class="detail-empty">这条记录没有输入数据。</div>
    </div>

    <div v-else class="io-panel">
      <template v-if="hasOutput">
        <div class="io-data main">
          <pre :class="{ mono: formatBlock(fmtOut, c.outHex).mono }">{{ formatBlock(fmtOut, c.outHex).display }}</pre>
          <button type="button" class="blk-copy" title="复制内容"
            @click="copy(formatBlock(fmtOut, c.outHex).copyVal)"><svg viewBox="0 0 16 16">
              <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
              <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
        </div>
      </template>
      <div v-else class="detail-empty">这条记录没有输出数据。</div>
    </div>
  </template>
</template>

<style scoped>
.detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}
.detail-head-main { min-width: 0; }
.detail-menu { position: relative; flex: none; }
.menu-btn {
  width: 28px; height: 26px;
  border: 0; border-radius: 6px;
  background: transparent; color: inherit;
  font-size: 16px; line-height: 1;
  cursor: pointer; opacity: 0.7;
}
.menu-btn:hover { opacity: 1; background: rgba(128, 128, 128, 0.14); }
.menu-pop {
  position: absolute; right: 0; top: 30px; z-index: 60;
  min-width: 168px; padding: 4px;
  display: flex; flex-direction: column; gap: 2px;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.3));
  border-radius: 8px;
  background: var(--panel, #1e2128);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
}
.menu-pop button {
  padding: 6px 10px; text-align: left;
  border: 0; border-radius: 5px;
  background: transparent; color: inherit;
  font-size: 13px; cursor: pointer;
}
.menu-pop button:hover { background: rgba(128, 128, 128, 0.14); }
.menu-pop .danger { color: #f87171; }
.menu-backdrop { position: fixed; inset: 0; z-index: 50; }

/* 一条工具栏：输入/输出 段控件 + 格式 段控件 */
.io-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  margin: 14px 0 10px;
}
.seg {
  display: inline-flex;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.3));
  border-radius: 7px;
  overflow: hidden;
}
.seg button {
  padding: 4px 12px;
  border: 0;
  background: transparent;
  color: inherit;
  font-size: 12.5px;
  cursor: pointer;
  opacity: 0.68;
  border-right: 1px solid var(--border, rgba(128, 128, 128, 0.3));
  white-space: nowrap;
}
.seg button:last-child { border-right: 0; }
.seg button.on {
  opacity: 1;
  font-weight: 600;
  background: rgba(59, 130, 246, 0.14);
  color: var(--accent, #6ea8fe);
}
.seg-fmt button { padding: 4px 9px; font-size: 12px; }
.seg-meta { opacity: 0.65; font-weight: 400; font-size: 11px; }

/* 数据区：小标签 + 单线框数据块，不再卡片套卡片 */
.io-panel { display: flex; flex-direction: column; gap: 12px; }
.io-field-label {
  font-size: 11px;
  letter-spacing: 0.04em;
  opacity: 0.55;
  margin-bottom: 4px;
}
.io-data {
  position: relative;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.22));
  border-radius: 8px;
  background: rgba(128, 128, 128, 0.05);
}
.io-data pre {
  margin: 0;
  padding: 10px 12px;
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 46vh;
  overflow: auto;
}
.io-data pre.mono { font-family: ui-monospace, Consolas, 'Cascadia Mono', monospace; }
.blk-copy {
  position: absolute; top: 6px; right: 6px;
  width: 24px; height: 22px;
  border: 0; border-radius: 5px;
  background: transparent; color: inherit;
  cursor: pointer; opacity: 0;
  display: flex; align-items: center; justify-content: center;
}
.io-data:hover .blk-copy, .stack-box:hover .blk-copy { opacity: 0.6; }
.blk-copy:hover { opacity: 1 !important; background: rgba(128, 128, 128, 0.18); }
.blk-copy svg { width: 13px; height: 13px; fill: none; stroke: currentColor; stroke-width: 1.4; }
.stack-box {
  position: relative;
  margin-top: 10px;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.22));
  border-radius: 8px;
  background: rgba(128, 128, 128, 0.05);
}
.stack-box pre { margin: 0; padding: 10px 12px; font-size: 12px; max-height: 34vh; overflow: auto; }
</style>

<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Cap } from '../api';
import { catClass, cryptoView, CATLABEL } from '../capview';
import { toast } from '../store';

const props = defineProps<{ detail: Record<string, unknown> }>();
const c = computed(() => props.detail as unknown as Cap & { text?: string; hex?: string; tid?: number; callStack?: string; hasKey?: boolean; source?: string });
type FmtMode = 'auto' | 'utf8' | 'hex' | 'b64' | 'hexdump';
const view = ref<'data' | 'event' | 'stack'>('data');
const fmt = ref<FmtMode>('auto');

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

function resolveMode(rawHex?: string): Exclude<FmtMode, 'auto'> {
  if (fmt.value !== 'auto') return fmt.value;
  return tryUtf8(rawHex).readable ? 'utf8' : 'hexdump';
}

function formatBlock(rawHex?: string, fallbackText?: string): { display: string; copyVal: string; mono: boolean } {
  if (!rawHex) {
    const t = fallbackText || '';
    return { display: t || '（未捕获字节）', copyVal: t, mono: false };
  }
  const m = resolveMode(rawHex);
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

function formatKey(rawHex: string): { display: string; copyVal: string } {
  if (fmt.value === 'b64') {
    const b = hexToBase64(rawHex);
    return { display: b, copyVal: b };
  }
  if (fmt.value === 'utf8') {
    const u = tryUtf8(rawHex);
    if (u.readable) return { display: u.text, copyVal: u.text };
  }
  if (fmt.value === 'hex') return { display: rawHex, copyVal: rawHex };
  return { display: hexdump(rawHex), copyVal: rawHex };
}

const isCrypto = computed(() => c.value.category === 'crypto');
const isFile = computed(() => c.value.category === 'file' || c.value.category === 'system');
const isNet = computed(() => c.value.category === 'net');
const cv = computed(() => (isCrypto.value ? cryptoView(c.value) : null));

const inLabel = computed(() => (isNet.value ? (/write/i.test(String(c.value.func || c.value.op || '')) ? '发送' : '接收') : '输入'));
const hasStack = computed(() => !!c.value.callStack);
const bytes = (n?: number) => (n == null ? '未记录' : `${n} B`);

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败'));
}
</script>

<template>
  <div v-if="detail._loading" class="detail-empty"><strong>正在读取记录…</strong></div>
  <div v-else-if="detail._error" class="detail-empty"><strong>{{ detail._error }}</strong></div>
  <template v-else>
    <div class="detail-head">
      <h2>
        <span class="cat-dot" :class="catClass(c)"></span>
        <template v-if="isCrypto">{{ cv?.title }}<template v-if="cv?.direction"> · {{ cv.direction }}</template></template>
        <template v-else>#{{ c.id }} {{ c.algo || c.func }}</template>
      </h2>
      <div class="sub">
        {{ [cv?.hook, new Date(c.ts).toLocaleString(), c.tid ? `tid ${c.tid}` : '', cv?.truncated ? '输入已截断' : ''].filter(Boolean).join(' · ') }}
      </div>
    </div>

    <div class="record-tabs">
      <button type="button" :aria-selected="view === 'data'" @click="view = 'data'">数据详情</button>
      <button type="button" :aria-selected="view === 'event'" @click="view = 'event'">事件信息</button>
      <button v-if="hasStack" type="button" :aria-selected="view === 'stack'" @click="view = 'stack'">调用栈</button>
    </div>

    <div v-if="view === 'data'" class="record-tab-panel">
      <div v-if="c.hex || c.outHex || c.keyHex || c.ivHex" class="fmt-bar">
        <button v-for="[k, lbl] in [['auto','自动'],['utf8','UTF-8'],['hex','Hex'],['b64','Base64'],['hexdump','Hexdump']]"
          :key="k" type="button" class="fmt-chip" :class="{ active: fmt === k }" @click="fmt = k as FmtMode">{{ lbl }}</button>
      </div>
      <template v-if="isFile && (c.text || c.preview || c.func || c.path)">
        <div class="io-section kv-card">
          <div class="io-card-head"><span class="io-label kv">路径</span></div>
          <div class="io-block-body">
            <pre>{{ c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview : '') || '未记录' }}</pre>
            <button type="button" class="block-copy" title="复制"
              @click="copy(c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview || '' : '') || '')"><svg
                viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
        <div class="io-section kv-card">
          <div class="io-card-head"><span class="io-label kv">详情</span></div>
          <div class="io-block-body">
            <pre>{{ [c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n') }}</pre>
            <button type="button" class="block-copy" title="复制"
              @click="copy([c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n'))"><svg
                viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>

      <template v-if="c.keyHex">
        <div class="io-section kv-card">
          <div class="io-card-head"><span class="io-label kv">KEY</span><span class="io-meta">{{ c.keyHex.length / 2 }}B</span></div>
          <div class="io-block-body">
            <pre class="hex">{{ formatKey(c.keyHex).display }}</pre>
            <button type="button" class="block-copy" title="复制" @click="copy(formatKey(c.keyHex).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>
      <template v-if="c.ivHex">
        <div class="io-section kv-card">
          <div class="io-card-head"><span class="io-label kv">IV</span><span class="io-meta">{{ c.ivHex.length / 2 }}B</span></div>
          <div class="io-block-body">
            <pre class="hex">{{ formatKey(c.ivHex).display }}</pre>
            <button type="button" class="block-copy" title="复制" @click="copy(formatKey(c.ivHex).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>

      <template v-if="c.hex || (!isFile && c.text) || (c.inl ?? 0) > 0">
        <div class="io-section in-card">
          <div class="io-card-head"><span class="io-label in">{{ inLabel }}</span><span class="io-meta">{{ bytes(c.inl) }}</span></div>
          <div class="io-block-body">
            <pre :class="{ hex: formatBlock(c.hex, c.text).mono }">{{ formatBlock(c.hex, c.text).display }}</pre>
            <button type="button" class="block-copy" title="复制内容"
              @click="copy(formatBlock(c.hex, c.text).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>
      <template v-if="c.outHex || (c.outl ?? 0) > 0">
        <div class="io-section out-card">
          <div class="io-card-head"><span class="io-label out">{{ isNet ? '响应' : '输出' }}</span><span
              class="io-meta">{{ bytes(c.outl ?? (c.outHex ? c.outHex.length / 2 : undefined)) }}</span></div>
          <div class="io-block-body">
            <pre :class="{ hex: formatBlock(c.outHex).mono }">{{ formatBlock(c.outHex).display }}</pre>
            <button type="button" class="block-copy" title="复制内容"
              @click="copy(formatBlock(c.outHex).copyVal)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>
      <div v-if="!isFile && !c.hex && !c.keyHex && !c.outHex && !(c.inl ?? 0) && !c.text" class="detail-empty">
        这条记录没有可显示的数据。
      </div>
    </div>

    <div v-else-if="view === 'event'" class="record-tab-panel">
      <div class="capture-overview">
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
      </div>
    </div>

    <div v-else class="record-tab-panel">
      <div class="io-section kv-card stack-section">
        <div class="io-card-head"><span class="io-label kv">调用栈</span></div>
        <div class="io-block-body">
          <pre>{{ c.callStack }}</pre>
          <button type="button" class="block-copy" title="复制" @click="copy(c.callStack || '')"><svg
              viewBox="0 0 16 16">
              <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
              <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
        </div>
      </div>
    </div>
  </template>
</template>

<style scoped>
.fmt-bar {
  display: flex;
  gap: 6px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.fmt-chip {
  padding: 2px 9px;
  font-size: 12px;
  border-radius: 6px;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.25));
  background: transparent;
  color: inherit;
  opacity: 0.72;
  cursor: pointer;
}
.fmt-chip.active {
  opacity: 1;
  font-weight: 600;
  border-color: var(--accent, #3b82f6);
  background: rgba(59, 130, 246, 0.12);
}
</style>

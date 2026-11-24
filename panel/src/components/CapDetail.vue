<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { Cap } from '../api';
import { deleteCapture } from '../api';
import { catClass, cryptoView, CATLABEL } from '../capview';
import { store, toast } from '../store';
import { CopyOutline } from '@vicons/ionicons5';

const props = defineProps<{ detail: Record<string, unknown> }>();
const emit = defineEmits<{ deleted: [id: number] }>();
const c = computed(() => props.detail as unknown as Cap & { text?: string; hex?: string; tid?: number; callStack?: string; hasKey?: boolean; source?: string });
type FmtMode = 'auto' | 'utf8' | 'hex' | 'b64' | 'hexdump';
const FMTS: [FmtMode, string][] = [['auto', '自动'], ['utf8', 'UTF-8'], ['hex', 'Hex'], ['b64', 'Base64'], ['hexdump', 'Hexdump']];
const ioTab = ref<'in' | 'out'>('in');
const fmtIn = ref<FmtMode>('auto');
const fmtOut = ref<FmtMode>('auto');
const confirmDelete = ref(false);
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
// 数据块语义标签：明文/密文/摘要/MAC/签名值 必须一眼分清，不笼统叫输入输出
const inDataLabel = computed(() => {
  if (!isCrypto.value) return inLabel.value;
  const d = cv.value?.direction;
  if (d === '加密') return '明文';
  if (d === '解密') return '密文';
  if (d === '签名') return '待签数据';
  if (d === '验签') return '待验数据';
  return '输入数据';
});
const outDataLabel = computed(() => {
  if (!isCrypto.value) return outLabel.value;
  const d = cv.value?.direction;
  if (d === '加密') return '密文';
  if (d === '解密') return '明文';
  if (d === '哈希') return '摘要';
  if (d === '认证') return 'MAC';
  if (d === '签名' || d === '验签') return '签名值';
  return '输出数据';
});
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
  confirmDelete.value = false;
  infoOpen.value = false;
  ioTab.value = hasInput.value ? 'in' : 'out';
});

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败'));
}
function onMenuSelect(key: string) {
  if (key === 'info') infoOpen.value = !infoOpen.value;
  else if (key === 'delete') confirmDelete.value = true;
}
async function doDelete() {
  const id = Number(c.value.id);
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
        <n-dropdown trigger="click" :options="[
            { label: '事件信息', key: 'info' },
            { label: '删除记录', key: 'delete', props: { style: 'color:#f87171' } },
          ]" @select="onMenuSelect">
          <n-button quaternary size="small" class="menu-btn" title="记录操作">⋯</n-button>
        </n-dropdown>
        <n-popconfirm v-model:show="confirmDelete" positive-text="删除" negative-text="取消"
          :positive-button-props="{ type: 'error' }" @positive-click="doDelete">
          <template #trigger><span class="pc-anchor"></span></template>
          删除这条捕获记录？磁盘上也会标记删除。
        </n-popconfirm>
      </div>
    </div>

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
        <button type="button" class="blk-copy" title="复制" @click="copy(c.callStack || '')"><n-icon size="16" :component="CopyOutline" /></button>
      </div>
    </div>

    <div class="io-toolbar">
      <n-radio-group v-model:value="ioTab" size="small">
        <n-radio-button value="in">{{ inLabel }}<span v-if="c.inl != null" class="seg-meta"> {{ bytes(c.inl) }}</span></n-radio-button>
        <n-radio-button value="out">{{ outLabel }}<span v-if="hasOutput" class="seg-meta"> {{ bytes(outBytes) }}</span></n-radio-button>
      </n-radio-group>
      <n-radio-group v-if="curHasData" :value="activeFmt" size="small" @update:value="setFmt">
        <n-radio-button v-for="[k, lbl] in FMTS" :key="k" :value="k">{{ lbl }}</n-radio-button>
      </n-radio-group>
    </div>

    <div v-if="ioTab === 'in'" class="io-panel">
      <template v-if="hasFileCards">
        <div class="io-field">
          <div class="io-field-label">路径</div>
          <div class="io-data">
            <pre>{{ c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview : '') || '未记录' }}</pre>
            <button type="button" class="blk-copy" title="复制"
              @click="copy(c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview || '' : '') || '')"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
        </div>
        <div class="io-field">
          <div class="io-field-label">详情</div>
          <div class="io-data">
            <pre>{{ [c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n') }}</pre>
            <button type="button" class="blk-copy" title="复制"
              @click="copy([c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n'))"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
        </div>
      </template>

      <template v-if="c.keyHex">
        <div class="io-field">
          <div class="io-field-label">KEY · {{ c.keyHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.keyHex).display }}</pre>
            <button type="button" class="blk-copy" title="复制" @click="copy(formatKey(fmtIn, c.keyHex).copyVal)"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
        </div>
      </template>
      <template v-if="c.ivHex">
        <div class="io-field">
          <div class="io-field-label">IV · {{ c.ivHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.ivHex).display }}</pre>
            <button type="button" class="blk-copy" title="复制" @click="copy(formatKey(fmtIn, c.ivHex).copyVal)"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
        </div>
      </template>

      <template v-if="hasInBlock">
        <div class="io-field">
          <div class="io-field-label">{{ inDataLabel }} · {{ bytes(c.inl ?? (c.hex ? c.hex.length / 2 : undefined)) }}</div>
          <div class="io-data main">
            <pre :class="{ mono: formatBlock(fmtIn, c.hex, c.text).mono }">{{ formatBlock(fmtIn, c.hex, c.text).display }}</pre>
            <button type="button" class="blk-copy" title="复制内容"
              @click="copy(formatBlock(fmtIn, c.hex, c.text).copyVal)"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
        </div>
      </template>
      <div v-if="!hasInput" class="detail-empty">这条记录没有输入数据。</div>
    </div>

    <div v-else class="io-panel">
      <template v-if="hasOutput">
        <div class="io-field">
          <div class="io-field-label">{{ outDataLabel }} · {{ bytes(outBytes) }}</div>
          <div class="io-data main">
            <pre :class="{ mono: formatBlock(fmtOut, c.outHex).mono }">{{ formatBlock(fmtOut, c.outHex).display }}</pre>
            <button type="button" class="blk-copy" title="复制内容"
              @click="copy(formatBlock(fmtOut, c.outHex).copyVal)"><n-icon size="16" :component="CopyOutline" /></button>
          </div>
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
.pc-anchor { position: absolute; right: 0; top: 28px; }

/* 一条工具栏：输入/输出 段控件 + 格式 段控件 */
.io-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  margin: 14px 0 10px;
}
.seg-meta { opacity: 0.6; font-weight: 400; font-size: 11px; }

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
  width: 30px; height: 28px;
  border: 0; border-radius: 6px;
  background: transparent; color: inherit;
  cursor: pointer; opacity: 0;
  display: flex; align-items: center; justify-content: center;
}
.io-data:hover .blk-copy, .stack-box:hover .blk-copy { opacity: 0.65; }
.blk-copy:hover { opacity: 1 !important; background: rgba(128, 128, 128, 0.18); }
.blk-copy .n-icon { display: flex; align-items: center; }
.stack-box {
  position: relative;
  margin-top: 10px;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.22));
  border-radius: 8px;
  background: rgba(128, 128, 128, 0.05);
}
.stack-box pre { margin: 0; padding: 10px 12px; font-size: 12px; max-height: 34vh; overflow: auto; }
</style>

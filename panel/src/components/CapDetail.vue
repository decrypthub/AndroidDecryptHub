<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Cap } from '../api';
import { catClass, cryptoView, CATLABEL } from '../capview';
import { toast } from '../store';

const props = defineProps<{ detail: Record<string, unknown> }>();
const c = computed(() => props.detail as unknown as Cap & { text?: string; hex?: string; tid?: number; callStack?: string; hasKey?: boolean; source?: string });
const view = ref<'data' | 'event' | 'stack'>('data');

function hexdump(hex: string): string {
  let out = '';
  for (let i = 0; i < hex.length; i += 32) {
    const row = hex.slice(i, i + 32);
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
const hex = (h?: string) => (h ? hexdump(h) : '');

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
            <pre class="hex">{{ hex(c.keyHex) }}</pre>
            <button type="button" class="block-copy" title="复制" @click="copy(c.keyHex)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>
      <template v-if="c.ivHex">
        <div class="io-section kv-card">
          <div class="io-card-head"><span class="io-label kv">IV</span><span class="io-meta">{{ c.ivHex.length / 2 }}B</span></div>
          <div class="io-block-body">
            <pre class="hex">{{ hex(c.ivHex) }}</pre>
            <button type="button" class="block-copy" title="复制" @click="copy(c.ivHex)"><svg viewBox="0 0 16 16">
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
                <path d="M10.5 5.5V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v5A1.5 1.5 0 0 0 4 10.5h1.5" /></svg></button>
          </div>
        </div>
      </template>

      <template v-if="c.hex || (!isFile && c.text) || (c.inl ?? 0) > 0">
        <div class="io-section in-card">
          <div class="io-card-head"><span class="io-label in">{{ inLabel }}</span><span class="io-meta">{{ bytes(c.inl) }}</span></div>
          <div class="io-block-body">
            <pre :class="{ hex: !!c.hex }">{{ c.hex ? hex(c.hex) : c.text || '（未捕获字节）' }}</pre>
            <button type="button" class="block-copy" title="复制"
              @click="copy(c.hex ? hex(c.hex) : c.text || '')"><svg viewBox="0 0 16 16">
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
            <pre :class="{ hex: !!c.outHex }">{{ c.outHex ? hex(c.outHex) : '（未捕获字节）' }}</pre>
            <button type="button" class="block-copy" title="复制"
              @click="copy(c.outHex ? hex(c.outHex) : '')"><svg viewBox="0 0 16 16">
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

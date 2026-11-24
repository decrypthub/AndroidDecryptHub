<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Cap } from '../api';
import { catClass, cryptoView, CATLABEL } from '../capview';

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

    <div class="detail-tabs">
      <button class="chip" :class="{ on: view === 'data' }" @click="view = 'data'">数据详情</button>
      <button class="chip" :class="{ on: view === 'event' }" @click="view = 'event'">事件信息</button>
      <button v-if="hasStack" class="chip" :class="{ on: view === 'stack' }" @click="view = 'stack'">调用栈</button>
    </div>

    <div v-if="view === 'data'" class="detail-body">
      <template v-if="isFile && (c.text || c.preview || c.func || c.path)">
        <div class="kv-label">路径</div>
        <pre class="io-block">{{ c.path || ((c.func === 'open' || c.func === 'openat') ? c.preview : '') || '未记录' }}</pre>
        <div class="kv-label">详情</div>
        <pre class="io-block">{{ [c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n') }}</pre>
      </template>
      <template v-if="c.keyHex">
        <div class="kv-label">KEY · {{ c.keyHex.length / 2 }}B</div>
        <pre class="io-block mono">{{ hex(c.keyHex) }}</pre>
      </template>
      <template v-if="c.ivHex">
        <div class="kv-label">IV · {{ c.ivHex.length / 2 }}B</div>
        <pre class="io-block mono">{{ hex(c.ivHex) }}</pre>
      </template>
      <template v-if="c.hex || (!isFile && c.text) || (c.inl ?? 0) > 0">
        <div class="kv-label">{{ inLabel }} · {{ bytes(c.inl) }}</div>
        <pre class="io-block mono">{{ c.hex ? hex(c.hex) : c.text || '（未捕获字节）' }}</pre>
      </template>
      <template v-if="c.outHex || (c.outl ?? 0) > 0">
        <div class="kv-label">{{ isNet ? '响应' : '输出' }} · {{ bytes(c.outl ?? (c.outHex ? c.outHex.length / 2 : undefined)) }}</div>
        <pre class="io-block mono">{{ c.outHex ? hex(c.outHex) : '（未捕获字节）' }}</pre>
      </template>
      <div v-if="!isFile && !c.hex && !c.keyHex && !c.outHex && !(c.inl ?? 0) && !c.text" class="detail-empty">
        这条记录没有可显示的数据。
      </div>
    </div>

    <div v-else-if="view === 'event'" class="detail-body">
      <table class="kv-table">
        <tr><td>事件编号</td><td>#{{ c.id ?? '未记录' }}</td></tr>
        <tr><td>类别</td><td>{{ CATLABEL[catClass(c)] }}</td></tr>
        <tr><td>输入大小</td><td>{{ bytes(c.inl) }}</td></tr>
        <tr><td>输出大小</td><td>{{ bytes(c.outl) }}</td></tr>
        <tr><td>线程 ID</td><td>{{ c.tid ? String(c.tid) : '未记录' }}</td></tr>
        <tr><td>时间</td><td>{{ new Date(c.ts).toLocaleString() }}</td></tr>
        <tr v-if="c.sessionId"><td>会话</td><td class="mono">{{ c.sessionId }}</td></tr>
      </table>
    </div>

    <div v-else class="detail-body">
      <pre class="io-block mono">{{ c.callStack }}</pre>
    </div>
  </template>
</template>

<style scoped>
.detail-head h2 { margin: 0 0 4px; font-size: 17px; }
.sub { color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.detail-tabs { display: flex; gap: 6px; margin-bottom: 12px; }
.kv-label { color: var(--muted); font-size: 12px; margin: 10px 0 4px; }
.io-block { background: var(--surface-2); border: 1px solid var(--line-soft); border-radius: 8px; padding: 10px; font-size: 12px; white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 40dvh; }
.kv-table { border-collapse: collapse; font-size: 13px; }
.kv-table td { padding: 5px 14px 5px 0; color: var(--ink-2); }
.kv-table td:first-child { color: var(--muted); }
.detail-empty { padding: 24px; color: var(--muted); }
.cat-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; background: var(--muted); }
.cat-dot.digest { background: var(--cyan); } .cat-dot.hmac { background: var(--lilac); }
.cat-dot.sym { background: var(--blue); } .cat-dot.asym { background: var(--pink); }
.cat-dot.aead { background: var(--teal); } .cat-dot.file { background: var(--amber); }
.cat-dot.sys { background: var(--green); } .cat-dot.net { background: var(--coral); }
</style>

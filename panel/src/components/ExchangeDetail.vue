<script setup lang="ts">
import { computed, ref } from 'vue';

const props = defineProps<{ ex: Record<string, any> }>();
const view = ref<'data' | 'event'>('data');

interface Part { startLine?: string; headerText?: string; bodyText?: string; bodyBytes?: number; bodyHex?: string; binary?: boolean; complete?: boolean; decoded?: boolean; contentEncoding?: string; note?: string }
const req = computed<Part | undefined>(() => props.ex.request);
const res = computed<Part | undefined>(() => props.ex.response);

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
function partMeta(p?: Part): string {
  if (!p) return '';
  return [
    p.complete ? '' : '未完成',
    p.decoded && p.contentEncoding ? `已解开 ${p.contentEncoding}` : '',
    `${p.bodyBytes ?? 0} bytes`, p.note ?? '',
  ].filter(Boolean).join(' · ');
}
function partText(p?: Part): string {
  if (!p) return '（还没有）';
  let body = p.bodyText || '';
  if (p.binary) body = `二进制 ${p.bodyBytes ?? 0} 字节${p.bodyHex ? '\n' + hexdump(p.bodyHex) : ''}`;
  else if (!body) body = '（空）';
  return (p.headerText ? p.headerText + '\n\n' : '') + body;
}
const bytes = (n?: number) => (n == null ? '未记录' : `${n} B`);
</script>

<template>
  <div class="detail-head">
    <h2><span class="cat-dot net"></span>{{ ex.label }}</h2>
    <div class="sub">{{ [ex.status ? `HTTP ${ex.status}` : '', ex.conn].filter(Boolean).join(' · ') }}</div>
  </div>

  <div class="detail-tabs">
    <button class="chip" :class="{ on: view === 'data' }" @click="view = 'data'">数据详情</button>
    <button class="chip" :class="{ on: view === 'event' }" @click="view = 'event'">事件信息</button>
  </div>

  <div v-if="view === 'data'" class="detail-body">
    <div class="io-section in-card">
      <div class="io-card-head"><span class="io-label in">请求</span><span class="io-meta">{{ partMeta(req) }}</span></div>
      <template v-if="req">
        <h3>{{ req.startLine }}</h3>
        <pre class="io-block">{{ partText(req) }}</pre>
      </template>
      <pre v-else class="io-block">（还没有）</pre>
    </div>
    <div class="io-section out-card">
      <div class="io-card-head"><span class="io-label out">响应</span><span class="io-meta">{{ partMeta(res) }}</span></div>
      <template v-if="res">
        <h3>{{ res.startLine }}</h3>
        <pre class="io-block">{{ partText(res) }}</pre>
      </template>
      <pre v-else class="io-block">（还没有）</pre>
    </div>
  </div>

  <div v-else class="detail-body">
    <table class="kv-table">
      <tr><td>请求大小</td><td>{{ bytes(req?.bodyBytes) }}</td></tr>
      <tr><td>响应大小</td><td>{{ bytes(res?.bodyBytes) }}</td></tr>
      <tr><td>HTTP 状态</td><td>{{ ex.status || '未记录' }}</td></tr>
    </table>
    <p v-if="ex.note" class="sub">{{ ex.note }}</p>
  </div>
</template>

<style scoped>
.detail-head h2 { margin: 0 0 4px; font-size: 17px; }
.sub { color: var(--muted); font-size: 12px; margin-bottom: 12px; }
.detail-tabs { display: flex; gap: 6px; margin-bottom: 12px; }
.io-section { margin-bottom: 14px; }
.io-card-head { display: flex; gap: 10px; align-items: baseline; margin-bottom: 4px; }
.io-label { font-size: 12px; font-weight: 600; }
.io-label.in { color: var(--blue); } .io-label.out { color: var(--green); }
.io-meta { color: var(--muted); font-size: 11px; }
h3 { font-size: 13px; margin: 6px 0; font-family: ui-monospace, monospace; }
.io-block { background: var(--surface-2); border: 1px solid var(--line-soft); border-radius: 8px; padding: 10px; font-size: 12px; white-space: pre-wrap; word-break: break-all; overflow: auto; max-height: 40dvh; }
.kv-table { border-collapse: collapse; font-size: 13px; }
.kv-table td { padding: 5px 14px 5px 0; color: var(--ink-2); }
.kv-table td:first-child { color: var(--muted); }
.cat-dot.net { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; background: var(--coral); }
</style>

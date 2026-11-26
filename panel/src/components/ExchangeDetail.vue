<script setup lang="ts">
import { computed, ref } from 'vue';
import { CopyOutline } from '@vicons/ionicons5';
import { toast } from '../store';

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
  const head = [p.startLine, p.headerText].filter(Boolean).join('\n');
  return (head ? head + '\n\n' : '') + body;
}
const bytes = (n?: number) => (n == null ? '未记录' : `${n} B`);
const when = computed(() => {
  const ts = props.ex.ts as number | undefined;
  if (!ts) return '未记录';
  const d = new Date(ts);
  return Number.isFinite(d.getTime()) ? d.toLocaleString() : '未记录';
});
function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败'));
}
</script>

<template>
  <div class="detail-head">
    <h2><span class="cat-dot net"></span>{{ ex.label }}</h2>
    <div class="sub">{{ [ex.seq ? `#${ex.seq}` : '', ex.status ? `HTTP ${ex.status}` : '', ex.conn].filter(Boolean).join(' · ') }}</div>
  </div>

  <div class="record-tabs">
    <button type="button" :aria-selected="view === 'data'" @click="view = 'data'">数据详情</button>
    <button type="button" :aria-selected="view === 'event'" @click="view = 'event'">事件信息</button>
  </div>

  <div v-if="view === 'data'" class="record-tab-panel">
    <div class="io-section in-card">
      <div class="io-card-head"><span class="io-label in">请求</span><span class="io-meta">{{ partMeta(req) }}</span></div>
      <div class="io-block-body">
        <pre>{{ partText(req) }}</pre>
        <button v-if="req" type="button" class="block-copy" title="复制" @click="copy(partText(req))"><n-icon size="13" :component="CopyOutline" /></button>
      </div>
    </div>
    <div class="io-section out-card">
      <div class="io-card-head"><span class="io-label out">响应</span><span class="io-meta">{{ partMeta(res) }}</span></div>
      <div class="io-block-body">
        <pre>{{ partText(res) }}</pre>
        <button v-if="res" type="button" class="block-copy" title="复制" @click="copy(partText(res))"><n-icon size="13" :component="CopyOutline" /></button>
      </div>
    </div>
  </div>

  <div v-else class="record-tab-panel">
    <div class="capture-overview">
      <h3>事件信息</h3>
      <dl class="capture-facts">
        <div><dt>序号</dt><dd>{{ ex.seq ? `#${ex.seq}` : '未记录' }}</dd></div>
        <div><dt>时间</dt><dd>{{ when }}</dd></div>
        <div><dt>请求大小</dt><dd>{{ bytes(req?.bodyBytes) }}</dd></div>
        <div><dt>响应大小</dt><dd>{{ bytes(res?.bodyBytes) }}</dd></div>
        <div><dt>HTTP 状态</dt><dd>{{ ex.status || '未记录' }}</dd></div>
        <div v-if="ex.conn"><dt>连接</dt><dd class="mono">{{ ex.conn }}</dd></div>
      </dl>
      <p v-if="ex.note" class="payload-note">{{ ex.note }}</p>
    </div>
  </div>
</template>

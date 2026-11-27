<script setup lang="ts">
import {copyText} from '../user_actions';
import { computed, ref, watch } from 'vue';
import type { Cap } from '../api';
import { captureHookMethod, captureHookSession } from '../capture_hook_link';
import { getCaptureControls, deleteCapture } from '../api';
import { catClass, cryptoView, captureLengths, captureLengthText, inputEvidence, systemRow, systemPath, CATLABEL } from '../capview';
import { store, toast } from '../store';
import { CopyOutline } from '@vicons/ionicons5';

const props = defineProps<{ detail: Record<string, unknown> }>();
const emit = defineEmits<{ deleted: [id: number] }>();
const c = computed(() => props.detail as unknown as Cap & { text?: string; hex?: string; tid?: number; callStack?: string; hasKey?: boolean; source?: string });
type FmtMode = 'auto' | 'utf8' | 'hex' | 'b64' | 'hexdump';
const FMTS: [FmtMode, string][] = [['auto', 'Raw'], ['utf8', 'UTF-8'], ['hex', 'Hex'], ['b64', 'Base64'], ['hexdump', 'Hexdump']];
const ioTab = ref<'in' | 'out'>('in');
const fmtIn = ref<FmtMode>('auto');
const fmtOut = ref<FmtMode>('auto');
const sourceBusy=ref(false);
const hasHookSource=computed(()=>(c.value.source==='native'||c.value.source==='java'&&!!c.value.captureMethodId&&c.value.javaTargetTruncated===false)&&!!c.value.deviceBinding?.serial&&!!c.value.package&&!String(c.value.func).startsWith('NATIVE_HOOK'));
async function openHookSource(){
 if(sourceBusy.value||!hasHookSource.value)return;
 const record=c.value,serial=record.deviceBinding!.serial,pkg=record.package!,deviceKey=store.selectedDeviceKey;
 sourceBusy.value=true;
 try{const session=captureHookSession(record,[...store.sessions.values()]);const control=await getCaptureControls(serial,pkg,session||undefined);if(store.selectedDeviceKey!==deviceKey||store.chosenPkg!==pkg)return;
  const method=captureHookMethod(record,control.catalogs?.methods??[]);if(!method){toast('此记录没有可精确定位的受控方法；未猜测来源');return;}
  const returnView=store.view==='sy'?'sy':store.view==='nt'?'nt':'cc';
  store.hookSource={serial,package:pkg,methodId:method.id,recordId:record.id,session,returnView};store.view='settings';
 }catch(error){toast('无法读取 Hook 目录：'+(error as Error).message);}finally{sourceBusy.value=false;}
}
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

// 原始格式标注：捕获的字节本身是合法 UTF-8 文本就是字符串，否则是二进制 bytes
function rawKind(rawHex?: string, fallbackText?: string): string {
  if (!rawHex) return fallbackText ? '字符串' : '';
  return tryUtf8(rawHex).readable ? '字符串' : 'bytes';
}

function formatBlock(mode: FmtMode, rawHex?: string, fallbackText?: string): { display: string; copyVal: string; mono: boolean } {
  if (rawHex === '') return { display: '（空字节）', copyVal: '', mono: true };
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
const hasInBlock = computed(() => typeof c.value.hex === 'string' || !!((!isFile.value && c.value.text) || (c.value.inl ?? 0) > 0));
const hasInput = computed(() => hasFileCards.value || hasInBlock.value || !!c.value.keyHex || !!c.value.ivHex);
const hasOutput = computed(() => typeof c.value.outHex === 'string' || (c.value.outl ?? 0) > 0);
const curHasData = computed(() => (ioTab.value === 'in' ? hasInput.value : hasOutput.value));
const activeFmt = computed(() => (ioTab.value === 'in' ? fmtIn.value : fmtOut.value));
function setFmt(k: FmtMode) { if (ioTab.value === 'in') fmtIn.value = k; else fmtOut.value = k; }
const bytes = (n?: number) => (n == null ? '未记录' : `${n} B`);
const lengths = computed(() => captureLengths(c.value));
const inputInfo = computed(() => inputEvidence(c.value));
const inputBlock = computed(() => {
  const block=formatBlock(fmtIn.value,c.value.hex,c.value.text);
  if(inputInfo.value.fragment&&(c.value.hex===''||c.value.hex==null&&(c.value.inl??0)===0))return {...block,display:inputInfo.value.emptyText};
  return block;
});
const inBytes = computed(() => lengths.value.input.captured ?? lengths.value.input.bytes);
const outBytes = computed(() => lengths.value.output.captured ?? lengths.value.output.bytes);
const inRawKind = computed(() => rawKind(c.value.hex, c.value.text));
const outRawKind = computed(() => rawKind(c.value.outHex));

watch(() => c.value.id, () => {
  confirmDelete.value = false;
  infoOpen.value = false;
  ioTab.value = hasInput.value ? 'in' : 'out';
});

function copy(text: string) {
  void copyText(text).then(() => toast('已复制'), (error:Error) => toast('复制失败：'+error.message));
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
  <div v-if="detail._loading" class="detail-empty detail-loading"><n-spin size="small" /></div>
  <div v-else-if="detail._error" class="detail-empty"><n-empty size="small" :description="String(detail._error)" /></div>
  <div v-else class="detail-anim" :key="String(c.id)">
    <div class="detail-head">
      <div class="detail-head-main">
        <h2 :data-algorithm-family="isCrypto ? catClass(c) : undefined">
          <span class="cat-dot" :class="catClass(c)"></span>
          <template v-if="isCrypto">{{ cv?.title }}<template v-if="cv?.direction"> · {{ cv.direction }}</template></template>
          <template v-else>#{{ c.id }} {{ isFile ? systemRow(c).method : c.algo || c.func }}</template>
        </h2>
        <div class="sub">
          {{ [cv?.hook, new Date(c.ts).toLocaleString(), c.tid ? `tid ${c.tid}` : '', cv?.truncated ? '输入已截断' : '', cv?.outputTruncated ? '输出已截断' : ''].filter(Boolean).join(' · ') }}
        </div>
      </div>
      <div class="detail-menu">
        <n-button v-if="hasHookSource" quaternary size="small" :loading="sourceBusy" @click="openHookSource">来源 Hook</n-button>
        <n-dropdown trigger="click" :options="[
            { label: '事件信息', key: 'info' },
            { label: '删除记录', key: 'delete', props: { style: 'color:#f87171' } },
          ]" @select="onMenuSelect">
          <n-button quaternary size="small" class="menu-btn" title="记录操作" aria-label="记录操作">⋯</n-button>
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
        <div v-if="c.source==='java'"><dt>方法重载</dt><dd class="mono">{{ c.javaTarget || '旧记录未提供完整签名' }}{{ c.javaTargetTruncated ? '（来源已截断，无法精确定位）' : '' }}</dd></div>
        <div v-if="c.inputScope"><dt>采样时点</dt><dd>调用返回后的参数采样；不等同完整输入</dd></div>
        <div><dt>{{ inputInfo.fragment ? '本次捕获输入' : '输入大小' }}</dt><dd>{{ inputInfo.lengthText }}</dd></div>
        <div><dt>输出大小</dt><dd>{{ captureLengthText(lengths.output) }}</dd></div>
        <div><dt>线程 ID</dt><dd>{{ c.tid ? String(c.tid) : '未记录' }}</dd></div>
        <div><dt>时间</dt><dd>{{ new Date(c.ts).toLocaleString() }}</dd></div>
        <div v-if="c.sessionId"><dt>会话</dt><dd class="mono">{{ c.sessionId }}</dd></div>
      </dl>
      <div v-if="hasStack" class="stack-box">
        <pre>{{ c.callStack }}</pre>
        <n-button quaternary circle size="small" class="blk-copy" title="复制调用栈" aria-label="复制调用栈"
          @click="copy(c.callStack || '')">
          <n-icon size="15" :component="CopyOutline" />
        </n-button>
      </div>
    </div>

    <div class="io-toolbar">
      <n-radio-group v-model:value="ioTab" size="small">
        <n-radio-button value="in">{{ inLabel }}</n-radio-button>
        <n-radio-button value="out">{{ outLabel }}</n-radio-button>
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
            <pre>{{ systemPath(c) || '未记录' }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" title="复制路径" aria-label="复制路径"
              @click="copy(systemPath(c))">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
        </div>
        <div class="io-field">
          <div class="io-field-label">详情</div>
          <div class="io-data">
            <pre>{{ [c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n') }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" title="复制详情" aria-label="复制详情"
              @click="copy([c.func, c.op, c.path ? c.preview : c.text].filter(Boolean).join('\n'))">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
        </div>
      </template>

      <template v-if="c.keyHex">
        <div class="io-field">
          <div class="io-field-label">KEY · {{ c.keyHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.keyHex).display }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" title="复制密钥" aria-label="复制密钥"
              @click="copy(formatKey(fmtIn, c.keyHex).copyVal)">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
        </div>
      </template>
      <template v-if="c.ivHex">
        <div class="io-field">
          <div class="io-field-label">IV · {{ c.ivHex.length / 2 }}B</div>
          <div class="io-data">
            <pre class="mono">{{ formatKey(fmtIn, c.ivHex).display }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" title="复制 IV" aria-label="复制 IV"
              @click="copy(formatKey(fmtIn, c.ivHex).copyVal)">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
        </div>
      </template>

      <template v-if="hasInBlock">
        <div class="io-field">
          <div class="io-field-label">{{ inDataLabel }} · {{ bytes(inBytes) }}{{ inRawKind ? ' · ' + inRawKind : '' }}</div>
          <div class="io-data main">
            <pre :class="{ mono: inputBlock.mono }">{{ inputBlock.display }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" :title="'复制' + inDataLabel" :aria-label="'复制' + inDataLabel"
              @click="copy(inputBlock.copyVal)">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
          <p v-if="inputInfo.fragment" class="payload-note">{{ inputInfo.note }}</p>
        </div>
      </template>
      <div v-if="!hasInput" class="detail-empty">这条记录没有输入数据。</div>
    </div>

    <div v-else class="io-panel">
      <template v-if="hasOutput">
        <div class="io-field">
          <div class="io-field-label">{{ outDataLabel }} · {{ bytes(outBytes) }}{{ outRawKind ? ' · ' + outRawKind : '' }}</div>
          <div class="io-data main">
            <pre :class="{ mono: formatBlock(fmtOut, c.outHex).mono }">{{ formatBlock(fmtOut, c.outHex).display }}</pre>
            <n-button quaternary circle size="small" class="blk-copy" :title="'复制' + outDataLabel" :aria-label="'复制' + outDataLabel"
              @click="copy(formatBlock(fmtOut, c.outHex).copyVal)">
              <n-icon size="15" :component="CopyOutline" />
            </n-button>
          </div>
        </div>
      </template>
      <div v-else class="detail-empty">这条记录没有输出数据。</div>
    </div>
  </div>
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

/* 记录切换入场：按 c.id 重建元素触发 */
.detail-anim { animation: detail-in .14s ease-out; }
@keyframes detail-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
.detail-loading { min-height: 40vh; display: grid; place-items: center; padding: 0; }

/* 一条工具栏：输入/输出 段控件 + 格式 段控件 */
.io-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  margin: 14px 0 10px;
}
/* 工具栏文字层级不能盖过正文数据（正文 12px） */
.io-toolbar :deep(.n-radio-button) {
  font-size: 12px;
  padding-inline: 10px;
}

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
.io-data pre.mono { white-space:pre; word-break:normal; overflow-wrap:normal; max-width:100%; font-family: ui-monospace, Consolas, 'Cascadia Mono', monospace; }
/* 复制按钮：naive-ui 圆形图标按钮，悬停/聚焦数据块才显现，定位不变 */
.blk-copy {
  position: absolute; top: 6px; right: 6px;
  opacity: 0;
  transition: opacity .12s;
}
.io-data:hover .blk-copy, .stack-box:hover .blk-copy,
.io-data:focus-within .blk-copy, .stack-box:focus-within .blk-copy { opacity: 1; }
.stack-box {
  position: relative;
  margin-top: 10px;
  border: 1px solid var(--border, rgba(128, 128, 128, 0.22));
  border-radius: 8px;
  background: rgba(128, 128, 128, 0.05);
}
.stack-box pre { margin: 0; padding: 10px 12px; font-size: 12px; max-height: 34vh; overflow: auto; }
@media(max-width:620px){.detail-head-main{width:100%}.detail-menu{margin-left:auto}.detail-head-main .sub{word-break:normal;overflow-wrap:break-word}}
</style>

<script setup lang="ts">
import {copyText} from '../user_actions';
import {computed,ref,watch} from 'vue';
import {CopyOutline} from '@vicons/ionicons5';
import {toast} from '../store';
import {bodyView,exchangeIdentity,BODY_FORMATS,type BodyFormat,type HttpBodyPart} from '../http_payload_view';
const props=defineProps<{ex:Record<string,any>}>();
const infoOpen=ref(false),side=ref<'request'|'response'>('request'),format=ref<BodyFormat>('raw');
const identity=computed(()=>exchangeIdentity(props.ex));
const part=computed<HttpBodyPart|undefined>(()=>props.ex[side.value]);
const payload=computed(()=>bodyView(part.value,format.value));
const headers=computed(()=>[part.value?.startLine,part.value?.headerText].filter(Boolean).join('\n'));
const when=computed(()=>{const ts=props.ex.ts;if(!ts)return '未记录';const d=new Date(ts);return Number.isFinite(d.getTime())?d.toLocaleString():'未记录';});
const meta=computed(()=>{const p=part.value;if(!p)return '尚未捕获';return[p.complete===false?'未完成':'',typeof p.bodyBytes==='number'?p.bodyBytes+' B':'大小未记录',p.decoded?'已解码正文':'',payload.value.known&&typeof p.bodyBytes==='number'&&payload.value.bytes<p.bodyBytes?'已保留 '+payload.value.bytes+' B':''].filter(Boolean).join(' · ');});
function copy(text:string){void copyText(text).then(()=>toast('已复制'),(e:Error)=>toast('复制失败：'+e.message));}
watch(()=>props.ex.id,()=>{infoOpen.value=false;side.value='request';format.value='raw';});
</script>
<template>
 <div class="detail-head exchange-head">
  <div class="detail-head-main"><h2 class="exchange-title" :title="identity.url||String(ex.label||'')"><span class="cat-dot net"></span>{{ identity.title }}</h2><div class="sub">{{ [identity.host,ex.status?'HTTP '+ex.status:'',when].filter(Boolean).join(' · ') }}</div></div>
  <div class="detail-menu"><n-dropdown trigger="click" :options="[{label:'事件信息',key:'info'}]" @select="infoOpen=true"><n-button quaternary size="small" aria-label="网络记录操作" title="记录操作">⋯</n-button></n-dropdown></div>
 </div>
 <div class="io-toolbar">
  <n-radio-group v-model:value="side" size="small" aria-label="请求或响应"><n-radio-button value="request">请求</n-radio-button><n-radio-button value="response">响应</n-radio-button></n-radio-group>
  <n-radio-group v-model:value="format" size="small" aria-label="网络正文格式"><n-radio-button v-for="[key,label] in BODY_FORMATS" :key="key" :value="key">{{ label }}</n-radio-button></n-radio-group>
 </div>
 <div class="io-panel network-payload">
  <div v-if="headers" class="io-field"><div class="io-field-label">{{ side==='request'?'请求头':'响应头' }}</div><div class="io-data"><pre class="mono">{{ headers }}</pre><n-button quaternary circle size="small" class="block-copy" aria-label="复制报文头" @click="copy(headers)"><n-icon size="14" :component="CopyOutline" /></n-button></div></div>
  <div class="io-field"><div class="io-field-label">{{ side==='request'?'请求正文':'响应正文' }} · {{ meta }}</div><div class="io-data"><pre class="mono" data-network-body>{{ payload.display }}</pre><n-button v-if="payload.known" quaternary circle size="small" class="block-copy" :aria-label="payload.copyLabel" :title="payload.copyLabel" @click="copy(payload.copy)"><n-icon size="14" :component="CopyOutline" /></n-button></div><p v-if="part?.decoded" class="payload-note">这里显示已解码的正文，不是原始压缩报文。</p><p v-if="part?.note" class="payload-note">{{ part.note }}</p></div>
 </div>
 <n-modal v-model:show="infoOpen" preset="card" title="事件信息" class="event-info-modal ui-window" :style="{width:'min(680px, calc(100vw - 24px))',maxHeight:'calc(100dvh - 48px)'}" :content-style="{overflow:'auto'}">
  <div class="capture-overview"><div v-if="identity.url" class="exchange-url"><span>URL</span><code>{{ identity.url }}</code><n-button text size="small" aria-label="复制完整 URL" @click="copy(identity.url)">复制</n-button></div><dl class="capture-facts"><div><dt>序号</dt><dd>{{ ex.seq?'#'+ex.seq:'未记录' }}</dd></div><div><dt>时间</dt><dd>{{ when }}</dd></div><div><dt>请求正文</dt><dd>{{ ex.request?.bodyBytes!=null?ex.request.bodyBytes+' B':'未记录' }}</dd></div><div><dt>响应正文</dt><dd>{{ ex.response?.bodyBytes!=null?ex.response.bodyBytes+' B':'未记录' }}</dd></div><div><dt>HTTP 状态</dt><dd>{{ ex.status||'未记录' }}</dd></div><div v-if="ex.conn"><dt>连接</dt><dd class="mono">{{ ex.conn }}</dd></div></dl><p v-if="ex.note" class="payload-note">{{ ex.note }}</p></div>
 </n-modal>
</template>
<style scoped>
.exchange-title{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}.exchange-head .detail-head-main{flex:1;min-width:0}.exchange-head .detail-menu{flex:none}.network-payload .io-data{position:relative}.network-payload pre{margin:0;padding:14px 16px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:46vh;overflow:auto}.block-copy{position:absolute;top:6px;right:6px;opacity:0;transition:opacity .12s}.io-data:hover .block-copy,.io-data:focus-within .block-copy{opacity:1}.exchange-url{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px;font-size:12px}.exchange-url>span{color:var(--muted);flex:none}.exchange-url code{flex:1;min-width:0;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--ink)}
</style>

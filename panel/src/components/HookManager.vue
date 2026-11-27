<script lang="ts">
// Tab-local drafts survive leaving Settings, but never execute themselves.
const drafts=new Map<string,{config:any;revision:number}>();
</script>
<script setup lang="ts">
import {ref,computed,watch,onBeforeUnmount} from 'vue';
import {store,appSessions,selectedSerial} from '../store';
import {getCaptureControls,writeCaptureControls,type CaptureControlsView} from '../api';
import {SearchOutline,RefreshOutline,ChevronDownOutline} from '@vicons/ionicons5';
const props=defineProps<{group?:'all'|'crypto'|'system'|'network'}>();
const FEATURES=[['digest','摘要',1],['hmac','HMAC',2],['symmetric','对称加密',4],['asymmetric','非对称签名',8],['tls','TLS 明文',16],['aead','AEAD',32],['system','系统检测',64],['file','文件访问',128]] as const;
const visibleFeatures=computed(()=>FEATURES.filter(([id])=>!props.group||props.group==='all'||props.group==='network'?(!props.group||props.group==='all'||id==='tls'):props.group==='system'?['system','file'].includes(id):!['system','file','tls'].includes(id)));
const groupMask=computed(()=>visibleFeatures.value.reduce((mask,[,,bit])=>mask|bit,0));
watch(()=>props.group,()=>{if(!visibleFeatures.value.some(([id])=>id===feature.value))feature.value=visibleFeatures.value[0][0];});
const copy=(x:any)=>JSON.parse(JSON.stringify(x));
const view=ref<CaptureControlsView|null>(null),draft=ref<any>(null),busy=ref(false),loading=ref(false),error=ref(''),notice=ref('');
const featuresExpanded=ref(false);
const feature=ref(props.group==='network'?'tls':props.group==='system'?'system':'digest'),query=ref(''),backend=ref('all'),stateFilter=ref('all'),detail=ref(''),sid=ref('');
const target=ref({serial:'',package:'',session:''}),pendingTarget=ref<any>(null),confirmApply=ref(false),review=ref<CaptureControlsView|null>(null);
let request=0;
const key=(t:typeof target.value)=>t.serial+'\n'+t.package+'\n'+t.session;
const appDraftKey=(t:{serial:string;package:string})=>t.serial+'\n'+t.package+'\n@automatic-generation';
const methods=computed<any[]>(()=>view.value?.catalogs?.methods??[]);
const activeFeature=computed(()=>FEATURES.find(([k])=>k===feature.value)!);
const currentChoices=computed(()=>draft.value?.features[feature.value]??{enabled:false,methods:[]});
const changed=computed(()=>{
 if(!draft.value||!view.value)return 0;let n=0;for(const [k]of FEATURES){const a=draft.value.features[k],b=view.value.config.features[k];if(a.enabled!==b.enabled)n++;for(const id of new Set([...a.methods,...b.methods]))if(a.methods.includes(id)!==b.methods.includes(id))n++;}for(const k of ['crypto','file','system'])if(draft.value.modules[k]!==view.value.config.modules[k])n++;return n;
});
const chosen=computed(()=>new Set<string>(FEATURES.flatMap(([k])=>draft.value?.features[k]?.enabled?draft.value.features[k].methods:[])));
const dependencies=computed(()=>{const out=new Map<string,string[]>(),by=new Map(methods.value.map(m=>[m.id,m])),all=new Set(chosen.value);for(let i=0;i<methods.value.length;i++){let add=false;for(const id of [...all])for(const dep of by.get(id)?.requires??[]){const rows=out.get(dep)??[];if(!rows.includes(id))rows.push(id);out.set(dep,rows);if(!all.has(dep)){all.add(dep);add=true;}}if(!add)break;}return out;});
const appOnline=computed(()=>appSessions.value.filter(s=>s.online&&s.package===store.chosenPkg&&s.deviceBinding?.serial===selectedSerial()));
const autoSession=computed(()=>{
 const source=store.hookSource;
 if(source&&source.serial===selectedSerial()&&source.package===store.chosenPkg&&typeof source.session==='string'&&appOnline.value.some(s=>s.sessionId===source.session))return source.session;
 const main=appOnline.value.filter(s=>s.process===s.package),pool=main.length?main:appOnline.value;
 const generations=new Set(pool.map(s=>s.pid+':'+(s.deviceBinding?.process?.starttimeTicks??s.sessionId)));
 return generations.size===1?[...pool].sort((a,b)=>Number(b.connectedAt??0)-Number(a.connectedAt??0))[0]?.sessionId??'':'';
});
const targetLabel=computed(()=>{const p=appOnline.value.find(s=>s.sessionId===sid.value);return p?(p.process===p.package?'主进程':'应用进程')+' · PID '+p.pid:'离线配置';});
const appConnectionHint=computed(()=>autoSession.value?'':appOnline.value.length?'当前 APP 尚未确认唯一主进程，连接稳定后会自动加载；不会随机操作子进程。':'当前 APP 尚未注入或已断开。配置可仅保存，连接后自动加载。');
const controlsDisabled=computed(()=>busy.value||!!pendingTarget.value||!!review.value);
const unconfirmed=computed(()=>view.value?.lastIntent?.state==='unknown'||((view.value?.control as any)?.uncertainOperations?.length??0)>0);
const rows=computed(()=>methods.value.filter(m=>(m.families&groupMask.value)&&(!!query.value||(m.families&activeFeature.value[2]))&&(backend.value==='all'||m.backend===backend.value)&&(!query.value||`${m.id} ${m.class??''} ${m.symbol??''} ${m.params??''}`.toLowerCase().includes(query.value.trim().toLowerCase()))&&(stateFilter.value==='all'||stateFilter.value==='active'&&isActive(m)||stateFilter.value==='inactive'&&!isActive(m)||stateFilter.value==='error'&&isProblem(m))).sort((a,b)=>a.id.localeCompare(b.id)));
const more=computed(()=>[{label:'全选当前功能的目录方法',key:'all'},{label:'全不选',key:'none'},{label:'恢复上次已应用的选择',key:'restore',disabled:!view.value?.lastApplied}]);
function isActive(m:any){return !!view.value?.runtime&&(m.backend==='java'?m.active===true:Number(m.ownedSlots)>0);}
function isProblem(m:any){return !!m.error||Number(m.changedSlots)>0||Number(m.unreadableSlots)>0||['failed','install-failed','owner-conflict','ownership-unknown','dependency-unavailable'].includes(m.state)||(!isActive(m)&&view.value?.lastIntent?.results?.some((r:any)=>r.id===m.id&&r.expected&&!r.ok));}
function methodName(m:any){return m.backend==='java'?`${String(m.class??'').split('.').at(-1)}.${m.method}(${m.params??''})`:m.symbol;}
function stateLabel(m:any){if(!view.value?.runtime)return '离线';if(isProblem(m))return '需处理';if(isActive(m))return '观测中';return m.patched?'已停用观测':'未启用';}
function toggleMethod(m:any,value:boolean){if(controlsDisabled.value||!currentChoices.value.enabled||dependencies.value.has(m.id))return;const f=draft.value.features[feature.value];f.methods=value?[...new Set([...f.methods,m.id])]:f.methods.filter((x:string)=>x!==m.id);}
function menu(action:string){if(!draft.value)return;const f=draft.value.features[feature.value];if(action==='all')f.methods=methods.value.filter(m=>m.families&activeFeature.value[2]).map(m=>m.id);if(action==='none')f.methods=[];if(action==='restore'&&view.value?.lastApplied)f.methods=copy(view.value.lastApplied.config.features[feature.value].methods);}
function retain(){if(changed.value&&draft.value)drafts.set(key(target.value),{config:copy(draft.value),revision:view.value!.revision});}
async function load(preserve=false){
 const id=++request,t=copy(target.value);if(!t.serial||!t.package){view.value=null;draft.value=null;return;}loading.value=true;error.value='';
 try{const data=await getCaptureControls(t.serial,t.package,t.session||undefined);if(id!==request||key(t)!==key(target.value))return;
  if(preserve&&changed.value){review.value=data;return;}
  view.value=data;const saved=drafts.get(key(t))??drafts.get(appDraftKey(t));draft.value=copy(saved?.config??data.config);notice.value=saved?'已恢复此目标的未应用草稿':'';focusSource();
 }catch(e){if(id===request)error.value=(e as Error).message;}finally{if(id===request)loading.value=false;}
}
function focusSource(){const source=store.hookSource;if(!source||source.serial!==target.value.serial||source.package!==target.value.package)return;if(source.feature&&FEATURES.some(([k])=>k===source.feature)){feature.value=source.feature;query.value='';detail.value='';return;}const m=methods.value.find(m=>m.id===source.methodId);if(!m)return;feature.value=FEATURES.find(([, ,bit])=>m.families&bit)![0];query.value=m.id;detail.value=m.id;}
function returnToRecord(){const source=store.hookSource;if(source)store.view=source.returnView;store.settingsOpen=false;store.hookSource=null;}
function switchTarget(t:typeof target.value){
 if(key(t)===key(target.value))return;
 const sameApp=t.serial===target.value.serial&&t.package===target.value.package;
 if(sameApp){
  const carry=changed.value&&draft.value?copy(draft.value):null;retain();if(carry)drafts.set(appDraftKey(t),{config:copy(carry),revision:view.value!.revision});
  target.value=t;sid.value=t.session;view.value=null;draft.value=null;review.value=null;pendingTarget.value=null;notice.value='';
  const boundKey=key(t),expectedRequest=request+1;void load().then(()=>{if(carry&&request===expectedRequest&&boundKey===key(target.value)){draft.value=carry;notice.value='进程已变更，草稿已保留；应用前请核对当前目录。';}});return;
 }
 if(changed.value){pendingTarget.value=t;return;}
 target.value=t;sid.value=t.session;view.value=null;draft.value=null;review.value=null;notice.value='';void load();
}
function finishSwitch(keep:boolean){const t=pendingTarget.value;if(!t)return;if(keep)retain();else {drafts.delete(key(target.value));drafts.delete(appDraftKey(target.value));}pendingTarget.value=null;target.value=t;sid.value=t.session;view.value=null;draft.value=null;review.value=null;notice.value='';void load();}
function useRefresh(keep:boolean){if(!review.value)return;const old=copy(draft.value);view.value=review.value;draft.value=keep?old:copy(review.value.config);review.value=null;notice.value=keep?'已采用新状态；请核对变更后再应用':'';}
function discard(){drafts.delete(key(target.value));drafts.delete(appDraftKey(target.value));if(view.value)draft.value=copy(view.value.config);error.value='';notice.value='';}
function restore(){if(view.value?.lastApplied)draft.value=copy(view.value.lastApplied.config);}
async function submit(action:'discover'|'save'|'apply',confirmed=false){
 if(!view.value||busy.value)return;
 if(action==='apply'&&!confirmed&&(!view.value.lastApplied||[...chosen.value].some(id=>id.startsWith('native.')))){confirmApply.value=true;return;}
 const frozen=copy(view.value),config=copy(draft.value),targetKey=key(target.value);busy.value=true;error.value='';notice.value='';confirmApply.value=false;
 try{const result=await writeCaptureControls(frozen,action,config,confirmed);if(targetKey!==key(target.value))return;
  if(result.ok===false){error.value=result.error??'操作未确认，请只读刷新状态';notice.value=result.state==='unknown'?'结果未知；未自动重试':'';}
  if(result.persisted||result.ok){drafts.delete(targetKey);drafts.delete(appDraftKey(frozen));const next=await getCaptureControls(frozen.serial,frozen.package,frozen.session||undefined);if(targetKey===key(target.value)){view.value=next;draft.value=config;}}
  if(result.ok!==false)notice.value=action==='discover'?'Java 方法目录已读取':action==='save'?'已保存，待应用；重连不会自动启用':'已应用并读回确认';
 }catch(e){if(targetKey===key(target.value)){error.value=(e as Error).message;notice.value='请求结果未确认；请只读刷新，不要直接重复写入';}}
 finally{busy.value=false;}
}
watch(()=>selectedSerial()+'\n'+store.chosenPkg+'\n'+autoSession.value,()=>switchTarget({serial:selectedSerial(),package:store.chosenPkg,session:autoSession.value}),{immediate:true});
onBeforeUnmount(retain);
</script>

<template>
 <section class="hook-manager" aria-label="两级 Hook 管理" :aria-busy="loading||busy">
  <div v-if="!target.serial||!target.package" class="hook-empty"><h2>先选择设备和 APP</h2><n-button secondary @click="store.appDialogOpen=true">选择 APP</n-button></div>
  <template v-else>
   <div v-if="store.hookSource?.serial===target.serial&&store.hookSource?.package===target.package" class="hook-hint"><n-button text @click="returnToRecord">‹ {{ store.hookSource.recordId!=null ? '返回记录 #'+store.hookSource.recordId : '返回网络' }}</n-button><span> · 来源符号定位；此处显示当前配置，不代表历史安装状态</span></div>
   <div class="hook-command-bar">
   <div class="hook-tools"><n-input v-model:value="query" clearable placeholder="搜索功能、类或方法" aria-label="搜索 Hook 方法"><template #prefix><n-icon :component="SearchOutline" /></template></n-input><n-select v-model:value="backend" aria-label="方法后端" :options="[{label:'全部后端',value:'all'},{label:'Java',value:'java'},{label:'Native',value:'native'}]"/><n-select v-model:value="stateFilter" aria-label="方法运行状态筛选" :options="[{label:'全部状态',value:'all'},{label:'观测中',value:'active'},{label:'未启用',value:'inactive'},{label:'需处理',value:'error'}]"/><n-button quaternary :loading="loading" :disabled="busy" aria-label="刷新 Hook 快照" @click="load(true)"><template #icon><n-icon :component="RefreshOutline"/></template></n-button></div>
   </div>
   <p v-if="appConnectionHint&&!loading" class="hook-message" role="status">{{ appConnectionHint }}</p>
   <p v-if="error" class="hook-message error" role="alert">{{ error }}</p>
   <p v-if="notice" class="hook-message" role="status">{{ notice }}</p>
   <div v-if="review" class="hook-review" role="alert"><span>检测到新状态。草稿仍保留，请选择如何继续。</span><n-button size="small" @click="useRefresh(true)">采用新状态，保留草稿</n-button><n-button size="small" @click="useRefresh(false)">采用新状态，放弃草稿</n-button></div>
   <div v-if="view?.foreignOwner" class="hook-message error" role="alert">当前进程由另一个 Hook 计划持有。先结束该计划，再应用这里的配置。</div>
   <div v-if="unconfirmed" class="hook-message error" role="alert">上次操作结果未知。请先只读核查或由操作员处理，不能直接重放写入。</div>
   <div v-if="view?.runtime&&!view.runtime.native.supported" class="hook-message error" role="alert">当前 Agent 缺少方法级安全控制能力，请升级 Agent 后再应用。</div>
   <n-spin :show="loading&&!view">
    <div v-if="loading&&!view" class="hook-empty">正在读取 Hook 配置…</div>
    <div v-if="draft&&view" class="hook-workspace">
     <div class="hook-feature-mobile-bar">
      <button class="hook-feature-picker" :aria-expanded="featuresExpanded" aria-controls="hook-feature-list" @click="featuresExpanded=!featuresExpanded"><span>{{ activeFeature[1] }}<small>已选 {{ currentChoices.methods.length }} / 已载入 {{ methods.filter(m=>m.families&activeFeature[2]).length }}</small></span><n-icon :component="ChevronDownOutline" /></button>
      <label v-if="!featuresExpanded" class="hook-current-gate"><span>总开关</span><n-switch size="small" :value="currentChoices.enabled" :aria-label="activeFeature[1]+'功能总开关'" :disabled="controlsDisabled" @update:value="(value:boolean)=>currentChoices.enabled=value" /></label>
     </div>
     <div id="hook-feature-list" class="hook-features" :class="{expanded:featuresExpanded}" aria-label="功能总开关">
      <div class="hook-feature-caption" aria-hidden="true"><span>功能</span><span>总开关</span></div>
      <div v-for="[id,label,bit] in visibleFeatures" :key="id" class="hook-feature" :class="{selected:feature===id}"><button class="hook-feature-label" :aria-pressed="feature===id" @click="feature=id;featuresExpanded=false"><span>{{ label }}</span><small>已选 {{ draft.features[id].methods.length }} / 已载入 {{ methods.filter(m=>m.families&bit).length }}</small></button><n-switch size="small" :value="draft.features[id].enabled" :aria-label="label+'功能总开关'" :disabled="controlsDisabled" :aria-disabled="controlsDisabled" @update:value="(value:boolean)=>draft.features[id].enabled=value" /></div>
     </div>
     <div class="hook-methods">
      <div class="hook-method-head"><div><h2>{{ activeFeature[1] }}</h2><span v-if="!currentChoices.enabled">功能已停用，子项选择保留</span><span v-else-if="!currentChoices.methods.length">未选择方法</span></div><n-dropdown :options="more" :disabled="controlsDisabled||!currentChoices.enabled" @select="menu"><n-button quaternary size="small" aria-label="当前功能的更多操作">更多<n-icon :component="ChevronDownOutline" /></n-button></n-dropdown></div>
      <div v-if="view.catalogs?.historical" class="hook-hint">上次读取的目录；当前离线。保存后仍需选择在线进程明确应用。</div>
      <div v-if="view.runtime?.java?.supported&&!view.runtime.java.discovered" class="hook-discovery"><span>Java 方法目录尚未读取。</span><n-button size="small" secondary :disabled="busy||!sid||view.foreignOwner" @click="submit('discover')">读取 Java 目录</n-button></div>
      <div v-for="m in rows" :key="m.id" class="hook-method-row">
       <div class="hook-method-title"><button class="hook-method-name" :title="m.id" :aria-expanded="detail===m.id" @click="detail=detail===m.id?'':m.id">{{ methodName(m) }}</button><small>{{ m.backend==='java'?'Java':'Native' }}</small></div>
       <span class="hook-runtime" :class="{problem:isProblem(m)}">{{ stateLabel(m) }}</span>
       <n-button v-if="!(m.families&activeFeature[2])" text size="tiny" @click="feature=FEATURES.find(([, ,bit])=>m.families&bit)![0]">前往</n-button>
       <n-switch v-else size="small" :value="currentChoices.methods.includes(m.id)||dependencies.has(m.id)" :aria-label="m.id+'方法选择'" :disabled="controlsDisabled||!currentChoices.enabled||dependencies.has(m.id)" :aria-disabled="controlsDisabled||!currentChoices.enabled||dependencies.has(m.id)" @update:value="(value:boolean)=>toggleMethod(m,value)" />
       <dl v-if="detail===m.id" class="hook-method-detail"><div><dt>完整方法</dt><dd>{{ m.id }}</dd></div><div><dt>归属功能</dt><dd>{{ FEATURES.filter(([, ,bit])=>m.families&bit).map(([,label])=>label).join('、') }}</dd></div><div v-if="m.requires?.length"><dt>必要依赖</dt><dd>{{ m.requires.join('、') }}</dd></div><div v-if="dependencies.has(m.id)"><dt>依赖来源</dt><dd>{{ dependencies.get(m.id)?.join('、') }}（随所依赖的方法一起停用）</dd></div><div><dt>停用方式</dt><dd>{{ m.backend==='java'?'停用观测；已安装的底层补丁可能保留':'只恢复本采集器仍拥有的 GOT 槽位，不覆盖其他写入者' }}</dd></div><div v-if="m.backend==='native'"><dt>模块范围</dt><dd>{{ (m.families&128)?draft.modules.file||'尚未指定':(m.families&64)?draft.modules.system||'尚未指定':draft.modules.crypto||'已加载模块（全部扫描）' }}</dd></div><div><dt>安装回执</dt><dd>{{ view.runtime?m.state:'离线，仅上次目录' }}<template v-if="m.backend==='native'&&view.runtime"> · 当前持有 {{ m.ownedSlots??0 }} 个槽位</template></dd></div><div v-if="m.error"><dt>失败原因</dt><dd>{{ m.error }}</dd></div></dl>
      </div>
      <div v-if="!rows.length" class="hook-empty small">{{ query?'没有匹配的方法':'当前目录中没有此类方法' }}<n-button v-if="query" text @click="query=''">清除搜索</n-button></div>
      <details class="hook-modules"><summary>Native 模块范围</summary><label>加解密 / TLS<n-input v-model:value="draft.modules.crypto" :disabled="controlsDisabled" placeholder="留空扫描已加载模块；可填 libtarget.so" aria-label="Native 加解密模块范围" /></label><label>文件访问<n-input v-model:value="draft.modules.file" :disabled="controlsDisabled" placeholder="指定调用方模块，如 libtarget.so" aria-label="Native 文件模块范围" /></label><label>系统检测<n-input v-model:value="draft.modules.system" :disabled="controlsDisabled" placeholder="指定调用方模块，多个用逗号分隔" aria-label="Native 系统模块范围" /></label></details>
     </div>
    </div>
   </n-spin>
   <footer v-if="draft&&view&&(changed||view.pending)" class="hook-apply-bar"><span>{{ changed?changed+' 项待应用':view.runtime?'配置与运行时尚未确认一致':'已保存配置，当前离线' }}</span><div><n-button v-if="view.lastApplied" text size="small" :disabled="controlsDisabled" @click="restore">恢复上次生效选择</n-button><n-button :disabled="controlsDisabled||!changed" @click="discard">放弃更改</n-button><n-button :disabled="controlsDisabled||!changed" @click="submit('save')">仅保存</n-button><n-button type="primary" :loading="busy" :disabled="controlsDisabled||unconfirmed||!sid||!view.runtime||!view.runtime.native.supported||view.foreignOwner" @click="submit('apply')">应用更改</n-button></div></footer>
  </template>
  <n-modal :show="!!pendingTarget" :mask-closable="false" :close-on-esc="false" preset="card" title="保留当前目标的草稿？" class="hook-confirm"><p>当前更改尚未应用。切换目标不会把这些更改发到另一台手机。</p><div class="hook-confirm-actions"><n-button @click="finishSwitch(false)">放弃草稿并切换</n-button><n-button type="primary" @click="finishSwitch(true)">保留草稿并切换</n-button></div></n-modal>
  <n-modal v-model:show="confirmApply" :mask-closable="false" preset="card" title="确认应用到当前进程" class="hook-confirm"><p>{{ target.package }} · {{ targetLabel }}</p><p>将先排空旧记录，再停用和重新配置观测。Native Hook 会改变进程；Java 停用后可能保留底层补丁。失败或结果未知时不会自动重试。</p><div class="hook-confirm-actions"><n-button @click="confirmApply=false">取消</n-button><n-button type="primary" @click="submit('apply',true)">确认应用</n-button></div></n-modal>
 </section>
</template>

<style scoped>
.hook-manager{display:flex;flex-direction:column;min-width:0;min-height:100%;color:var(--ink);font-size:13px;--feature-width:180px}.hook-context{display:flex;gap:20px;align-items:center;justify-content:space-between;padding-bottom:18px}.hook-context>div{min-width:0;display:flex;flex-direction:column;gap:4px}.hook-context strong{font-size:14px;font-weight:620}.hook-context span{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:430px}.hook-process{flex:0 1 270px;min-width:190px}.hook-tools{display:grid;grid-template-columns:minmax(180px,1fr) 118px 118px 34px;gap:8px;margin-bottom:18px}.hook-workspace{display:grid;grid-template-columns:var(--feature-width) minmax(0,1fr);min-height:390px;border-top:1px solid var(--line-soft)}.hook-features{padding:10px 18px 10px 0;border-right:1px solid var(--line-soft)}.hook-feature{display:flex;align-items:center;gap:14px;padding:7px 9px;margin:3px 0;border-radius:5px}.hook-feature.selected{background:var(--line-soft)}.hook-feature-label{flex:1;min-width:0;display:flex;gap:5px;flex-direction:column;align-items:flex-start;background:none;border:0;color:var(--ink);text-align:left;padding:4px 0;cursor:pointer;font:inherit}.hook-feature-label small{white-space:nowrap;font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums}.hook-methods{min-width:0;padding:18px 0 0 24px}.hook-method-head{display:flex;align-items:center;justify-content:space-between;min-height:42px;margin-bottom:12px}.hook-method-head h2{margin:0;font-size:16px;font-weight:620}.hook-method-head span{display:block;margin-top:5px;color:var(--muted);font-size:12px}.hook-method-row{display:grid;grid-template-columns:minmax(0,1fr) 70px 36px;gap:12px;align-items:center;border-bottom:1px solid var(--line-soft);padding:13px 0}.hook-method-title{min-width:0;display:flex;align-items:baseline;gap:10px}.hook-method-name{background:none;border:0;padding:0;color:var(--ink);text-align:left;overflow-wrap:anywhere;font:500 13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;cursor:pointer}.hook-method-title small{color:var(--muted);font-size:10px;flex:none}.hook-runtime{font-size:11px;color:var(--muted);text-align:right}.hook-runtime.problem,.error{color:var(--error,#d45d5d)}.hook-method-detail{grid-column:1/-1;margin:0;padding:12px 14px;background:var(--line-soft);font-size:12px;line-height:1.8;overflow-wrap:anywhere;border-radius:4px}.hook-method-detail>div{display:grid;grid-template-columns:72px minmax(0,1fr);gap:12px;margin:5px 0}.hook-method-detail dt{color:var(--muted)}.hook-method-detail dd{margin:0}.hook-empty{display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;padding:60px 20px;color:var(--muted)}.hook-empty h2{font-size:16px;font-weight:550}.hook-empty.small{padding:30px 12px;font-size:12px}.hook-hint,.hook-discovery,.hook-message,.hook-review{font-size:12px;line-height:1.7;margin:0 0 15px}.hook-hint{color:var(--muted)}.hook-discovery,.hook-review{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.hook-review{padding:12px;background:var(--line-soft);border-radius:5px}.hook-modules{margin-top:24px;color:var(--muted);font-size:12px}.hook-modules summary{cursor:pointer;padding:10px 0}.hook-modules label{display:grid;grid-template-columns:110px minmax(0,1fr);align-items:center;gap:12px;margin:12px 0}.hook-apply-bar{position:sticky;bottom:0;z-index:3;display:flex;gap:16px;align-items:center;justify-content:space-between;padding:14px 0;margin-top:auto;border-top:1px solid var(--line);background:var(--bg,var(--panel));font-size:12px}.hook-apply-bar>div{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.hook-confirm{width:min(520px,calc(100vw - 32px))}.hook-confirm p{font-size:13px;line-height:1.8;overflow-wrap:anywhere}.hook-confirm-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}.hook-feature-label:focus-visible,.hook-method-name:focus-visible{outline:2px solid var(--accent,#7186a4);outline-offset:4px;border-radius:2px}
@media(max-width:900px){.hook-manager{--feature-width:158px}.hook-methods{padding-left:18px}.hook-context{gap:10px}.hook-context span{max-width:260px}.hook-apply-bar{flex-wrap:wrap}.hook-method-title{gap:5px}.hook-method-title small{display:none}}
@media(max-width:620px){.hook-context{align-items:stretch;flex-direction:column}.hook-context span{max-width:100%}.hook-process{flex:initial;max-width:none}.hook-tools{grid-template-columns:1fr 1fr 34px}.hook-tools>.n-input{grid-column:1/-1}.hook-workspace{grid-template-columns:minmax(0,1fr)}.hook-features{border-right:0;border-bottom:1px solid var(--line-soft);display:grid;grid-template-columns:1fr 1fr;padding:8px 0;gap:2px 8px}.hook-feature{gap:8px;margin:0;padding:5px 7px}.hook-methods{padding:16px 0 0}.hook-method-row{gap:8px;grid-template-columns:minmax(0,1fr) 60px 32px}.hook-modules label{grid-template-columns:1fr;gap:5px}.hook-apply-bar>div{width:100%;justify-content:flex-end}.hook-confirm-actions{flex-wrap:wrap}}
</style>

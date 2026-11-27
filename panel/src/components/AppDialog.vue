<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NAlert, NModal, NVirtualList } from 'naive-ui';
import { SearchOutline } from '@vicons/ionicons5';
import { store, choosePackage } from '../store';
import { appIconUrl, scopeAdd, scopeRemove, appControl, observePackage, getCapturePackages, type AppInfo } from '../api';

const props = defineProps<{ show: boolean }>();
const emit = defineEmits<{ close: [] }>();
const tab = ref<'user' | 'system' | 'injected' | 'history'>('user');
const q = ref('');
const historyApps=ref<Array<AppInfo&{history:true}>>([]),historyLoading=ref(false),historyError=ref('');let historyRequest=0;
const toastMsg = ref('');
const messageType = ref<'success' | 'error'>('error');
const picking = ref('');
const scopePending = ref('');
const controlling = ref('');
const busy = computed(() => !!(picking.value || scopePending.value || controlling.value));

watch(() => props.show, open => {
  if (open) { q.value = ''; tab.value = 'user'; toastMsg.value = ''; }
});
const tabs = [['user', '应用'], ['system', '系统'], ['injected', '注入范围'], ['history','历史']] as const;

const apps = computed(() => {
  let list:Array<AppInfo&{history?:boolean}> = tab.value==='history'?historyApps.value:store.apps;
  if (tab.value === 'user') list = list.filter(a => !a.system);
  else if (tab.value === 'system') list = list.filter(a => a.system);
  else if(tab.value==='injected') list = [...list].sort((a,b)=>Number(store.scope.has(b.package))-Number(store.scope.has(a.package))||(a.label||a.package).localeCompare(b.label||b.package));
  const s = q.value.trim().toLowerCase();
  if (s) list = list.filter(a =>
    (a.package + ' ' + (a.label ?? '')).toLowerCase().includes(s));
  return list;
});
const chosen = computed(() => store.apps.find(a => a.package === store.chosenPkg));
const iconSerial = computed(() => store.devices.find(d => d.key === store.selectedDeviceKey)?.serial || '');
const chosenLabel = computed(() => chosen.value?.label || store.chosenPkg || '未选择应用');
const chosenInitial = computed(() => (chosenLabel.value[0] ?? '?'));
const itemInitial = (label?: string, pkg?: string) => ((label || pkg || '?')[0] ?? '?');
const onlinePackages = computed(() => {
  const dev = store.devices.find(d => d.key === store.selectedDeviceKey);
  const sessionId = dev?.agent?.sessionId || dev?.appSession;
  return new Set([...store.sessions.values()].filter(s => s.online && (s.deviceBinding?.serial ? s.deviceBinding.serial===dev?.serial : s.sessionId===sessionId)).map(s => s.package));
});
const canControl = computed(() => store.scope.has(store.chosenPkg)&&store.apps.some(a=>a.package===store.chosenPkg));
const emptyText = computed(() => q.value.trim() ? '没有匹配的应用' : '没有应用');

async function loadHistory(){
 const token=++historyRequest,key=store.selectedDeviceKey,serial=iconSerial.value;historyError.value='';historyApps.value=[];
 if(!serial){historyError.value='请先选择设备';return;}historyLoading.value=true;
 try{const reply=await getCapturePackages(serial);if(token!==historyRequest||key!==store.selectedDeviceKey)return;
  historyApps.value=reply.packages.filter(p=>p.lines>0).sort((a,b)=>b.newestTs-a.newestTs).map(p=>{const installed=store.apps.find(a=>a.package===p.package);return{...installed,package:p.package,label:installed?.label||p.package,system:installed?.system??false,hasIcon:installed?.hasIcon??false,history:true};});
 }catch(e){if(token===historyRequest)historyError.value=(e as Error).message||'读取历史应用失败';}
 finally{if(token===historyRequest)historyLoading.value=false;}
}
watch(()=>props.show,open=>{if(open)void loadHistory();else{historyRequest++;historyLoading.value=false;}});
watch(()=>store.selectedDeviceKey,()=>{q.value='';historyApps.value=[];if(props.show)void loadHistory();else historyRequest++;});
function reportError(e: unknown, fallback: string) {
  messageType.value = 'error';
  toastMsg.value = e instanceof Error && e.message ? e.message : fallback;
}
function close() {
  if (!busy.value) emit('close');
}
function scopeDisabled(pkg: string) {
  return busy.value || pkg === store.chosenPkg && store.scope.has(pkg);
}
async function pick(pkg: string) {
  if (busy.value) return;
  picking.value = pkg;
  toastMsg.value = '';
  const dev = store.devices.find(d => d.key === store.selectedDeviceKey);
  const deviceKey = store.selectedDeviceKey;
  try {
    // 先确认观察请求，失败保留原应用/窗口；不能把未完成的切换显示成成功。
    if (store.localUsb && tab.value!=='history') {
      if (!dev?.serial) throw new Error('设备不可用，请先选择设备');
      await observePackage(dev.serial, pkg);
    }
    if (store.selectedDeviceKey !== deviceKey) throw new Error('设备已切换，请重新选择应用');
    choosePackage(pkg);
    emit('close');
  } catch (e) { reportError(e, '切换应用失败'); }
  finally { picking.value = ''; }
}
async function toggleInject(pkg: string, on: boolean) {
  if (scopeDisabled(pkg)) return;
  scopePending.value = pkg;
  const deviceKey=store.selectedDeviceKey,serial=iconSerial.value;
  toastMsg.value = '';
  try {
    const r = await (on ? scopeAdd(pkg,serial) : scopeRemove(pkg,serial)) as { ok?: boolean; error?: string };
    if (r?.ok !== true) throw new Error(r?.error || '写入未确认');
    if(store.selectedDeviceKey!==deviceKey)return;
    if (on) store.scope.add(pkg); else store.scope.delete(pkg);
  } catch (e) { reportError(e, '写入失败'); }
  finally { scopePending.value = ''; }
}
async function control(action: 'open' | 'stop' | 'restart') {
  const pkg = store.chosenPkg;
  if (!pkg || busy.value || !canControl.value) return;
  controlling.value = action;
  toastMsg.value = '';
  const labels = { open: '已打开', stop: '已结束', restart: '已重启' };
  try {
    const r = await appControl(pkg, action) as { ok?: boolean; error?: string };
    if (r?.ok !== true) throw new Error(r?.error || '手机没有确认这个操作');
    messageType.value = 'success';
    toastMsg.value = labels[action];
  } catch (e) { reportError(e, '手机没有完成这个操作'); }
  finally { controlling.value = ''; }
}
</script>

<template>
  <n-modal :show="show" preset="card" title="应用" aria-label="应用" :bordered="false"
    :style="{ width: 'min(880px, calc(100vw - 24px))', height: 'min(640px, calc(100dvh - 32px))' }"
    :content-style="{ padding: '0', display: 'flex', minHeight: '0', overflow: 'hidden' }"
    :closable="!busy" :mask-closable="!busy" :close-on-esc="!busy"
    @update:show="!$event && close()">
    <div class="app-dialog show app-picker-layout" :aria-busy="busy">
      <aside class="app-dialog-side" aria-label="应用分类">
        <n-button v-for="[k, label] in tabs" :key="k" quaternary block :aria-pressed="tab === k"
          :disabled="busy" @click="tab = k">{{ label }}</n-button>
      </aside>
      <div class="app-dialog-main">
        <div class="app-dialog-card">
          <span class="app-face">
            <span class="app-dialog-letter">{{ chosenInitial }}</span>
            <img v-if="store.chosenPkg && chosen && chosen.hasIcon !== false" :src="appIconUrl(store.chosenPkg, iconSerial, chosen.iconVersion)" alt=""
              @error="($event.target as HTMLElement).style.display = 'none'" />
          </span>
          <div class="app-dialog-id">
            <strong :title="chosenLabel">{{ chosenLabel }}</strong>
            <span v-if="chosenLabel!==store.chosenPkg || !store.chosenPkg" :title="store.chosenPkg">{{ store.chosenPkg || '从下方列表选择要观测的应用' }}</span>
          </div>
          <div class="app-dialog-actions">
            <template v-if="canControl">
              <n-button size="small" :loading="controlling === 'open'" :disabled="busy" @click="control('open')">打开</n-button>
              <n-button size="small" :loading="controlling === 'restart'" :disabled="busy" @click="control('restart')">重启</n-button>
              <n-button size="small" :loading="controlling === 'stop'" :disabled="busy" @click="control('stop')">结束</n-button>
            </template>
          </div>
        </div>
        <div class="dialog-search"><n-input v-model:value="q" clearable placeholder="搜索名称或包名" :input-props="{ 'aria-label': '搜索应用' }">
          <template #prefix><n-icon :component="SearchOutline" /></template>
        </n-input></div>
        <div class="app-choices">
          <n-alert v-if="toastMsg && messageType === 'error'" type="error" :show-icon="false"
            class="app-picker-message">{{ toastMsg }}</n-alert>
          <p v-else-if="toastMsg" class="app-picker-message app-picker-success" role="status">{{ toastMsg }}</p>
          <n-virtual-list v-if="apps.length" class="app-virtual" :items="apps" :item-size="52" key-field="package">
            <template #default="{ item: a }">
              <div class="app-row">
                <n-button quaternary class="app-item" :class="{ active: a.package === store.chosenPkg }"
                  :aria-pressed="a.package === store.chosenPkg" :title="`${a.label || a.package} · ${a.package}`"
                  :loading="picking === a.package" :disabled="busy" @click="pick(a.package)">
                  <span class="app-face">
                    <span class="app-dialog-letter">{{ itemInitial(a.label, a.package) }}</span>
                    <img v-if="a.hasIcon !== false" :src="appIconUrl(a.package, iconSerial, a.iconVersion)" alt="" loading="lazy"
                      @error="($event.target as HTMLElement).style.display = 'none'" />
                  </span>
                  <span class="app-copy">
                    <span class="app-name">{{ a.label || a.package }}</span>
                    <span v-if="a.label && a.label!==a.package" class="app-pkg">{{ a.package }}</span>
                  </span>
                  <span v-if="a.history" class="app-state">历史记录</span>
                  <span v-else-if="onlinePackages.has(a.package)" class="app-state on">采集在线</span>
                </n-button>
                <span v-if="tab!=='injected' && tab!=='history' && store.scope.has(a.package)" class="app-state">允许注入</span>
                <n-switch v-if="tab==='injected'" size="small" class="app-inject-sw" :aria-label="`允许注入 ${a.label || a.package}`" :value="store.scope.has(a.package)"
                  :loading="scopePending === a.package" :disabled="scopeDisabled(a.package)" :aria-disabled="scopeDisabled(a.package)"
                  :title="a.package === store.chosenPkg && store.scope.has(a.package) ? '当前观察应用不能移出注入范围' : '允许下次启动时注入'"
                  @update:value="on => toggleInject(a.package, !!on)" />
              </div>
            </template>
          </n-virtual-list>
          <div v-if="tab==='history' && historyLoading" class="app-empty" role="status">读取历史应用…</div>
          <div v-else-if="tab==='history' && historyError" class="app-empty" role="alert">{{ historyError }}</div>
          <div v-else-if="store.appsError && tab!=='history'" class="app-empty" role="alert">{{ store.appsError }}</div>
          <div v-else-if="!apps.length" class="app-empty" role="status">{{ tab==='history'&&!q.trim() ? '此设备没有已保留的历史记录' : store.appsFailed&&tab!=='history' ? '读取失败，保留上次清单' : emptyText }}</div>
        </div>
      </div>
    </div>
  </n-modal>
</template>

<style scoped>
.app-picker-layout { width:100%; height:100%; border:0; border-radius:0; }
.app-dialog-side .n-button { justify-content:flex-start; }
.app-dialog-side .n-button[aria-pressed="true"] { background:var(--surface-2); color:var(--ink); }
.app-dialog-card { flex:none; }
.app-dialog-id { overflow:hidden; }
.app-dialog-actions { flex:none; flex-wrap:wrap; }
.app-item { height:52px; }
.app-item :deep(.n-button__content) { display:flex; align-items:center; gap:10px; width:100%; min-width:0; }
.app-item .app-copy { text-align:left; overflow:hidden; }
.app-picker-message { flex:none; margin:0 6px 8px; overflow-wrap:anywhere; }
.app-picker-success { padding:8px 12px; color:var(--green); }
@media (max-width:700px) {
  .app-picker-layout { width:100%; height:100%; }
  .app-dialog-side .n-button { flex:1; width:auto; justify-content:center; }
  .app-dialog-actions { width:100%; justify-content:flex-end; }
  .app-item :deep(.n-button__content) { gap:8px; }
  .app-inject-sw { margin-right:8px; }
  .app-state { font-size:10px; }
}
</style>

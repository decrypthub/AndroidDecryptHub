<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NAlert, NModal, NVirtualList } from 'naive-ui';
import { SearchOutline } from '@vicons/ionicons5';
import { store, choosePackage, refreshScope } from '../store';
import { appIconUrl, scopeAdd, scopeRemove, appControl, observePackage, type AppInfo } from '../api';

const props = defineProps<{ show: boolean }>();
const emit = defineEmits<{ close: [] }>();
const tab = ref<'injected' | 'user' | 'system'>('user');
const q = ref('');
const toastMsg = ref('');
const messageType = ref<'success' | 'error'>('error');
const picking = ref('');
const scopePending = ref('');
const controlling = ref('');
const busy = computed(() => !!(picking.value || scopePending.value || controlling.value));

const tabs = [['injected', '已注入'], ['user', '个人应用'], ['system', '系统应用']] as const;

const apps = computed(() => {
  let list:AppInfo[] = store.apps;
  if (tab.value === 'injected') { const known=new Map(list.map(a=>[a.package,a]));list=[...onlinePackages.value].map(pkg=>known.get(pkg)??{package:pkg,label:pkg,hasIcon:false}); }
  else if (tab.value === 'user') list = list.filter(a => !a.system);
  else if (tab.value === 'system') list = list.filter(a => a.system);
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
  const serial=iconSerial.value;
  return new Set([...store.sessions.values()].filter(s=>s.online&&!!serial&&s.deviceBinding?.serial===serial).map(s=>s.package));
});
watch(() => props.show, open => {
  if(open){q.value='';tab.value=onlinePackages.value.size?'injected':'user';toastMsg.value='';}
},{immediate:true});
const canControl = computed(() => store.scope.has(store.chosenPkg)&&store.apps.some(a=>a.package===store.chosenPkg));
const emptyText = computed(() => q.value.trim() ? '没有匹配的应用' : tab.value==='injected'?'当前设备暂无在线注入应用':'没有应用');

watch(()=>store.selectedDeviceKey,()=>{q.value='';toastMsg.value='';});
function reportError(e: unknown, fallback: string) {
  messageType.value = 'error';
  toastMsg.value = e instanceof Error && e.message ? e.message : fallback;
}
function close() {
  if (!busy.value) emit('close');
}
function scopeDisabled(pkg: string) {
  return busy.value || store.scopeReady===false;
}
async function pick(pkg: string) {
  if (busy.value) return;
  picking.value = pkg;
  toastMsg.value = '';
  const dev = store.devices.find(d => d.key === store.selectedDeviceKey);
  const deviceKey = store.selectedDeviceKey;
  try {
    // 先确认观察请求，失败保留原应用/窗口；不能把未完成的切换显示成成功。
    if (store.localUsb) {
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
  <n-modal :show="show" preset="card" class="app-modal ui-window" title="选择应用" aria-label="应用" :bordered="false"
    :style="{width:'min(760px, calc(100vw - 24px))',height:'min(640px, calc(100dvh - 48px))'}"
    :content-style="{padding:'0',display:'flex',minHeight:'0',overflow:'hidden'}"
    :closable="!busy" :mask-closable="!busy" :close-on-esc="!busy" @update:show="!$event && close()">
    <div class="app-picker-simple" :aria-busy="busy">
      <nav class="app-picker-tabs ui-nav" aria-label="应用分类"><n-button v-for="[k,label] in tabs" :key="k" quaternary class="ui-nav-item" :aria-pressed="tab===k" :title="k==='injected'?'当前设备已连接的注入应用':undefined" :disabled="busy" @click="tab=k">{{ label }}</n-button></nav>
      <section class="app-picker-content">
      <div class="dialog-search"><n-input v-model:value="q" clearable placeholder="搜索名称或包名" :input-props="{'aria-label':'搜索应用'}"><template #prefix><n-icon :component="SearchOutline" /></template></n-input></div>
      <n-alert v-if="store.scopeError" type="warning" :show-icon="false" class="app-picker-message">注入状态读取失败：{{ store.scopeError }} <n-button text size="small" @click="refreshScope">重试</n-button></n-alert><p v-else-if="store.scopeReady===false" class="app-picker-message" role="status">读取注入状态…</p>
      <div class="app-list-heading"><span></span><span>允许注入</span></div>
      <n-alert v-if="toastMsg && messageType==='error'" type="error" :show-icon="false" class="app-picker-message">{{ toastMsg }}</n-alert><p v-else-if="toastMsg" class="app-picker-message app-picker-success" role="status">{{ toastMsg }}</p>
      <n-virtual-list v-if="apps.length" class="app-virtual" :items="apps" :item-size="64" key-field="package"><template #default="{item:a}">
        <div class="app-row"><n-button quaternary class="app-item" :class="{active:a.package===store.chosenPkg}" :aria-pressed="a.package===store.chosenPkg" :title="a.label||a.package" :loading="picking===a.package" :disabled="busy" @click="pick(a.package)">
          <span class="app-face"><span class="app-dialog-letter">{{ itemInitial(a.label,a.package) }}</span><img v-if="a.hasIcon!==false" :src="appIconUrl(a.package,iconSerial,a.iconVersion)" alt="" loading="lazy" @error="($event.target as HTMLElement).style.display='none'" /></span>
          <span class="app-copy"><span class="app-name">{{ a.label||a.package }}</span><span v-if="a.label&&a.label!==a.package" class="app-pkg">{{ a.package }}</span></span><span v-if="onlinePackages.has(a.package)" class="app-state on">采集在线</span>
        </n-button><n-switch class="app-inject-sw" size="small" :aria-label="'允许注入 '+(a.label||a.package)" :value="store.scope.has(a.package)" :loading="scopePending===a.package" :disabled="scopeDisabled(a.package)" :aria-disabled="scopeDisabled(a.package)" :title="store.scopeReady===false?'注入状态尚未确认':'允许下次启动时注入'" @update:value="on=>toggleInject(a.package,!!on)" /></div>
      </template></n-virtual-list><div v-else class="app-empty" :role="store.appsError?'alert':'status'">{{ store.appsError||emptyText }}</div>
      </section>
    </div>
  </n-modal>
</template>
<style scoped>
.app-picker-simple{display:flex;flex-direction:row;width:100%;min-height:0;color:var(--ink)}.app-picker-tabs{display:flex;flex-direction:column;width:132px;flex:none;gap:4px;padding:12px 8px;border-right:1px solid var(--line);background:var(--bg)}.dialog-search{padding:16px 18px 10px}.app-list-heading{display:flex;justify-content:space-between;padding:0 22px 6px;color:var(--muted);font-size:12px}.app-virtual{flex:1;min-height:0;padding:0 10px 10px}.app-row{display:flex;align-items:center;gap:14px;min-height:64px;padding-right:14px}.app-item{flex:1;min-width:0;height:64px;padding:8px 10px}.app-item :deep(.n-button__content){display:flex;align-items:center;gap:12px;width:100%;min-width:0}.app-face{width:36px;height:36px;flex:none}.app-face img,.app-dialog-letter{width:36px;height:36px;border-radius:8px}.app-copy{display:flex;flex-direction:column;gap:3px;min-width:0;text-align:left;flex:1}.app-name,.app-pkg{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.app-name{font-size:13px;font-weight:500}.app-pkg{font-size:11px;color:var(--muted)}.app-state{font-size:12px;flex:none;color:var(--green)}.app-inject-sw{flex:none}.app-picker-message{margin:0 18px 10px}.app-empty{padding:60px 20px;text-align:center;color:var(--muted)}
@media(max-width:500px){.app-row{gap:8px;padding-right:8px}.app-state{display:none}.app-picker-tabs{padding-inline:12px}.dialog-search{padding-inline:12px}.app-name{font-size:13px}}
.app-picker-content{display:flex;flex-direction:column;flex:1;min-width:0;min-height:0;overflow:hidden}.app-picker-tabs .n-button :deep(.n-button__content){justify-content:flex-start;width:100%}
@media(max-width:520px){.app-picker-tabs{width:100px;padding:10px 6px}}
</style>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { store, choosePackage } from '../store';
import { appIconUrl, scopeAdd, scopeRemove, appControl, observePackage } from '../api';

const emit = defineEmits<{ close: [] }>();
const tab = ref<'user' | 'system' | 'injected'>('user');
const q = ref('');
const toast = ref('');

const apps = computed(() => {
  let list = store.apps;
  if (tab.value === 'user') list = list.filter(a => !a.system);
  else if (tab.value === 'system') list = list.filter(a => a.system);
  else list = list.filter(a => store.scope.has(a.package));
  const s = q.value.trim().toLowerCase();
  if (s) list = list.filter(a =>
    (a.package + ' ' + (a.label ?? '')).toLowerCase().includes(s));
  return list;
});

function pick(pkg: string) {
  choosePackage(pkg);
  // 本地观察设备：选包即 observe
  const dev = store.devices.find(d => d.key === store.selectedDeviceKey);
  if (dev?.serial && store.localUsb) void observePackage(dev.serial, pkg);
  emit('close');
}
async function toggleInject(pkg: string, on: boolean) {
  try {
    const r = await (on ? scopeAdd(pkg) : scopeRemove(pkg)) as { ok?: boolean; error?: string };
    if (r?.ok === false) { toast.value = r.error ?? '写入失败'; return; }
    if (on) store.scope.add(pkg); else store.scope.delete(pkg);
  } catch { toast.value = '写入失败'; }
}
async function control(action: 'open' | 'stop' | 'restart') {
  const pkg = store.chosenPkg;
  if (!pkg) return;
  const labels = { open: '已打开', stop: '已结束', restart: '已重启' };
  try {
    const r = await appControl(pkg, action) as { ok?: boolean; error?: string };
    toast.value = r?.ok === false ? (r.error ?? '手机没有完成这个操作') : labels[action];
  } catch { toast.value = '手机没有完成这个操作'; }
}
const canControl = computed(() => store.scope.has(store.chosenPkg));
</script>

<template>
  <div class="dlg-mask" @click.self="emit('close')">
    <div class="dlg app-dialog">
      <div class="dlg-head">
        <img :src="appIconUrl(store.chosenPkg)" class="app-icon" alt="" v-if="store.chosenPkg" @error="($event.target as HTMLElement).style.visibility='hidden'" />
        <div class="dlg-title">
          <b class="mono">{{ store.chosenPkg || '选择应用' }}</b>
          <span v-if="toast" class="muted">{{ toast }}</span>
        </div>
        <div class="dlg-actions" v-if="canControl">
          <button class="btn sm" @click="control('open')">打开</button>
          <button class="btn sm" @click="control('restart')">重启</button>
          <button class="btn sm danger" @click="control('stop')">结束</button>
        </div>
        <button class="btn sm" @click="emit('close')">✕</button>
      </div>

      <div class="dlg-tabs">
        <button v-for="[k, label] in [['user','应用'],['system','系统'],['injected','已注入']] as const"
          :key="k" class="chip" :class="{ on: tab === k }" @click="tab = k">{{ label }}</button>
        <input v-model="q" class="dlg-search" placeholder="搜索包名 / 名称" />
      </div>

      <div class="app-choices">
        <div v-for="a in apps" :key="a.package" class="app-choice" :class="{ on: a.package === store.chosenPkg }">
          <img :src="appIconUrl(a.package)" class="app-icon" alt="" loading="lazy"
            @error="($event.target as HTMLElement).style.display='none'" />
          <button class="app-choice-main" @click="pick(a.package)">
            <span class="app-label">{{ a.label || a.package }}</span>
            <span class="mono muted">{{ a.package }}</span>
          </button>
          <button class="chip" :class="{ on: store.scope.has(a.package) }"
            :aria-pressed="store.scope.has(a.package)"
            @click="toggleInject(a.package, !store.scope.has(a.package))">注入</button>
        </div>
        <div v-if="store.appsError" class="muted pad">{{ store.appsError }}</div>
        <div v-else-if="!apps.length" class="muted pad">{{ store.appsFailed ? '读取失败，保留上次清单' : '没有应用' }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dlg-mask { position: fixed; inset: 0; background: #000a; z-index: 50; display: flex; align-items: flex-start; justify-content: center; padding-top: 8dvh; }
.dlg { width: min(720px, 92vw); max-height: 80dvh; display: flex; flex-direction: column; background: var(--surface); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
.dlg-head { display: flex; align-items: center; gap: 10px; padding: 14px 16px; border-bottom: 1px solid var(--line-soft); }
.dlg-title { flex: 1; display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.dlg-actions { display: flex; gap: 6px; }
.dlg-tabs { display: flex; align-items: center; gap: 8px; padding: 10px 16px; border-bottom: 1px solid var(--line-soft); }
.dlg-search { flex: 1; }
.app-icon { width: 28px; height: 28px; border-radius: 6px; }
.app-choices { overflow: auto; padding: 8px; }
.app-choice { display: flex; align-items: center; gap: 10px; padding: 7px 8px; border-radius: 9px; }
.app-choice:hover { background: var(--surface-2); }
.app-choice.on { background: var(--surface-3); }
.app-choice-main { flex: 1; display: flex; flex-direction: column; gap: 1px; border: 0; background: none; color: var(--ink-2); cursor: pointer; text-align: left; min-width: 0; }
.app-label { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pad { padding: 16px; }
</style>

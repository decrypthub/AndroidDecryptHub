<script setup lang="ts">
import { computed, ref } from 'vue';
import { store, choosePackage } from '../store';
import { appIconUrl, scopeAdd, scopeRemove, appControl, observePackage } from '../api';

const emit = defineEmits<{ close: [] }>();
const tab = ref<'user' | 'system' | 'injected'>('user');
const q = ref('');
const toastMsg = ref('');

const tabs = [['user', '应用'], ['system', '系统'], ['injected', '已注入']] as const;

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
const chosen = computed(() => store.apps.find(a => a.package === store.chosenPkg));
const chosenLabel = computed(() => chosen.value?.label || store.chosenPkg || '未选择应用');
const chosenInitial = computed(() => (chosenLabel.value[0] ?? '?'));
const itemInitial = (label?: string, pkg?: string) => ((label || pkg || '?')[0] ?? '?');

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
    if (r?.ok === false) { toastMsg.value = r.error ?? '写入失败'; return; }
    if (on) store.scope.add(pkg); else store.scope.delete(pkg);
  } catch { toastMsg.value = '写入失败'; }
}
async function control(action: 'open' | 'stop' | 'restart') {
  const pkg = store.chosenPkg;
  if (!pkg) return;
  const labels = { open: '已打开', stop: '已结束', restart: '已重启' };
  try {
    const r = await appControl(pkg, action) as { ok?: boolean; error?: string };
    toastMsg.value = r?.ok === false ? (r.error ?? '手机没有完成这个操作') : labels[action];
  } catch { toastMsg.value = '手机没有完成这个操作'; }
}
const canControl = computed(() => store.scope.has(store.chosenPkg));
</script>

<template>
  <div class="modal-mask show" @click.self="emit('close')">
    <div class="app-dialog show">
      <aside class="app-dialog-side">
        <h2>应用</h2>
        <button v-for="[k, label] in tabs" :key="k" type="button" :aria-pressed="tab === k"
          @click="tab = k">{{ label }}</button>
      </aside>
      <div class="app-dialog-main">
        <div class="app-dialog-card">
          <span class="app-face">
            <span class="app-dialog-letter">{{ chosenInitial }}</span>
            <img v-if="store.chosenPkg" :src="appIconUrl(store.chosenPkg)" alt=""
              @error="($event.target as HTMLElement).style.display = 'none'" />
          </span>
          <div class="app-dialog-id">
            <strong>{{ chosenLabel }}</strong>
            <span>{{ store.chosenPkg || '从下方列表选择要观测的应用' }}</span>
          </div>
          <div class="app-dialog-actions">
            <template v-if="canControl">
              <button type="button" @click="control('open')">打开</button>
              <button type="button" @click="control('restart')">重启</button>
              <button type="button" @click="control('stop')">结束</button>
            </template>
            <button type="button" class="set-close-x" @click="emit('close')">
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"
                stroke-linecap="round">
                <path d="M4 4l8 8M12 4l-8 8" /></svg>
            </button>
          </div>
        </div>
        <input v-model="q" class="app-menu-search" placeholder="搜索包名 / 名称" />
        <div class="app-choices">
          <div v-if="toastMsg" class="app-empty">{{ toastMsg }}</div>
          <div v-for="a in apps" :key="a.package" class="app-row">
            <button type="button" class="app-item" :class="{ active: a.package === store.chosenPkg }"
              @click="pick(a.package)">
              <span class="app-face">
                <span class="app-dialog-letter">{{ itemInitial(a.label, a.package) }}</span>
                <img :src="appIconUrl(a.package)" alt="" loading="lazy"
                  @error="($event.target as HTMLElement).style.display = 'none'" />
              </span>
              <span class="app-copy">
                <span class="app-name">{{ a.label || a.package }}</span>
                <span class="app-pkg">{{ a.package }}</span>
              </span>
              <span class="app-state" :class="{ on: store.scope.has(a.package) }">
                {{ store.scope.has(a.package) ? '已注入' : '' }}</span>
            </button>
            <button type="button" class="app-inject" title="允许注入" :aria-pressed="store.scope.has(a.package)"
              :disabled="a.package === store.chosenPkg && store.scope.has(a.package)"
              @click="toggleInject(a.package, !store.scope.has(a.package))"></button>
          </div>
          <div v-if="store.appsError" class="app-empty">{{ store.appsError }}</div>
          <div v-else-if="!apps.length" class="app-empty">{{ store.appsFailed ? '读取失败，保留上次清单' : '没有应用' }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

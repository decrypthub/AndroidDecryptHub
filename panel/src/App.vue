<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue';
import { store, selectDevice } from './store';
import { perfLast, perfStats } from './api';
import DeviceMenu from './components/DeviceMenu.vue';
import AppDialog from './components/AppDialog.vue';
import CapturePanel from './components/CapturePanel.vue';
import FilesPanel from './components/FilesPanel.vue';
import DumpPanel from './components/DumpPanel.vue';
import SettingsPanel from './components/SettingsPanel.vue';

const tabs = [
  ['cc', '加解密'], ['sy', '系统'], ['nt', '网络'],
  ['files', '文件'], ['dump', '脱壳'], ['settings', '设置'],
] as const;

// 顶栏耗时显示：跟随 perfLast，1s 刷一次显示
const perfText = ref('');
const perfTitle = ref('');
let perfTimer = 0;
onMounted(() => {
  perfTimer = window.setInterval(() => {
    const l = perfLast();
    perfText.value = l.label ? `${l.label} ${Math.round(l.ms)}ms` : '';
    perfTitle.value = [...perfStats().entries()]
      .sort((a, b) => b[1].total - a[1].total)
      .map(([k, s]) => `${k}\t最近 ${Math.round(s.last)}ms\t均 ${Math.round(s.total / s.n)}ms\t峰 ${Math.round(s.peak)}ms\t×${s.n}`)
      .join('\n');
  }, 1000);
});
onUnmounted(() => clearInterval(perfTimer));

const logoUrl = '/raven.svg'; // 运行期 URL，不走 vite 资源打包
const wsText = computed(() =>
  store.wsState === 'live' ? '电脑服务在线' : store.wsState === 'fail' ? '连接异常' : '离线');
const wsCls = computed(() => `status-dot ${store.wsState === 'live' ? 'ok' : 'bad'}`);
</script>

<template>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <img :src="logoUrl" alt="" class="brand-logo" />
        <span class="brand-name">ADH</span>
      </div>

      <DeviceMenu :devices="store.devices" :failed="store.devicesFailed" :selected="store.selectedDeviceKey"
        @select="selectDevice" />

      <button class="btn app-picker" @click="store.appDialogOpen = true">
        <span class="mono">{{ store.chosenPkg || '选择应用' }}</span>
      </button>

      <nav class="view-tabs">
        <button v-for="[k, label] in tabs" :key="k" class="tab" :class="{ on: store.view === k }"
          @click="store.view = k">{{ label }}</button>
      </nav>

      <div class="top-right">
        <span class="perf-stat mono" :title="perfTitle">{{ perfText }}</span>
        <span :class="wsCls"></span>
        <span class="conn-text">{{ wsText }}</span>
        <span v-if="store.devicesFailed" class="badge fail">读取失败</span>
      </div>
    </header>

    <main class="panel-body">
      <CapturePanel v-if="store.view === 'cc'" kind="crypto" />
      <CapturePanel v-else-if="store.view === 'sy'" kind="system" />
      <CapturePanel v-else-if="store.view === 'nt'" kind="net" />
      <FilesPanel v-else-if="store.view === 'files'" />
      <DumpPanel v-else-if="store.view === 'dump'" />
      <SettingsPanel v-else-if="store.view === 'settings'" />
    </main>

    <AppDialog v-if="store.appDialogOpen" @close="store.appDialogOpen = false" />
  </div>
</template>

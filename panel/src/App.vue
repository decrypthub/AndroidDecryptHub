<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue';
import { darkTheme, type GlobalThemeOverrides } from 'naive-ui';
import { store, selectDevice, toasts, belongsToApp, capVisible, panelDisplay, savePanelDisplay } from './store';
import { perfLast, perfStats } from './api';
import DeviceMenu from './components/DeviceMenu.vue';
import AppDialog from './components/AppDialog.vue';
import CapturePanel from './components/CapturePanel.vue';
import FilesPanel from './components/FilesPanel.vue';
import DumpPanel from './components/DumpPanel.vue';
import SettingsPanel from './components/SettingsPanel.vue';

type ViewKey = 'cc' | 'sy' | 'nt' | 'files' | 'dump' | 'settings';
const ICONS: Record<string, string> = {
  cc: '<rect x="4" y="8" width="12" height="9" rx="2"/><path d="M7 8V6a3 3 0 0 1 6 0v2m-3 4v2"/>',
  sy: '<rect x="4" y="4" width="12" height="12" rx="2"/><rect x="8" y="8" width="4" height="4"/><path d="M7 2v2m6-2v2M7 16v2m6-2v2M2 7h2m-2 6h2m12-6h2m-2 6h2"/>',
  nt: '<path d="M3 7a11 11 0 0 1 14 0M5.5 10a7 7 0 0 1 9 0m-6.5 3a3 3 0 0 1 4 0m-2 3h.01"/>',
  files: '<path d="M2.5 6A1.5 1.5 0 0 1 4 4.5h4l2 2h6A1.5 1.5 0 0 1 17.5 8v6.5A1.5 1.5 0 0 1 16 16H4a1.5 1.5 0 0 1-1.5-1.5Z"/>',
  dump: '<path d="M4 4h12v4H4zM5.5 8v8h9V8m-6.5 3h4"/>',
  settings: '<circle cx="10" cy="10" r="2.6"/><path d="M10 2.5v2.2M10 15.3v2.2M17.5 10h-2.2M4.7 10H2.5M15.3 4.7 14 6.1M6 13.9l-1.3 1.4M15.3 15.3 14 14M6 6.1 4.7 4.7"/>',
  collapse: '<path d="M12.5 4.5 7 10l5.5 5.5"/>',
};
const NAV: Array<{ key: ViewKey; label: string; count?: 'cc' | 'sy' | 'nt' }> = [
  { key: 'cc', label: '加解密', count: 'cc' },
  { key: 'sy', label: '系统', count: 'sy' },
  { key: 'nt', label: '网络', count: 'nt' },
  { key: 'files', label: '文件' },
  { key: 'dump', label: '脱壳' },
];

// 侧栏计数：当前应用下各类别的可见记录数
const counts = computed(() => {
  const c = { cc: 0, sy: 0, nt: 0 };
  for (const it of store.capItems) {
    if (!belongsToApp(it) || !capVisible(it)) continue;
    if (it.category === 'crypto') c.cc++;
    else if (it.category === 'net') c.nt++;
    else c.sy++;
  }
  return c;
});
const navCount = (k?: 'cc' | 'sy' | 'nt') => (k ? counts.value[k] || '' : '');

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

const wsText = computed(() =>
  store.wsState === 'live' ? '电脑服务在线' : store.wsState === 'fail' ? '连接异常' : '正在连接…');
const wsCls = computed(() =>
  `status-dot ${store.wsState === 'live' ? 'ok' : store.wsState === 'fail' ? 'bad' : ''}`);

const chosenApp = computed(() => store.apps.find(a => a.package === store.chosenPkg));
const appLabel = computed(() => chosenApp.value?.label || (store.chosenPkg ? '当前应用' : '未选择 APP'));
const appInitial = computed(() => (appLabel.value[0] ?? '?'));

function toggleRail() {
  savePanelDisplay({ ...panelDisplay, rail: !panelDisplay.rail });
}

// Naive 主题对齐面板色板：蓝 #78a9ff、面 #0f1218、边 #343b48、13px 基础字号
const themeOverrides: GlobalThemeOverrides = {
  common: {
    primaryColor: '#78a9ff',
    primaryColorHover: '#95bcff',
    primaryColorPressed: '#5d92f5',
    primaryColorSuppl: '#78a9ff',
    borderRadius: '6px',
    borderRadiusSmall: '5px',
    fontSize: '13px',
    bodyColor: '#06070a',
    cardColor: '#0f1218',
    modalColor: '#0f1218',
    popoverColor: '#151922',
    inputColor: 'rgba(255,255,255,0.04)',
    borderColor: '#343b48',
    dividerColor: '#20252e',
    textColorBase: '#e5e8ee',
  },
  Radio: { buttonBorderColor: '#343b48' },
};
</script>

<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides">
  <div class="app-shell">
    <aside class="side" :class="{ rail: panelDisplay.rail }">
      <div class="side-brand">
        <span class="hdr-mark"><img src="/raven.svg" alt=""></span>
        <span class="side-title">ADH</span>
      </div>
      <nav class="side-nav">
        <div class="side-group">观测</div>
        <button v-for="item in NAV" :key="item.key" class="side-item" :title="item.label"
          :class="{ active: store.view === item.key }" @click="store.view = item.key">
          <svg class="side-icon" viewBox="0 0 20 20" v-html="ICONS[item.key]" />
          <span class="side-label">{{ item.label }}</span>
          <span class="side-n">{{ navCount(item.count) }}</span>
        </button>
      </nav>
      <div class="side-foot">
        <button class="side-item" :class="{ active: store.view === 'settings' }" title="设置"
          @click="store.view = 'settings'">
          <svg class="side-icon" viewBox="0 0 20 20" v-html="ICONS.settings" />
          <span class="side-label">设置</span>
        </button>
        <button class="side-item side-collapse" :title="panelDisplay.rail ? '展开导航' : '收起导航'"
          @click="toggleRail">
          <svg class="side-icon" viewBox="0 0 20 20" v-html="ICONS.collapse" />
          <span class="side-label">收起</span>
        </button>
      </div>
    </aside>

    <div class="main-col">
      <header class="topbar">
        <div class="stats">
          <span :class="wsCls"></span>
          <span>{{ wsText }}</span>
          <span v-if="store.devicesFailed" class="badge fail">读取失败</span>
          <span class="perf-stat" :title="perfTitle">{{ perfText }}</span>
        </div>
        <DeviceMenu :devices="store.devices" :failed="store.devicesFailed" :selected="store.selectedDeviceKey"
          @select="selectDevice" />
        <div class="header-actions">
          <section class="app-context">
            <button type="button" class="process-trigger" title="应用" @click="store.appDialogOpen = true">
              <span class="proc-primary">
                <span class="app-face proc-face">
                  <span class="app-dialog-letter">{{ appInitial }}</span>
                  <img v-if="store.chosenPkg" :src="'/api/apps/icon?v=2&package=' + encodeURIComponent(store.chosenPkg)"
                    alt="" @error="($event.target as HTMLElement).style.display = 'none'" />
                </span>
                <span class="proc-text">
                  <span id="procLabel">{{ appLabel }}</span>
                  <span class="proc-pkg">{{ store.chosenPkg }}</span>
                </span>
              </span>
              <span class="menu-chevron"><svg viewBox="0 0 12 12" width="10" height="10" fill="none"
                  stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M2.5 4.5l3.5 3.5 3.5-3.5" /></svg></span>
            </button>
          </section>
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
    </div>

    <AppDialog v-if="store.appDialogOpen" @close="store.appDialogOpen = false" />
    <div class="toast-stack">
      <div v-for="t in toasts" :key="t.id" class="toast">{{ t.text }}</div>
    </div>
  </div>
  </n-config-provider>
</template>

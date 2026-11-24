<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue';
import { darkTheme, type GlobalThemeOverrides } from 'naive-ui';
import type { Component } from 'vue';
import {
  LockClosedOutline, HardwareChipOutline, WifiOutline, FolderOutline, CubeOutline,
  SettingsOutline, ChevronBackOutline, ChevronDownOutline,
} from '@vicons/ionicons5';
import { store, selectDevice, toasts, belongsToApp, capVisible, panelDisplay, savePanelDisplay } from './store';
import { perfLast, perfStats } from './api';
import DeviceMenu from './components/DeviceMenu.vue';
import AppDialog from './components/AppDialog.vue';
import CapturePanel from './components/CapturePanel.vue';
import FilesPanel from './components/FilesPanel.vue';
import DumpPanel from './components/DumpPanel.vue';
import SettingsPanel from './components/SettingsPanel.vue';

type ViewKey = 'cc' | 'sy' | 'nt' | 'files' | 'dump' | 'settings';
const ICONS: Record<string, Component> = {
  cc: LockClosedOutline, sy: HardwareChipOutline, nt: WifiOutline,
  files: FolderOutline, dump: CubeOutline, settings: SettingsOutline,
  collapse: ChevronBackOutline,
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
          <n-icon class="side-icon" size="16" :component="ICONS[item.key]" />
          <span class="side-label">{{ item.label }}</span>
          <span class="side-n">{{ navCount(item.count) }}</span>
        </button>
      </nav>
      <div class="side-foot">
        <button class="side-item" :class="{ active: store.view === 'settings' }" title="设置"
          @click="store.view = 'settings'">
          <n-icon class="side-icon" size="16" :component="ICONS.settings" />
          <span class="side-label">设置</span>
        </button>
        <button class="side-item side-collapse" :title="panelDisplay.rail ? '展开导航' : '收起导航'"
          @click="toggleRail">
          <n-icon class="side-icon" size="16" :component="ICONS.collapse" />
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
              <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
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

<script setup lang="ts">
import { useAppearance, isDark } from './appearance';
useAppearance();
import { computed } from 'vue';
import { darkTheme, NAlert, type GlobalThemeOverrides } from 'naive-ui';
import type { Component } from 'vue';
import {
  LockClosedOutline, HardwareChipOutline, WifiOutline, FolderOutline, CubeOutline,
  SettingsOutline, ChevronBackOutline, ChevronDownOutline,
} from '@vicons/ionicons5';
import { store, selectDevice, toasts, belongsToApp, capVisible, panelDisplay, savePanelDisplay } from './store';
import { appIconUrl } from './api';
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
const NAV: Array<{ key: ViewKey; label: string; count?: 'cc' | 'sy' | 'nt' | 'ff' }> = [
  { key: 'cc', label: '加解密', count: 'cc' },
  { key: 'sy', label: '系统', count: 'sy' },
  { key: 'nt', label: '网络', count: 'nt' },
  { key: 'files', label: '文件', count: 'ff' },
  { key: 'dump', label: '脱壳' },
];

// 侧栏计数：当前应用下各类别的可见记录数
const counts = computed(() => {
  const c = { cc: 0, sy: 0, nt: 0, ff: 0 };
  for (const it of store.capItems) {
    if (!belongsToApp(it) || !capVisible(it)) continue;
    if (it.category === 'crypto') c.cc++;
    else if (it.category === 'net') c.nt++;
    else if (it.category === 'file') c.ff++;
    else c.sy++;
  }
  return c;
});
const navCount = (k?: 'cc' | 'sy' | 'nt' | 'ff') => (k ? counts.value[k] || '' : '');

const wsText = computed(() =>
  store.wsState === 'live' ? '电脑服务在线' : store.wsState === 'fail' ? '连接异常' : '正在连接…');
const wsCls = computed(() =>
  `status-dot ${store.wsState === 'live' ? 'ok' : store.wsState === 'fail' ? 'bad' : ''}`);

const chosenApp = computed(() => store.apps.find(a => a.package === store.chosenPkg));
const appLabel = computed(() => chosenApp.value?.label || (store.chosenPkg ? '当前应用' : '未选择 APP'));
const appInitial = computed(() => (appLabel.value[0] ?? '?'));
const iconSerial = computed(() => store.devices.find(d => d.key === store.selectedDeviceKey)?.serial || '');

const boardOptions = [...NAV.map(({ key: value, label }) => ({ value, label })), { value: 'settings', label: '设置' }];

function toggleRail() {
  savePanelDisplay({ ...panelDisplay, rail: !panelDisplay.rail });
}

// Use the same surface tokens for Naive's teleported menus, inputs and dialogs.
const themeOverrides = computed<GlobalThemeOverrides>(() => {
  const fg = isDark.value ? '#f4f6f8' : '#111315';
  const paper = isDark.value ? '#141619' : '#ffffff';
  const border = isDark.value ? '#383c42' : '#d3d6da';
  return {
    common: { primaryColor:fg, primaryColorSuppl:fg, primaryColorHover:isDark.value?'#d2d6db':'#393e42',
      primaryColorPressed:isDark.value?'#c8cbd0':'#090b0d', textColorBase:fg, bodyColor:isDark.value?'#090b0d':'#fbfcfd',
      cardColor:paper, modalColor:paper, popoverColor:paper, inputColor:paper, borderColor:border,
      dividerColor:isDark.value?'#282d32':'#e7e8ea', borderRadius:'5px', fontSize:'13px' },
    Button:{textColorPrimary:paper,textColorHoverPrimary:paper,textColorPressedPrimary:paper},
    Radio: {
      buttonColor:paper, buttonColorActive:fg, buttonTextColorActive:paper, buttonTextColorHover:fg,
      buttonBorderColor:border, buttonBorderColorActive:fg,
    },
    Checkbox: { checkMarkColor:paper },
    Switch: {
      railColor:isDark.value?'#50565d':'#9bA1a7', railColorActive:isDark.value?'#417761':'#346851',
      buttonColor:'#fff',
    },
  };
});
</script>

<template>
  <n-config-provider :theme="isDark ? darkTheme : null" :theme-overrides="themeOverrides">
  <div class="app-shell">
    <aside class="side" :class="{ rail: panelDisplay.rail }">
      <div class="side-brand">
        <span class="hdr-mark"><img src="/raven.svg" alt=""></span>
        <span class="side-title">ADH</span>
      </div>
      <nav class="side-nav" aria-label="主导航">
        <n-button v-for="item in NAV" :key="item.key" quaternary block class="rail-action"
          :class="{ selected: store.view === item.key }" :title="item.label" :aria-label="item.label"
          :aria-current="store.view === item.key ? 'page' : undefined" @click="store.view = item.key">
          <span class="rail-line"><n-icon size="17" :component="ICONS[item.key]" />
            <span class="rail-caption">{{ item.label }}</span><small v-if="navCount(item.count)">{{ navCount(item.count) }}</small>
          </span>
        </n-button>
      </nav>
      <div class="side-foot">
        <n-button quaternary block class="rail-action" :class="{ selected: store.view === 'settings' }"
          title="设置" aria-label="设置" :aria-current="store.view === 'settings' ? 'page' : undefined" @click="store.view = 'settings'">
          <span class="rail-line"><n-icon size="17" :component="ICONS.settings" /><span class="rail-caption">设置</span></span>
        </n-button>
        <n-button quaternary block class="rail-action side-collapse" :aria-expanded="!panelDisplay.rail"
          :title="panelDisplay.rail ? '展开导航' : '收起导航'" :aria-label="panelDisplay.rail ? '展开导航' : '收起导航'" @click="toggleRail">
          <span class="rail-line"><n-icon size="17" :component="ICONS.collapse" /><span class="rail-caption">收起</span></span>
        </n-button>
      </div>
    </aside>

    <div class="main-col">
      <header class="topbar">
        <div class="mobile-board-picker"><n-select v-model:value="store.view" size="small" aria-label="切换板块" :options="boardOptions" /></div>
        <div class="stats">
          <span :class="wsCls"></span>
          <span>{{ wsText }}</span>
          <span v-if="store.devicesFailed" class="badge fail">读取失败</span>
        </div>
        <DeviceMenu :devices="store.devices" :failed="store.devicesFailed" :selected="store.selectedDeviceKey"
          @select="selectDevice" />
        <div class="header-actions">
          <section class="app-context">
            <button type="button" class="process-trigger" title="应用" @click="store.appDialogOpen = true">
              <span class="proc-primary">
                <span class="app-face proc-face">
                  <span class="app-dialog-letter">{{ appInitial }}</span>
                  <img v-if="store.chosenPkg && chosenApp && chosenApp.hasIcon !== false" :src="appIconUrl(store.chosenPkg, iconSerial, chosenApp.iconVersion)"
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

    <AppDialog :show="store.appDialogOpen" @close="store.appDialogOpen = false" />
    <div class="panel-messages" role="status" aria-live="polite">
      <TransitionGroup name="notice">
        <n-alert v-for="t in toasts" :key="t.id" :show-icon="false">{{ t.text }}</n-alert>
      </TransitionGroup>
    </div>
  </div>
  </n-config-provider>
</template>

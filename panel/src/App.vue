<script setup lang="ts">
import { useAppearance, isDark } from './appearance';
useAppearance();
import { computed, watch } from 'vue';
import { darkTheme, NAlert, NModal, type GlobalThemeOverrides } from 'naive-ui';
import type { Component } from 'vue';
import {
  LockClosedOutline, HardwareChipOutline, WifiOutline, FolderOutline, CubeOutline,
  SettingsOutline, ChevronBackOutline, ChevronDownOutline,
} from '@vicons/ionicons5';
import { store, selectDevice, toasts, panelDisplay, savePanelDisplay } from './store';
import { appIconUrl } from './api';
import DeviceDialog from './components/DeviceDialog.vue';
import AppDialog from './components/AppDialog.vue';
import AppLifecycleControl from './components/AppLifecycleControl.vue';
import BoardCaptureControl from './components/BoardCaptureControl.vue';
import HelpDialog from './components/HelpDialog.vue';
import type {CaptureBoard} from '../../daemon/src/capture_boards';
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
const NAV: Array<{ key: ViewKey; label: string }> = [
  { key: 'cc', label: '加解密' },
  { key: 'sy', label: '系统' },
  { key: 'nt', label: '网络' },
  { key: 'files', label: '文件' },
  { key: 'dump', label: '脱壳' },
];

// 页面内部不再画标题（侧栏高亮已经说明当前板块），板块名留在标签页/Tab 标题上，
// 这样多开几个面板时仍能分清谁是谁，读屏也还能拿到页面名。
const VIEW_TITLES: Record<ViewKey, string> = {
  cc: '加解密', sy: '系统', nt: '网络', files: '文件', dump: '脱壳', settings: '设置',
};
watch(() => store.view, (v,previous) => { if(v==='settings'){store.view=previous&&previous!=='settings'?previous:'cc';store.settingsOpen=true;return;}document.title=`ADH · ${VIEW_TITLES[v]??''}`; }, { immediate: true });

const wsText = computed(() =>
  (store.wsState === 'live' ? '电脑服务在线' : store.wsState === 'fail' ? '连接异常' : '正在连接…')+(store.devicesFailed?' · 设备列表读取失败':''));
const wsCls = computed(() =>
  `status-dot ${store.wsState === 'live' ? 'ok' : store.wsState === 'fail' ? 'bad' : ''}`);

const chosenApp = computed(() => store.apps.find(a => a.package === store.chosenPkg));
const appLabel = computed(() => chosenApp.value?.label || (store.chosenPkg ? store.chosenPkg.split('.').pop() || store.chosenPkg : '未选择 APP'));
const appInitial = computed(() => (appLabel.value[0] ?? '?'));
const iconSerial = computed(() => store.devices.find(d => d.key === store.selectedDeviceKey)?.serial || '');

const panels = {cc:CapturePanel,sy:CapturePanel,nt:CapturePanel,files:FilesPanel,dump:DumpPanel,settings:SettingsPanel};
const activePanel = computed(() => panels[store.view]);
const captureKind = computed(() => ({cc:'crypto',sy:'system',nt:'net'} as Record<string,CaptureBoard>)[store.view]);
const boardOptions = [...NAV.map(({ key: value, label }) => ({ value, label })), { value: 'settings', label: '设置' }];

function countKey(key:string):'crypto'|'system'|'net'|null{return ({cc:'crypto',sy:'system',nt:'net'} as const)[key as 'cc'|'sy'|'nt']??null;}
function toggleRail() {
  savePanelDisplay({ ...panelDisplay, rail: !panelDisplay.rail });
}

// Use the same surface tokens for Naive's teleported menus, inputs and dialogs.
const themeOverrides = computed<GlobalThemeOverrides>(() => {
  const fg = isDark.value ? '#ececf1' : '#0d0d0d';
  const paper = isDark.value ? '#171717' : '#ffffff';
  const border = isDark.value ? '#2a2a2a' : '#e5e5e5';
  // Official site: monochrome controls; green is a signal/link/focus color.
  const accent = fg;
  const focus = isDark.value ? '#10a37f' : '#0b7a5f';
  return {
    common: { primaryColor:accent, primaryColorSuppl:accent, primaryColorHover:isDark.value?'#ffffff':'#333333',
      primaryColorPressed:fg, textColorBase:fg, bodyColor:isDark.value?'#0d0d0d':'#ffffff',
      cardColor:paper, modalColor:paper, popoverColor:paper, inputColor:paper, borderColor:border,
      dividerColor:isDark.value?'#2a2a2a':'#ececf1', borderRadius:'4px', fontSize:'13px',
      fontFamily:'"ADH Sans","Noto Sans SC",-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif' },
    Input:{color:paper,colorHover:paper,colorFocus:paper,textColor:fg,placeholderColor:isDark.value?'#8e8ea0':'#6e6e80',
      border:'1px solid '+border,borderHover:'1px solid '+accent,borderFocus:'1px solid '+focus,
      boxShadowFocus:'none',heightSmall:'32px',heightMedium:'34px'},
    Select:{peers:{InternalSelection:{color:paper,colorActive:paper,textColor:fg,
      border:'1px solid '+border,borderHover:'1px solid '+accent,borderActive:'1px solid '+accent,borderFocus:'1px solid '+focus,
      heightSmall:'32px',heightMedium:'34px',borderRadius:'4px'}}},
    Button:{textColorPrimary:paper,textColorHoverPrimary:paper,textColorPressedPrimary:paper},
    Radio: {
      buttonColor:paper, buttonColorActive:accent, buttonTextColorActive:paper, buttonTextColorHover:fg,
      buttonBorderColor:border, buttonBorderColorActive:accent,
    },
    Checkbox: { checkMarkColor:paper },
    Switch: {
      railColor:isDark.value?'#8e8ea0':'#6e6e80', railColorActive:fg,
      buttonColor:isDark.value?'#0d0d0d':'#ffffff',
    },
  };
});
</script>

<template>
  <n-config-provider :theme="isDark ? darkTheme : null" :theme-overrides="themeOverrides">
  <div class="app-shell">
    <aside class="side" :class="{ rail: panelDisplay.rail }">
      <div class="side-brand">
        <span class="hdr-mark brand-mark"><img src="/raven.svg" alt=""><n-tooltip trigger="hover" placement="right"><template #trigger><span :class="['brand-service-status',wsCls]" role="status" tabindex="0" :aria-label="wsText"></span></template>{{ wsText }}</n-tooltip></span>
        <span class="side-title">ADH</span>
      </div>
      <nav class="side-nav ui-nav" aria-label="主导航">
        <n-button v-for="item in NAV" :key="item.key" quaternary block class="rail-action ui-nav-item"
          :class="{ selected: store.view === item.key }" :title="item.label" :aria-label="item.label"
          :aria-current="store.view === item.key ? 'page' : undefined" @click="store.view = item.key">
          <span class="rail-line"><n-icon size="17" :component="ICONS[item.key]" />
            <span class="rail-caption">{{ item.label }}</span><span v-if="countKey(item.key)" class="nav-event-count" :aria-label="item.label+'事件数量'">{{ store.capTotal[countKey(item.key)!].toLocaleString('zh-CN') }}</span>
          </span>
        </n-button>
      </nav>
      <div class="side-foot">
        <n-button quaternary block class="rail-action" :class="{ selected: store.settingsOpen }"
          title="设置" aria-label="设置" :aria-expanded="store.settingsOpen" @click="store.settingsOpen = true">
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
        <DeviceDialog :devices="store.devices" :failed="store.devicesFailed" :selected="store.selectedDeviceKey"
          @select="selectDevice" @visibility="store.deviceDialogOpen=$event" />
        <div class="header-actions">
          <section class="app-context">
            <button type="button" class="process-trigger" title="选择应用" aria-label="选择应用" @click="store.appDialogOpen = true">
              <span class="proc-primary">
                <span class="app-face proc-face">
                  <span class="app-dialog-letter">{{ appInitial }}</span>
                  <img v-if="store.chosenPkg && chosenApp && chosenApp.hasIcon !== false" :src="appIconUrl(store.chosenPkg, iconSerial, chosenApp.iconVersion)"
                    alt="" @error="($event.target as HTMLElement).style.display = 'none'" />
                </span>
                <span class="proc-text">
                  <span id="procLabel">{{ appLabel }}</span>
                  <span v-if="store.chosenPkg && appLabel !== store.chosenPkg" class="proc-pkg">{{ store.chosenPkg }}</span>
                </span>
              </span>
              <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
            </button>
            <AppLifecycleControl :serial="iconSerial" :package="store.chosenPkg" :app="chosenApp" />
          </section>
        </div>
        <div class="topbar-tools"><BoardCaptureControl v-if="captureKind" :kind="captureKind" /><HelpDialog /></div>
      </header>

      <n-alert v-if="store.backendStatus==='incompatible'" type="warning" class="backend-version-warning">页面与电脑服务版本不一致；请更新并重启电脑服务后再采集，旧记录不会被补写为当前设备。</n-alert>
      <main class="panel-body">
        <KeepAlive include="CapturePanel" :max="3">
          <component :is="activePanel" :key="store.view" v-bind="captureKind ? {kind:captureKind} : {}" />
        </KeepAlive>
      </main>
    </div>

    <n-modal v-model:show="store.settingsOpen" preset="card" aria-label="设置" class="settings-modal ui-window" :style="{width:'min(1040px, calc(100vw - 24px))',height:'min(740px, calc(100dvh - 48px))'}" :content-style="{padding:'0',overflow:'hidden',display:'flex',minHeight:'0'}"><template #header><div class="settings-dialog-title"><span>设置</span><span v-if="store.chosenPkg" class="settings-dialog-target" :title="store.chosenPkg+' · '+iconSerial" :aria-label="'当前应用 '+appLabel+'，设备 '+iconSerial">{{ appLabel }}<small v-if="iconSerial"> · {{ iconSerial.slice(-4) }}</small></span></div></template><SettingsPanel /></n-modal>
    <AppDialog :show="store.appDialogOpen" @close="store.appDialogOpen = false" />
    <div class="panel-messages" role="status" aria-live="polite">
      <TransitionGroup name="notice">
        <n-alert v-for="t in toasts" :key="t.id" :show-icon="false">{{ t.text }}</n-alert>
      </TransitionGroup>
    </div>
  </div>
  </n-config-provider>
</template>

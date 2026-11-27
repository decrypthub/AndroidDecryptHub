<script setup lang="ts">
import HookManager from './HookManager.vue';
import AdvancedHostSettings from './AdvancedHostSettings.vue';
import { appearance, setAppearance } from '../appearance';
import { ref, computed, watch, onMounted } from 'vue';
import {
  store, liveSession, appSessions, hiddenHooks, setHidden, resetHidden,
  panelDisplay, savePanelDisplay, DISPLAY_CAPS, hostDisplayCap, belongsToApp, toast,
} from '../store';
import { getHealth, getConfig, type Cap } from '../api';
import {
  FAMILIES as ALGO_FAMILIES, HOOK_GROUPS, categoryKey, summarize, summarizeHooks,
  sessionHookEvidence, type AlgoEntry, type HookEntry,
} from '../observations';

import type { Component } from 'vue';
import {
  SunnyOutline, MoonOutline, DesktopOutline, SearchOutline, LockClosedOutline, EyeOutline, LocateOutline, ScanOutline, OptionsOutline, ServerOutline,
} from '@vicons/ionicons5';

// ---- 页内子导航 ----
type PageKey = 'capture' | 'system' | 'network' | 'records' | 'display' | 'conn';
const PAGE_ICONS:Partial<Record<PageKey,Component>>={capture:LockClosedOutline,records:EyeOutline,display:OptionsOutline,conn:ServerOutline};
const PAGES:Array<{key:PageKey;label:string}>=[{key:'capture',label:'加解密'},{key:'system',label:'系统'},{key:'network',label:'网络'}];
const EXTRA_PAGES:Array<{key:PageKey;label:string}>=[{key:'records',label:'显示过滤'},{key:'display',label:'界面偏好'},{key:'conn',label:'高级'}];
const captureGroup=computed(()=>page.value==='system'?'system':page.value==='network'?'network':'crypto');
const functionalPage=computed(()=>['capture','system','network'].includes(page.value));
const page=ref<PageKey>('capture');
watch(()=>store.hookSource?.feature,feature=>{if(feature)page.value=feature==='tls'?'network':['system','file'].includes(feature)?'system':'capture';},{immediate:true});

// ---- 记录显示 ----
// 设置页用快照：进入页面、切换应用、手动刷新时取一次，此后列表稳定不动。
// 实时记录只属于捕获主面板；设置里行和计数都不随采集跳动，否则开关点不中。
const recordsSnap = ref<Cap[]>([]);
function takeSnap() { recordsSnap.value = store.capItems.filter(belongsToApp); }
const obsView = ref<'algo' | 'hook'>('algo');
const obsQuery = ref('');
const obsFamily = ref('');
const hookQuery = ref('');
const hookCategory = ref('');

const algoList = computed<AlgoEntry[]>(() => {
  const q = obsQuery.value.trim().toLowerCase();
  return summarize(recordsSnap.value, hiddenHooks).filter(e =>
    (!obsFamily.value || e.family === obsFamily.value) &&
    (!q || e.name.toLowerCase().includes(q) ||
      e.methods.some(m => `${m.className}.${m.member} ${m.label}`.toLowerCase().includes(q))));
});
const hookList = computed<HookEntry[]>(() => {
  const q = hookQuery.value.trim().toLowerCase();
  return summarizeHooks(recordsSnap.value).filter(h =>
    (!hookCategory.value || h.category === hookCategory.value) &&
    (!q || h.name.toLowerCase().includes(q)));
});
// Display-only preferences: never change capture configuration.
const grouping = computed(() => obsView.value === 'algo');
const search = computed({
  get: () => grouping.value ? obsQuery.value : hookQuery.value,
  set: (v: string) => { if (grouping.value) obsQuery.value = v; else hookQuery.value = v; },
});
const family = computed({
  get: () => grouping.value ? obsFamily.value : hookCategory.value,
  set: (v: string) => { if (grouping.value) obsFamily.value = v; else hookCategory.value = v; },
});
const familyOptions = computed(() => [
  { label: '全部类别', value: '' },
  ...Object.entries(grouping.value ? ALGO_FAMILIES : HOOK_GROUPS).map(([value, label]) => ({ value, label })),
]);
const shownRows = computed(() => grouping.value
  ? algoList.value.map(e => ({key:e.key, name:e.name, note:ALGO_FAMILIES[e.family as keyof typeof ALGO_FAMILIES] ?? e.family, count:e.count}))
  : hookList.value.map(h => ({key:h.key, name:h.name, note:[HOOK_GROUPS[h.category as keyof typeof HOOK_GROUPS] ?? h.category,h.source].filter(Boolean).join(' · '), count:h.count})));
const catKey = (cat: string) => categoryKey(cat) ?? '';
const catShown = (cat: string) => !hiddenHooks.has(catKey(cat));
function toggleCategory(cat: string, show: boolean) { setHidden(catKey(cat), show); }
function resetAll() {
  resetHidden();
  toast('已恢复此应用的全部显示');
}

// ---- 显示偏好 ----
const appearances = [
  { value: 'system', label: '跟随系统', icon: DesktopOutline },
  { value: 'light', label: '浅色', icon: SunnyOutline },
  { value: 'dark', label: '深色', icon: MoonOutline },
] as const;
const limits = computed(() => [{ value: 0, label: `服务默认（${hostDisplayCap.value} 条）` },
  ...DISPLAY_CAPS.map(value => ({ value, label: `${value} 条` }))]);
const displaySaved = ref('');
function saveDisplay(v?: Partial<typeof panelDisplay>) {
  displaySaved.value = savePanelDisplay(v) ? '已保存到当前浏览器。' : '浏览器无法保存偏好，当前页面已应用。';
}
const displayAtDefault = computed(() =>
  appearance.value === 'system' && panelDisplay.limit === null && panelDisplay.time === 'time' && panelDisplay.density === 'standard');

// ---- 连接与数据 ----
const status = ref<Record<string, string>>({});
const statusMsg = ref('');
const statusBusy = ref(false);
async function refreshStatus() {
  if (statusBusy.value) return;
  statusBusy.value = true;
  statusMsg.value = '正在读取连接和保留规则…';
  const [health, config] = await Promise.allSettled([getHealth(), getConfig()]);
  const service = health.status === 'fulfilled' && health.value?.ok ? health.value : null;
  const data = config.status === 'fulfilled' ? config.value : null;
  const cap = data?.settings?.capture;
  const dev = store.devices.find(d => d.key === store.selectedDeviceKey);
  const sess = liveSession.value;
  if (data?.settings?.ui?.displayCap) hostDisplayCap.value = data.settings.ui.displayCap;
  status.value = {
    dev: dev ? `${dev.model || dev.serial} · ${dev.state || dev.link || '—'}` : '未连接',
    app: store.chosenPkg || '未选择',
    session: sess ? `在线 · pid ${sess.pid}` : (appSessions.value.length ? '有会话记录，当前离线' : '未连接'),
    host: service ? '已响应健康检查' : '健康检查未通过',
    panel: location.origin,
    version: typeof service?.version === 'string' ? service.version : '未读取',
    retention: Number.isSafeInteger(cap?.retain) && Number.isSafeInteger(cap?.maxAgeDays)
      ? `每个 APP 最多 ${cap!.retain!.toLocaleString('zh-CN')} 条 · ${cap!.maxAgeDays ? '保留 ' + cap!.maxAgeDays + ' 天' : '不限天数'}`
      : '未读取',
  };
  statusMsg.value = (service && data) ? '' : '部分信息读取失败，可点「刷新」重试。';
  statusBusy.value = false;
}
onMounted(() => { void refreshStatus(); takeSnap(); });
watch(() => store.selectedDeviceKey+'\n'+store.chosenPkg, () => { takeSnap(); if(page.value==='conn')void refreshStatus(); });
watch(page,p=>{if(p==='records')takeSnap();if(p==='conn')void refreshStatus();});
</script>

<template>
  <div class="set-page-shell">
    <nav class="settings-side-tabs" aria-label="设置分类">
      <n-button v-for="p in [...PAGES,...EXTRA_PAGES]" :key="p.key" quaternary :aria-pressed="page===p.key" :class="{active:page===p.key,secondary:p.key==='records'}" @click="page=p.key">{{ p.label }}</n-button>
    </nav>
    <div class="set-content">
      <div class="set-main">
        <h1 class="sr-only">设置</h1>

        <HookManager v-if="functionalPage" :group="captureGroup" />

        <section v-else-if="page === 'records'" class="record-prefs" aria-label="记录显示偏好">
          <div class="rec-categories" role="group" aria-labelledby="categories-label">
            <h4 id="categories-label">记录类别</h4>
            <div class="rec-checks">
              <n-checkbox v-for="(label, cat) in HOOK_GROUPS" :key="cat" :checked="catShown(cat)"
                @update:checked="toggleCategory(cat, $event)">{{ label }}</n-checkbox>
            </div>
          </div>
          <div class="rec-heading">
            <h4>显示规则</h4>
            <span class="rec-heading-actions">
              <n-button text size="small" @click="takeSnap">刷新</n-button>
              <n-button v-if="hiddenHooks.size" text size="small" @click="resetAll">恢复全部显示</n-button>
            </span>
          </div>
          <div class="rec-tools">
            <n-radio-group v-model:value="obsView" name="record-group" size="small" aria-label="显示规则分组">
              <n-radio-button value="algo">按算法</n-radio-button><n-radio-button value="hook">按 Hook</n-radio-button>
            </n-radio-group>
            <n-input v-model:value="search" size="small" clearable class="rec-search"
              :input-props="{ 'aria-label': '搜索显示规则' }" :placeholder="grouping ? '搜索算法或方法' : '搜索 Hook'">
              <template #prefix><n-icon :component="SearchOutline" /></template>
            </n-input>
            <n-select v-model:value="family" size="small" aria-label="筛选类别" class="rec-select" :options="familyOptions" />
          </div>
          <div class="rec-table">
            <div class="rec-columns" aria-hidden="true"><span>{{ grouping ? '算法' : 'Hook' }}</span><span>显示</span></div>
            <div v-for="row in shownRows" :key="row.key" class="rec-line">
              <div class="rec-identity"><strong>{{ row.name }}</strong><small>{{ row.note }}</small></div>
              <n-switch size="small" :value="!hiddenHooks.has(row.key)"
                :aria-label="'显示 ' + row.name" @update:value="setHidden(row.key, $event)" />
            </div>
            <div v-if="!shownRows.length" class="rec-empty" role="status">
              <span>{{ search || family ? '没有匹配的记录' : '暂无已观察到的' + (grouping ? '算法' : 'Hook') }}</span>
              <n-button v-if="search || family" text size="small" @click="search = ''; family = ''">清除筛选</n-button>
            </div>
          </div>
        </section>

        <section v-else-if="page === 'display'" class="display-preferences" aria-label="显示偏好">
          <div class="pref-block">
            <h4>界面外观</h4>
            <div class="pref-line">
              <span id="theme-label">主题</span>
              <n-radio-group :value="appearance" name="appearance" aria-labelledby="theme-label" @update:value="setAppearance">
                <n-radio-button v-for="a in appearances" :key="a.value" :value="a.value">
                  <span class="appearance-choice"><n-icon :component="a.icon" />{{ a.label }}</span>
                </n-radio-button>
              </n-radio-group>
            </div>
          </div>
          <div class="pref-block">
            <h4>记录列表</h4>
            <div class="pref-line"><span id="limit-label">显示条数</span>
              <n-select aria-labelledby="limit-label" class="pref-limit" :value="panelDisplay.limit ?? 0" :options="limits"
                @update:value="saveDisplay({ ...panelDisplay, limit: $event || null })" />
            </div>
            <div class="pref-line"><span id="time-label">时间格式</span>
              <n-radio-group name="time" aria-labelledby="time-label" :value="panelDisplay.time" @update:value="saveDisplay({ ...panelDisplay, time: $event })">
                <n-radio-button value="time">仅时间</n-radio-button><n-radio-button value="date">日期和时间</n-radio-button>
              </n-radio-group>
            </div>
            <div class="pref-line"><span id="density-label">行间距</span>
              <n-radio-group name="density" aria-labelledby="density-label" :value="panelDisplay.density" @update:value="saveDisplay({ ...panelDisplay, density: $event })">
                <n-radio-button value="standard">标准</n-radio-button><n-radio-button value="compact">紧凑</n-radio-button>
              </n-radio-group>
            </div>
          </div>
          <footer class="pref-footer"><span role="status">{{ displaySaved }}</span>
            <n-button v-if="!displayAtDefault" size="small" secondary @click="setAppearance('system'); saveDisplay({ rail: panelDisplay.rail })">恢复默认</n-button>
          </footer>
        </section>

        <section v-else class="set-page">
          <div class="set-page-head">
            <span class="set-status">{{ statusMsg }}</span>
            <n-button size="small" secondary :loading="statusBusy" @click="refreshStatus">刷新</n-button>
          </div>
          <dl class="set-meta">
            <div><dt>当前设备</dt><dd>{{ status.dev || '读取中…' }}</dd></div>
            <div><dt>APP 采集会话</dt><dd>{{ status.session || '未读取' }}</dd></div>
            <div><dt>电脑服务</dt><dd>{{ status.host || '未读取' }}</dd></div>
            <div><dt>面板地址</dt><dd>{{ status.panel || '—' }}</dd></div>
            <div><dt>电脑服务版本</dt><dd>{{ status.version || '—' }}</dd></div>
            <div><dt>记录保留规则</dt><dd>{{ status.retention || '—' }}</dd></div>
          </dl>
          <details class="settings-advanced-scope"><summary>分析范围与注入设置</summary>          <dl class="set-meta">
            <div><dt>当前设备</dt><dd>{{ status.dev || '未连接' }}</dd></div>
            <div><dt>当前 APP</dt><dd>{{ store.chosenPkg || '未选择' }}</dd></div>
            <div><dt>允许注入</dt><dd>{{ store.chosenPkg ? (store.scope.has(store.chosenPkg) ? '已勾选' : '未勾选') : '未选择 APP'
                }}</dd></div>
            <div><dt>观测会话</dt><dd>{{ status.session || '未连接' }}</dd></div>
          </dl>
          <div v-if="appSessions.length" class="set-choice-group" style="margin-top:14px">
            <div class="set-group-head">
              <h4>会话明细</h4><span class="set-group-count">{{ appSessions.length }} 个</span>
            </div>
            <div class="set-group-items">
              <div v-for="s in appSessions" :key="s.sessionId" class="set-toggle-row" style="cursor:default">
                <span class="lab"><b class="mono">pid {{ s.pid }}</b><span class="mono">{{ [s.process, s.mapsCount ?
                  `${s.mapsCount} maps` : '', s.sessionId].filter(Boolean).join(' · ') }}</span></span>
                <span class="pill" :class="s.online ? 'on' : 'no'">{{ s.online ? '在线' : '离线' }}</span>
              </div>
            </div>
          </div></details>
          <AdvancedHostSettings />
        </section>

      </div>
    </div>
  </div>
</template>

<style scoped>
.set-page-shell{display:flex;flex-direction:row;min-width:0}.set-content{min-width:0;flex:1;width:auto}.set-main{padding:22px 26px}.settings-advanced-scope{margin-top:26px;border-top:1px solid var(--line-soft);padding-top:12px}.settings-advanced-scope summary{cursor:pointer;font-size:13px;margin-bottom:16px}@media(max-width:700px){.set-main{padding:16px}}
@media (min-width:701px) {
  .settings-mobile-only { display:none; }
}
.set-header{flex:none;padding:12px 24px;border-bottom:1px solid var(--line-soft)}
.set-context{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0;min-height:24px}
@media(max-width:700px){.set-header{padding:10px 16px}}
.set-context .rec-scope,.set-context .set-app{margin:0}
.set-group-head .set-group-count{margin-left:auto}
.rec-scope{margin:4px 0 0;color:var(--muted);font-size:12px;line-height:1.6}
.record-prefs{width:100%;max-width:740px;container-type:inline-size;color:var(--ink);font-size:14px}
.record-prefs h4{margin:0;font-size:14px;font-weight:620;line-height:1.5;color:var(--ink);letter-spacing:0}
.rec-categories,.rec-heading,.rec-tools,.rec-checks{display:flex;align-items:center}
.rec-categories{gap:24px;flex-wrap:wrap;padding:3px 0 22px;border-bottom:1px solid var(--line-soft)}
.rec-checks{gap:8px 18px;flex-wrap:wrap}.rec-categories h4{white-space:nowrap}
.rec-heading{min-height:36px;margin:14px 0 7px;justify-content:space-between}
.rec-heading-actions{display:flex;align-items:center;gap:14px}
.rec-tools{gap:8px;margin-bottom:18px;flex-wrap:wrap}
.rec-tools .n-radio-group{flex:none}.rec-search{margin-left:auto;max-width:245px;min-width:0;flex:1 1 120px}
.rec-select{flex:0 0 124px;min-width:0}
.rec-columns,.rec-line{display:grid;grid-template-columns:minmax(0,1fr) 48px;gap:20px;align-items:center}
.rec-columns{font-size:12px;color:var(--muted);padding:7px 4px 8px;border-bottom:1px solid var(--line)}
.rec-line{padding:12px 4px;border-bottom:1px solid var(--line-soft)}
.rec-columns>:not(:first-child),.rec-count,.rec-line>.n-switch{justify-self:end}
.rec-identity{min-width:0;display:grid;gap:3px}.rec-identity strong{font-size:14px;font-weight:600;overflow-wrap:anywhere;line-height:1.5}
.rec-identity small,.rec-count{color:var(--muted);font-size:12px}.rec-count{font-variant-numeric:tabular-nums}
.rec-empty{display:flex;justify-content:center;align-items:center;gap:12px;padding:26px 0;color:var(--muted)}
@container(max-width:510px){
 .rec-categories{align-items:flex-start;flex-direction:column;gap:9px;padding-bottom:14px}
 .rec-tools{display:grid;grid-template-columns:minmax(0,1fr) minmax(106px,38%);gap:8px}
 .rec-tools .n-radio-group{grid-column:1/-1}.rec-search,.rec-select{width:100%;max-width:none}
 .rec-checks{gap:8px 12px}.rec-columns,.rec-line{grid-template-columns:minmax(0,1fr) 40px;gap:9px}
}
</style>

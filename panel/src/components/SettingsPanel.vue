<script setup lang="ts">
import { appearance, setAppearance } from '../appearance';
import { ref, computed, watch, onMounted } from 'vue';
import {
  store, liveSession, appSessions, hiddenHooks, setHidden, resetHidden,
  panelDisplay, savePanelDisplay, DISPLAY_CAPS, hostDisplayCap, belongsToApp, toast,
} from '../store';
import { getFamilies, setFamily, getDetectSummary, getHealth, getConfig } from '../api';
import {
  FAMILIES as ALGO_FAMILIES, HOOK_GROUPS, categoryKey, summarize, summarizeHooks,
  sessionHookEvidence, type AlgoEntry, type HookEntry,
} from '../observations';

import type { Component } from 'vue';
import {
  SunnyOutline, MoonOutline, DesktopOutline, SearchOutline, LockClosedOutline, EyeOutline, LocateOutline, ScanOutline, OptionsOutline, ServerOutline,
} from '@vicons/ionicons5';

// ---- 页内子导航 ----
type PageKey = 'capture' | 'records' | 'hooks' | 'scope' | 'display' | 'conn';
const PAGE_ICONS: Record<PageKey, Component> = {
  capture: LockClosedOutline, records: EyeOutline, hooks: LocateOutline,
  scope: ScanOutline, display: OptionsOutline, conn: ServerOutline,
};
const PAGES: Array<{ key: PageKey; label: string }> = [
  { key: 'capture', label: '捕获' },
  { key: 'records', label: '记录显示' },
  { key: 'hooks', label: 'Hook 状态' },
  { key: 'scope', label: '分析范围' },
  { key: 'display', label: '显示' },
  { key: 'conn', label: '连接与数据' },
];
const page = ref<PageKey>('capture');
const pageTitle = computed(() => PAGES.find(p => p.key === page.value)?.label ?? '');

// ---- 捕获家族（键序对齐 daemon CRYPTO_FAMILY_KEYS）----
const FAMILIES = [
  ['digest', '摘要', 'MessageDigest.digest · EVP_DigestUpdate'],
  ['hmac', 'HMAC', 'Mac.doFinal · HMAC_Update'],
  ['symmetric', '对称', 'Cipher.doFinal · EVP_CipherUpdate'],
  ['asymmetric', '非对称', 'Signature.sign · EVP_DigestSign'],
  ['tls', 'TLS', 'SSL_read · SSL_write'],
  ['aead', 'AEAD', 'AES-GCM · EVP_AEAD'],
] as const;

const famState = ref<Record<string, boolean>>({});
const famEnabled = ref(false);
const famError = ref('');
const saving = ref('');
const radar = ref('');
const radarTitle = ref('');

async function loadFamilies() {
  if (!store.chosenPkg) return;
  try {
    const r = await getFamilies(store.chosenPkg);
    if (!r.ok || !r.capture) { famError.value = '读取配置失败'; return; }
    famEnabled.value = r.capture.enabled !== false;
    famState.value = { ...(r.capture.families ?? {}) };
    famError.value = '';
  } catch { famError.value = '读取配置失败'; }
}
async function toggle(fam: string) {
  if (!store.chosenPkg || saving.value) return;
  const next = !famState.value[fam];
  saving.value = fam;
  try {
    const r = await setFamily(store.chosenPkg, fam, next) as { ok?: boolean; error?: string };
    if (r?.ok === false) { famError.value = r.error ?? '保存失败'; return; }
    famState.value[fam] = next;
  } catch { famError.value = '保存失败'; }
  saving.value = '';
}
async function loadRadar() {
  if (!store.chosenPkg) { radar.value = '先选择应用'; return; }
  try {
    const r = await getDetectSummary(store.chosenPkg) as {
      armed?: boolean; kinds?: Array<{ label: string; count: number }>;
      caveat?: string; unchecked?: string[];
    };
    if (r.armed === false) { radar.value = '系统检测：未开'; radarTitle.value = '在 Manager → 应用 → Hook 配置 → 系统检测 里打开'; return; }
    if (r.armed == null) { radar.value = '系统检测：摘要未上报'; return; }
    const hit = (r.kinds ?? []).filter(k => (k.count ?? 0) > 0).map(k => `${k.label} ${k.count}`);
    radar.value = '系统检测：' + (hit.length ? `已开 · ${hit.join(' · ')}` : '已开 · 暂无');
    const parts: string[] = [];
    if (r.caveat) parts.push(r.caveat);
    if (r.unchecked?.length) parts.push('未覆盖：' + r.unchecked.join('、'));
    radarTitle.value = parts.join('\n');
  } catch { radar.value = '系统检测：摘要读取失败'; radarTitle.value = '不代表功能已开启或关闭'; }
}

// ---- 记录显示 ----
const appRecords = computed(() => store.capItems.filter(belongsToApp));
const obsView = ref<'algo' | 'hook'>('algo');
const obsQuery = ref('');
const obsFamily = ref('');
const hookQuery = ref('');
const hookCategory = ref('');

const algoList = computed<AlgoEntry[]>(() => {
  const q = obsQuery.value.trim().toLowerCase();
  return summarize(appRecords.value, hiddenHooks).filter(e =>
    (!obsFamily.value || e.family === obsFamily.value) &&
    (!q || e.name.toLowerCase().includes(q) ||
      e.methods.some(m => `${m.className}.${m.member} ${m.label}`.toLowerCase().includes(q))));
});
const hookList = computed<HookEntry[]>(() => {
  const q = hookQuery.value.trim().toLowerCase();
  return summarizeHooks(appRecords.value).filter(h =>
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

// ---- 功能与 Hook 状态 ----
const evidence = computed(() => {
  const s = liveSession.value;
  if (!s) return null;
  return sessionHookEvidence(appRecords.value, store.chosenPkg, s.sessionId);
});
const EVIDENCE_LABELS: Record<string, string> = { crypto: '加解密', system: '系统调用', file: '文件读写', net: '网络' };

// ---- 显示偏好 ----
const appearances = [
  { value: 'system', label: '跟随系统', icon: DesktopOutline },
  { value: 'light', label: '浅色', icon: SunnyOutline },
  { value: 'dark', label: '深色', icon: MoonOutline },
] as const;
const pageOptions = PAGES.map(({ key: value, label }) => ({ value, label }));
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
onMounted(() => { void loadFamilies(); void loadRadar(); void refreshStatus(); });
watch(() => store.chosenPkg, () => { void loadFamilies(); void loadRadar(); });
</script>

<template>
  <div class="set-page-shell">
    <aside class="set-sidebar">
      <h2>设置</h2>
      <nav class="settings-links" aria-label="设置分类">
        <n-button v-for="p in PAGES" :key="p.key" quaternary block :aria-label="p.label" :title="p.label" :aria-pressed="page === p.key" @click="page = p.key">
          <span class="settings-link"><n-icon class="set-nav-icon" size="16" :component="PAGE_ICONS[p.key]" />
          <span>{{ p.label }}</span></span>
        </n-button>
      </nav>
    </aside>
    <div class="set-content">
      <div class="set-header">
        <div>
          <h3 class="settings-title">{{ pageTitle }}</h3>
          <div class="settings-picker"><n-select size="small" v-model:value="page" aria-label="设置分类" :options="pageOptions" /></div>
          <p v-if="page === 'records'" class="rec-scope">仅调整当前应用在此浏览器中的显示，不影响采集。</p>
          <p v-else-if="page === 'display'" class="rec-scope">外观与列表偏好仅保存在当前浏览器。</p>
          <p v-else class="set-app"><span>APP <strong>{{ store.chosenPkg || '未选择应用' }}</strong></span></p>
        </div>
      </div>
      <div class="set-main">

        <section v-if="page === 'capture'" class="set-page">
          <div class="set-choice-group">
            <div class="set-group-head">
              <h4>捕获家族</h4>
              <span class="set-group-count">{{ famEnabled ? '已启用' : '已停用' }}</span>
            </div>
            <div class="set-group-items">
              <div v-for="[key, label, members] in FAMILIES" :key="key" class="set-toggle-row">
                <span class="lab"><b>{{ label }}</b><span>{{ members }}</span></span>
                <n-switch size="small" :aria-label="label" :value="famState[key] !== false"
                  :disabled="!!saving || !store.chosenPkg" @update:value="toggle(key)" />
              </div>
            </div>
          </div>
          <p v-if="famError" class="set-status" data-error="true">{{ famError }}</p>
          <p v-else-if="!store.chosenPkg" class="set-status">先选择应用。</p>
          <div class="set-choice-group">
            <div class="set-group-head">
              <h4>检测状态</h4>
              <n-button size="small" secondary @click="loadRadar">刷新</n-button>
            </div>
            <p class="detect-radar" style="padding:10px 13px" :title="radarTitle">{{ radar || '未读取' }}</p>
          </div>
        </section>

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
            <n-button v-if="hiddenHooks.size" text size="small" @click="resetAll">恢复全部显示</n-button>
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
            <div class="rec-columns" aria-hidden="true"><span>{{ grouping ? '算法' : 'Hook' }}</span><span>记录数</span><span>显示</span></div>
            <div v-for="row in shownRows" :key="row.key" class="rec-line">
              <div class="rec-identity"><strong>{{ row.name }}</strong><small>{{ row.note }}</small></div>
              <span class="rec-count" :aria-label="row.count + ' 条记录'">{{ row.count }}</span>
              <n-switch size="small" :value="!hiddenHooks.has(row.key)"
                :aria-label="'显示 ' + row.name" @update:value="setHidden(row.key, $event)" />
            </div>
            <div v-if="!shownRows.length" class="rec-empty" role="status">
              <span>{{ search || family ? '没有匹配的记录' : '暂无已观察到的' + (grouping ? '算法' : 'Hook') }}</span>
              <n-button v-if="search || family" text size="small" @click="search = ''; family = ''">清除筛选</n-button>
            </div>
          </div>
        </section>

        <section v-else-if="page === 'hooks'" class="set-page">
          <div v-if="!evidence" class="set-observation-empty">没有在线会话。Hook 状态按当前进程会话统计。</div>
          <template v-else>
            <div v-for="(label, key) in EVIDENCE_LABELS" :key="key" class="set-algorithm-entry">
              <details>
                <summary>
                  <span>
                    <strong>{{ label }}</strong>
                    <span class="set-algorithm-meta">{{ evidence[key].records }} 条 · {{ evidence[key].uniqueEntries }}
                      个入口</span>
                  </span>
                </summary>
                <ul v-if="evidence[key].methods.length" class="set-algorithm-methods">
                  <li v-for="(m, i) in evidence[key].methods" :key="i">
                    <dl>
                      <dt>×{{ m.count }}</dt>
                      <dd>{{ m.className ? m.className + '.' + m.member : (m.member || m.label) }}</dd>
                    </dl>
                  </li>
                </ul>
                <p v-else class="set-lead" style="margin:0 0 10px 15px">本会话暂无此类记录。</p>
              </details>
            </div>
            <p class="set-status">上报入口详情只读；会话识别到的入口不代表完整安装清单。</p>
          </template>
        </section>

        <section v-else-if="page === 'scope'" class="set-page">
          <dl class="set-meta">
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
        </section>

      </div>
    </div>
  </div>
</template>

<style scoped>
.rec-scope{margin:4px 0 0;color:var(--muted);font-size:12px;line-height:1.6}
.record-prefs{width:100%;max-width:740px;container-type:inline-size;color:var(--ink);font-size:14px}
.record-prefs h4{margin:0;font-size:14px;font-weight:620;line-height:1.5;color:var(--ink);letter-spacing:0}
.rec-categories,.rec-heading,.rec-tools,.rec-checks{display:flex;align-items:center}
.rec-categories{gap:24px;flex-wrap:wrap;padding:3px 0 22px;border-bottom:1px solid var(--line-soft)}
.rec-checks{gap:8px 18px;flex-wrap:wrap}.rec-categories h4{white-space:nowrap}
.rec-heading{min-height:36px;margin:14px 0 7px;justify-content:space-between}
.rec-tools{gap:8px;margin-bottom:18px;flex-wrap:wrap}
.rec-tools .n-radio-group{flex:none}.rec-search{margin-left:auto;max-width:245px;min-width:0;flex:1 1 120px}
.rec-select{flex:0 0 124px;min-width:0}
.rec-columns,.rec-line{display:grid;grid-template-columns:minmax(0,1fr) 60px 48px;gap:20px;align-items:center}
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
 .rec-checks{gap:8px 12px}.rec-columns,.rec-line{grid-template-columns:minmax(0,1fr) 42px 40px;gap:9px}
}
</style>

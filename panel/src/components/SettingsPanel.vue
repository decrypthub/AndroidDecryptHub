<script setup lang="ts">
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

// ---- 页内子导航 ----
type PageKey = 'capture' | 'records' | 'hooks' | 'scope' | 'display' | 'conn';
const PAGE_ICONS: Record<PageKey, string> = {
  capture: '<rect x="4" y="8" width="12" height="9" rx="2"/><path d="M7 8V6a3 3 0 0 1 6 0v2m-3 4v2"/>',
  records: '<path d="M2 10s3-5 8-5 8 5 8 5-3 5-8 5-8-5-8-5z"/><circle cx="10" cy="10" r="2.4"/>',
  hooks: '<circle cx="10" cy="10" r="6.5"/><circle cx="10" cy="10" r="2"/><path d="M10 1.5v2M18.5 10h-2M10 18.5v-2M1.5 10h2"/>',
  scope: '<circle cx="10" cy="10" r="7"/><circle cx="10" cy="10" r="3"/>',
  display: '<path d="M4 6h5M13 6h3M4 14h3M11 14h5"/><circle cx="11" cy="6" r="1.8"/><circle cx="9" cy="14" r="1.8"/>',
  conn: '<rect x="3" y="4" width="14" height="5" rx="1.5"/><rect x="3" y="11" width="14" height="5" rx="1.5"/><path d="M6 6.5h.01M6 13.5h.01"/>',
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
const displaySaved = ref('');
function saveDisplay(v?: Partial<typeof panelDisplay>) {
  displaySaved.value = savePanelDisplay(v) ? '已保存到当前浏览器。' : '浏览器无法保存偏好，当前页面已应用。';
}
const displayAtDefault = computed(() =>
  panelDisplay.limit === null && panelDisplay.time === 'time' && panelDisplay.density === 'standard');

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
      <nav class="set-nav">
        <button v-for="p in PAGES" :key="p.key" type="button" :aria-pressed="page === p.key" @click="page = p.key">
          <svg class="set-nav-icon" viewBox="0 0 20 20" v-html="PAGE_ICONS[p.key]" />
          <span class="set-nav-label">{{ p.label }}</span>
        </button>
      </nav>
    </aside>
    <div class="set-content">
      <div class="set-header">
        <div>
          <h3>{{ pageTitle }}</h3>
          <p class="set-app"><span>APP <strong>{{ store.chosenPkg || '未选择应用' }}</strong></span></p>
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
              <label v-for="[key, label, members] in FAMILIES" :key="key" class="set-toggle-row">
                <span class="lab"><b>{{ label }}</b><span>{{ members }}</span></span>
                <span class="set-switch"><input type="checkbox" :checked="famState[key] !== false"
                    :disabled="!!saving || !store.chosenPkg" @change="toggle(key)" /><span class="slider"></span></span>
              </label>
            </div>
          </div>
          <p v-if="famError" class="set-status" data-error="true">{{ famError }}</p>
          <p v-else-if="!store.chosenPkg" class="set-status">先选择应用。</p>
          <div class="set-choice-group">
            <div class="set-group-head">
              <h4>检测状态</h4>
              <button type="button" class="set-small-button" @click="loadRadar">刷新</button>
            </div>
            <p class="detect-radar" style="padding:10px 13px" :title="radarTitle">{{ radar || '未读取' }}</p>
          </div>
        </section>

        <section v-else-if="page === 'records'" class="set-page">
          <fieldset class="set-record-controls">
            <legend>记录类别</legend>
            <label v-for="(label, cat) in HOOK_GROUPS" :key="cat">
              <input type="checkbox" :checked="catShown(cat)" @change="toggleCategory(cat, !catShown(cat))" />{{
                label }}</label>
          </fieldset>
          <div class="set-observation-nav">
            <button type="button" class="set-small-button" :aria-pressed="obsView === 'algo'"
              @click="obsView = 'algo'">按算法</button>
            <button type="button" class="set-small-button" :aria-pressed="obsView === 'hook'"
              @click="obsView = 'hook'">按 Hook</button>
            <span class="set-family-count">{{ obsView === 'algo' ? algoList.length : hookList.length }} 项</span>
            <button type="button" class="set-small-button" :disabled="!hiddenHooks.size"
              @click="resetAll">恢复全部显示</button>
          </div>
          <template v-if="obsView === 'algo'">
            <div class="set-observation-filters">
              <input v-model="obsQuery" placeholder="算法、类或方法" />
              <select v-model="obsFamily">
                <option value="">全部类别</option>
                <option v-for="(label, key) in ALGO_FAMILIES" :key="key" :value="key">{{ label }}</option>
              </select>
            </div>
            <div class="set-choice-group">
              <div class="set-group-head">
                <h4>已观察算法</h4><span class="set-group-count">{{ algoList.length }} 项</span>
              </div>
              <div class="set-group-items">
                <label v-for="e in algoList" :key="e.key" class="set-toggle-row">
                  <span class="lab"><b>{{ e.name }}</b><span>{{ ALGO_FAMILIES[e.family as keyof typeof ALGO_FAMILIES] ??
                    e.family }} · {{ e.count }} 条</span></span>
                  <span class="set-switch"><input type="checkbox" :checked="!hiddenHooks.has(e.key)"
                      @change="setHidden(e.key, hiddenHooks.has(e.key))" /><span class="slider"></span></span>
                </label>
                <div v-if="!algoList.length" class="set-observation-empty">{{ appRecords.length ? '没有匹配的已观察算法。' :
                  '还没有记录可归纳。' }}</div>
              </div>
            </div>
          </template>
          <template v-else>
            <div class="set-observation-filters">
              <input v-model="hookQuery" placeholder="按名称搜索 Hook" />
              <select v-model="hookCategory">
                <option value="">全部类别</option>
                <option v-for="(label, key) in HOOK_GROUPS" :key="key" :value="key">{{ label }}</option>
              </select>
            </div>
            <div class="set-choice-group">
              <div class="set-group-head">
                <h4>已观察 Hook</h4><span class="set-group-count">{{ hookList.length }} 项</span>
              </div>
              <div class="set-group-items">
                <label v-for="h in hookList" :key="h.key" class="set-toggle-row">
                  <span class="lab"><b class="mono">{{ h.name }}</b><span>{{ HOOK_GROUPS[h.category as keyof typeof
                    HOOK_GROUPS] ?? h.category }}{{ h.source ? ' · ' + h.source : '' }} · {{ h.count }} 条</span></span>
                  <span class="set-switch"><input type="checkbox" :checked="!hiddenHooks.has(h.key)"
                      @change="setHidden(h.key, hiddenHooks.has(h.key))" /><span class="slider"></span></span>
                </label>
                <div v-if="!hookList.length" class="set-observation-empty">{{ appRecords.length ? '没有匹配的 Hook。' :
                  '还没有记录可归纳。' }}</div>
              </div>
            </div>
          </template>
          <p class="set-status">勾选即时生效，按应用保存在此浏览器。</p>
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

        <section v-else-if="page === 'display'" class="set-page">
          <div class="set-preferences">
            <label class="set-row"><span class="lab"><b>列表显示条数</b><span>每个板块保留在列表里的最近记录数</span></span>
              <select :value="panelDisplay.limit ?? ''"
                @change="saveDisplay({ ...panelDisplay, limit: Number(($event.target as HTMLSelectElement).value) || null })">
                <option value="">跟随服务默认（{{ hostDisplayCap.value }}）</option>
                <option v-for="n in DISPLAY_CAPS" :key="n" :value="n">{{ n }} 条</option>
              </select>
            </label>
            <label class="set-row"><span class="lab"><b>时间格式</b><span>记录时间戳显示到日期还是只到时间</span></span>
              <select :value="panelDisplay.time"
                @change="saveDisplay({ ...panelDisplay, time: ($event.target as HTMLSelectElement).value as 'time' })">
                <option value="time">只显示时间</option>
                <option value="date">日期和时间</option>
              </select>
            </label>
            <label class="set-row"><span class="lab"><b>列表间距</b><span>紧凑模式每行更矮，一屏能看更多条</span></span>
              <select :value="panelDisplay.density"
                @change="saveDisplay({ ...panelDisplay, density: ($event.target as HTMLSelectElement).value as 'standard' })">
                <option value="standard">标准</option>
                <option value="compact">紧凑</option>
              </select>
            </label>
          </div>
          <div class="set-actions">
            <button type="button" :disabled="displayAtDefault" @click="saveDisplay()">恢复默认</button>
            <span class="set-status">{{ displaySaved }}</span>
          </div>
        </section>

        <section v-else class="set-page">
          <div class="set-page-head">
            <span class="set-status">{{ statusMsg }}</span>
            <button type="button" class="set-small-button" :disabled="statusBusy" @click="refreshStatus">刷新</button>
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

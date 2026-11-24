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

// 六个加密家族 + tls（键序对齐 daemon CRYPTO_FAMILY_KEYS）
const FAMILIES = [
  ['digest', '摘要'], ['hmac', 'HMAC'], ['symmetric', '对称'], ['asymmetric', '非对称'],
  ['tls', 'TLS'], ['aead', 'AEAD'],
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
  if (!store.chosenPkg) { radar.value = ''; return; }
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

// ---- 记录显示（只筛本浏览器列表，不改手机采集策略）----
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

// ---- 功能与 Hook 状态（会话内已观察入口，非安装清单）----
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
  <div class="settings-panel">
    <section class="set-block">
      <h3>捕获配置 <span class="mono muted">{{ store.chosenPkg }}</span></h3>
      <div v-if="famError" class="set-error">{{ famError }}</div>
      <div v-else-if="!store.chosenPkg" class="muted">先选择应用。</div>
      <div v-else class="fam-grid">
        <label v-for="[key, label] in FAMILIES" :key="key" class="fam-item" :class="{ saving: saving === key }">
          <input type="checkbox" :checked="famState[key] !== false" :disabled="!!saving"
            @change="toggle(key)" />
          <span>{{ label }}</span>
          <code class="muted">{{ key }}</code>
        </label>
        <div class="muted fam-master">总开关：{{ famEnabled ? '开' : '关' }}（全部家族关闭时自动关）</div>
      </div>
    </section>

    <section class="set-block">
      <h3>检测状态</h3>
      <div class="radar" :title="radarTitle">{{ radar || '未读取' }}</div>
      <button class="btn sm" @click="loadRadar">刷新</button>
    </section>

    <section class="set-block">
      <h3>记录显示</h3>
      <div class="cat-toggles">
        <label v-for="(label, cat) in HOOK_GROUPS" :key="cat" class="fam-item">
          <input type="checkbox" :checked="catShown(cat)" @change="toggleCategory(cat, !catShown(cat))" />
          <span>{{ label }}</span>
        </label>
      </div>
      <div class="obs-nav">
        <button class="btn sm" :class="{ on: obsView === 'algo' }" @click="obsView = 'algo'">按算法</button>
        <button class="btn sm" :class="{ on: obsView === 'hook' }" @click="obsView = 'hook'">按 Hook</button>
      </div>
      <template v-if="obsView === 'algo'">
        <div class="obs-filters">
          <input v-model="obsQuery" class="obs-search" placeholder="算法、类或方法" />
          <select v-model="obsFamily" class="cap-cat">
            <option value="">全部类别</option>
            <option v-for="(label, key) in ALGO_FAMILIES" :key="key" :value="key">{{ label }}</option>
          </select>
        </div>
        <div class="obs-list">
          <label v-for="e in algoList" :key="e.key" class="obs-item">
            <input type="checkbox" :checked="!hiddenHooks.has(e.key)" @change="setHidden(e.key, hiddenHooks.has(e.key))" />
            <span class="obs-name">{{ e.name }}</span>
            <span class="muted obs-fam">{{ ALGO_FAMILIES[e.family as keyof typeof ALGO_FAMILIES] ?? e.family }}</span>
            <span class="muted obs-count">{{ e.count }} 条</span>
          </label>
          <div v-if="!algoList.length" class="muted obs-empty">{{ appRecords.length ? '没有匹配的已观察算法。' : '还没有记录可归纳。' }}</div>
        </div>
      </template>
      <template v-else>
        <div class="obs-filters">
          <input v-model="hookQuery" class="obs-search" placeholder="按名称搜索 Hook" />
          <select v-model="hookCategory" class="cap-cat">
            <option value="">全部类别</option>
            <option v-for="(label, key) in HOOK_GROUPS" :key="key" :value="key">{{ label }}</option>
          </select>
        </div>
        <div class="obs-list">
          <label v-for="h in hookList" :key="h.key" class="obs-item">
            <input type="checkbox" :checked="!hiddenHooks.has(h.key)" @change="setHidden(h.key, hiddenHooks.has(h.key))" />
            <span class="obs-name mono">{{ h.name }}</span>
            <span class="muted obs-fam">{{ HOOK_GROUPS[h.category as keyof typeof HOOK_GROUPS] ?? h.category }}{{ h.source ? ' · ' + h.source : '' }}</span>
            <span class="muted obs-count">{{ h.count }} 条</span>
          </label>
          <div v-if="!hookList.length" class="muted obs-empty">{{ appRecords.length ? '没有匹配的 Hook。' : '还没有记录可归纳。' }}</div>
        </div>
      </template>
      <div class="obs-footer">
        <span class="muted">勾选即时生效，按应用保存</span>
        <button class="btn sm" :disabled="!hiddenHooks.size" @click="resetAll">恢复全部显示</button>
      </div>
    </section>

    <section v-if="evidence" class="set-block">
      <h3>功能与 Hook 状态</h3>
      <details v-for="(label, key) in EVIDENCE_LABELS" :key="key" class="evidence">
        <summary>
          <strong>{{ label }}</strong>
          <span class="muted">{{ evidence[key].records }} 条 · {{ evidence[key].uniqueEntries }} 个入口</span>
        </summary>
        <ul v-if="evidence[key].methods.length" class="evidence-methods">
          <li v-for="(m, i) in evidence[key].methods" :key="i" class="mono">
            {{ m.className ? m.className + '.' + m.member : (m.member || m.label) }}
            <span class="muted">×{{ m.count }}</span>
          </li>
        </ul>
        <div v-else class="muted">本会话暂无此类记录。</div>
      </details>
      <p class="muted ev-note">上报入口详情只读；会话识别到的入口不代表完整安装清单。</p>
    </section>

    <section class="set-block">
      <h3>分析范围</h3>
      <dl class="set-meta">
        <div><dt>当前设备</dt><dd>{{ status.dev || '未连接' }}</dd></div>
        <div><dt>当前 APP</dt><dd>{{ store.chosenPkg || '未选择' }}</dd></div>
        <div><dt>允许注入</dt><dd>{{ store.chosenPkg ? (store.scope.has(store.chosenPkg) ? '已勾选' : '未勾选') : '未选择 APP' }}</dd></div>
        <div><dt>观测会话</dt><dd>{{ status.session || '未连接' }}</dd></div>
      </dl>
    </section>

    <section class="set-block">
      <h3>显示</h3>
      <div class="pref-rows">
        <label class="pref-row"><span>列表显示条数</span>
          <select :value="panelDisplay.limit ?? ''" class="cap-cat"
            @change="saveDisplay({ ...panelDisplay, limit: Number(($event.target as HTMLSelectElement).value) || null })">
            <option value="">跟随服务默认（{{ hostDisplayCap.value }}）</option>
            <option v-for="n in DISPLAY_CAPS" :key="n" :value="n">{{ n }} 条</option>
          </select>
        </label>
        <label class="pref-row"><span>时间格式</span>
          <select :value="panelDisplay.time" class="cap-cat"
            @change="saveDisplay({ ...panelDisplay, time: ($event.target as HTMLSelectElement).value as 'time' })">
            <option value="time">只显示时间</option>
            <option value="date">日期和时间</option>
          </select>
        </label>
        <label class="pref-row"><span>列表间距</span>
          <select :value="panelDisplay.density" class="cap-cat"
            @change="saveDisplay({ ...panelDisplay, density: ($event.target as HTMLSelectElement).value as 'standard' })">
            <option value="standard">标准</option>
            <option value="compact">紧凑</option>
          </select>
        </label>
      </div>
      <div class="obs-footer">
        <span class="muted">{{ displaySaved }}</span>
        <button class="btn sm" :disabled="displayAtDefault" @click="saveDisplay()">恢复默认</button>
      </div>
    </section>

    <section class="set-block">
      <h3>连接与数据 <button class="btn sm" :disabled="statusBusy" @click="refreshStatus">刷新</button></h3>
      <dl class="set-meta">
        <div><dt>当前设备</dt><dd>{{ status.dev || '读取中…' }}</dd></div>
        <div><dt>APP 采集会话</dt><dd>{{ status.session || '未读取' }}</dd></div>
        <div><dt>电脑服务</dt><dd>{{ status.host || '未读取' }}</dd></div>
        <div><dt>面板地址</dt><dd>{{ status.panel || '—' }}</dd></div>
        <div><dt>电脑服务版本</dt><dd>{{ status.version || '—' }}</dd></div>
        <div><dt>记录保留规则</dt><dd>{{ status.retention || '—' }}</dd></div>
      </dl>
      <p v-if="statusMsg" class="muted">{{ statusMsg }}</p>
    </section>
  </div>
</template>

<style scoped>
.settings-panel { flex: 1; overflow: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 18px; }
.set-block { background: var(--surface); border: 1px solid var(--line-soft); border-radius: 12px; padding: 14px 16px; }
.set-block h3 { margin: 0 0 10px; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
.fam-grid { display: flex; flex-direction: column; gap: 8px; }
.fam-item { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); }
.fam-item.saving { opacity: 0.6; }
.fam-master { margin-top: 6px; font-size: 12px; }
.set-error { color: var(--danger); font-size: 13px; }
.radar { font-size: 13px; color: var(--ink-2); margin-bottom: 8px; }
.cat-toggles { display: flex; flex-wrap: wrap; gap: 10px 18px; padding: 4px 0 12px; }
.obs-nav { display: flex; gap: 8px; margin-bottom: 10px; }
.obs-filters { display: flex; gap: 8px; margin-bottom: 8px; }
.obs-search { flex: 1; }
.obs-list { max-height: 320px; overflow: auto; border: 1px solid var(--line-soft); border-radius: 8px; }
.obs-item { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-bottom: 1px solid var(--line-soft); font-size: 13px; color: var(--ink-2); cursor: pointer; }
.obs-item:last-child { border-bottom: 0; }
.obs-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.obs-fam { font-size: 11px; flex: none; }
.obs-count { font-size: 11px; flex: none; font-variant-numeric: tabular-nums; }
.obs-empty { padding: 18px; text-align: center; font-size: 12px; }
.obs-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 10px; font-size: 12px; }
.evidence { border: 1px solid var(--line-soft); border-radius: 8px; padding: 8px 12px; margin-bottom: 8px; }
.evidence summary { display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; }
.evidence-methods { margin: 8px 0 0; padding-left: 18px; font-size: 12px; color: var(--ink-2); max-height: 180px; overflow: auto; }
.ev-note { font-size: 11px; margin: 6px 0 0; }
.pref-rows { display: flex; flex-direction: column; gap: 10px; }
.pref-row { display: flex; align-items: center; gap: 12px; font-size: 13px; color: var(--ink-2); }
.pref-row > span { flex: 1; }
.set-meta { margin: 0; }
.set-meta > div { display: grid; grid-template-columns: minmax(100px, 1fr) minmax(0, 2fr); column-gap: 12px; align-items: baseline; padding: 9px 0; border-bottom: 1px solid var(--line-soft); }
.set-meta > div:last-child { border-bottom: 0; }
.set-meta dt { color: var(--muted); font-size: 12px; }
.set-meta dd { margin: 0; color: var(--ink-2); overflow-wrap: anywhere; font-variant-numeric: tabular-nums; font-size: 13px; }
</style>

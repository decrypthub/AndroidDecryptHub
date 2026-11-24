<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import { store } from '../store';
import { getFamilies, setFamily, getDetectSummary } from '../api';

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

onMounted(() => { void loadFamilies(); void loadRadar(); });
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
  </div>
</template>

<style scoped>
.settings-panel { flex: 1; overflow: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 18px; }
.set-block { background: var(--surface); border: 1px solid var(--line-soft); border-radius: 12px; padding: 14px 16px; }
.set-block h3 { margin: 0 0 10px; font-size: 14px; font-weight: 600; }
.fam-grid { display: flex; flex-direction: column; gap: 8px; }
.fam-item { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--ink-2); }
.fam-item.saving { opacity: 0.6; }
.fam-master { margin-top: 6px; font-size: 12px; }
.set-error { color: var(--danger); font-size: 13px; }
.radar { font-size: 13px; color: var(--ink-2); margin-bottom: 8px; }
</style>

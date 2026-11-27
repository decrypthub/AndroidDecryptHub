<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount, nextTick } from 'vue';
import { NModal, NButton, NInput, NIcon, NEmpty } from 'naive-ui';
import {
  ChevronDownOutline, RefreshOutline, AddOutline, PhonePortraitOutline,
  TrashOutline, CreateOutline, CheckmarkOutline,
} from '@vicons/ionicons5';
import type { DeviceView } from '../store';
import { toast, refreshDevices, deviceLabel, rememberDevice, forgetDevice, renameDevice } from '../store';
import { reconnectDevice, adbConnectDevice, getDeviceInfo, type DeviceInfo } from '../api';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string]; visibility:[open:boolean] }>();

const show = ref(false);
watch(show,value=>emit('visibility',value));
onBeforeUnmount(()=>emit('visibility',false));
const busy = ref('');

// 重命名：行内改当前设备名
const renaming = ref(false);
const renameText = ref('');
const renameInput = ref<InstanceType<typeof NInput> | null>(null);

// 底栏添加网络设备
const adding = ref(false);
const addAddress = ref('');
const addBusy = ref(false);
const addError = ref('');

// 只读当前设备的硬件信息（daemon 侧缓存 60s）
const info = ref<DeviceInfo | null>(null);
let infoToken = 0;

function isOnline(d: DeviceView) {
  return d.rpc || d.state === 'device' || d.state === 'online' || d.agent?.online === true;
}
const current = computed(() => props.devices.find(d => d.key === props.selected) ?? props.devices[0] ?? null);

// 在线排前，其他排后
const sortedDevices = computed(() => {
  const on = props.devices.filter(isOnline);
  const off = props.devices.filter(d => !isOnline(d));
  return [...on, ...off];
});

const STATE_TEXT: Record<string, string> = {
  unauthorized: '未授权', offline: '离线', disconnected: '未连接', unknown: '状态未知',
};
function dotClass(d: DeviceView | null | undefined) {
  if (!d) return '';
  if (isOnline(d)) return 'ok';
  if (d.state === 'unauthorized' || d.state === 'offline' || d.state === 'disconnected') return 'bad';
  return '';
}
function adbText(d: DeviceView) {
  if (d.state === 'device') return '已连接';
  if (d.state === 'online') return '在线';
  return STATE_TEXT[d.state] ?? d.state ?? '未知';
}
function linkText(d: DeviceView) {
  return d.net ? '局域网' : 'USB';
}
function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const date = new Date(ts);
  return `${date.getMonth() + 1}-${date.getDate()}`;
}
function rowMeta(d: DeviceView) {
  const bits = [d.serial, linkText(d)];
  if (!isOnline(d) && d.seenAt) bits.push(`${timeAgo(d.seenAt)}在线过`);
  else bits.push(adbText(d));
  if (d.agent?.online) bits.push('Agent 在线');
  else if (d.observed) bits.push(`观察 ${d.observed}`);
  return bits.join(' · ');
}

// 当前设备状态一句话
const currentStatus = computed(() => {
  const d = current.value;
  if (!d) return '';
  const bits = [linkText(d), adbText(d)];
  if (d.agent?.online) bits.push(`Agent 在线${d.agent.version ? ` v${d.agent.version}` : ''}`);
  if (d.observed) bits.push('观察中');
  return bits.join(' · ');
});

// 当前设备硬件一句话 + 两条细进度条
const specLine = computed(() => {
  const i = info.value;
  if (!i) return '';
  const bits: string[] = [];
  if (i.android) bits.push(`Android ${i.android}`);
  if (i.abi) bits.push(i.abi);
  if (i.screen) bits.push(i.screen);
  if (i.battery != null) bits.push(`电量 ${i.battery}%`);
  return bits.join(' · ');
});
function pct(used: number, total: number) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}
const ramBar = computed(() => {
  const i = info.value;
  if (!i || !i.ramBytes) return null;
  const used = i.ramBytes - (i.ramFreeBytes || 0);
  return {
    pct: pct(used, i.ramBytes),
    text: `${(used / 1073741824).toFixed(1)} / ${(i.ramBytes / 1073741824).toFixed(0)} GB`,
  };
});
const storageBar = computed(() => {
  const i = info.value;
  if (!i || !i.storageTotalBytes) return null;
  const used = i.storageTotalBytes - (i.storageFreeBytes || 0);
  return {
    pct: pct(used, i.storageTotalBytes),
    text: `${(used / 1073741824).toFixed(0)} / ${(i.storageTotalBytes / 1073741824).toFixed(0)} GB`,
  };
});

async function loadInfo(d: DeviceView | null) {
  const token = ++infoToken;
  if (!d || !isOnline(d)) { info.value = null; return; }
  try {
    const r = await getDeviceInfo(d.serial);
    if (token === infoToken) info.value = r.ok && r.info ? r.info : null;
  } catch {
    if (token === infoToken) info.value = null;
  }
}

function openDialog() {
  show.value = true;
  renaming.value = false;
  adding.value = false;
  addError.value = '';
  void refreshDevices();
  void loadInfo(current.value);
}
watch(() => current.value?.key, () => {
  if (!show.value) return;
  renaming.value = false;
  void loadInfo(current.value);
});

// 点列表行 = 切换设备
function pick(d: DeviceView) {
  if (d.key === props.selected) return;
  emit('select', d.key);
}

async function reconnect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.key;
  const label = deviceLabel(d);
  try {
    const r = await reconnectDevice(d.serial);
    if (r.ok) {
      const detailText = r.agent
        ? `agent ${r.agent.online ? '已连上' : '仍离线'} · ${r.agent.waitedMs}ms`
        : r.rpc ? '设备通道已连接' : '已连接';
      const warn = r.warnings.length ? `（注意：${r.warnings[0]}）` : '';
      toast(`${label} 重连成功：${detailText}${warn}`);
    } else {
      toast(`${label} 重连失败：${r.error ?? r.code ?? '未知原因'}`);
    }
  } catch (e) {
    toast(`重连失败：${(e as Error).message}`);
  } finally {
    busy.value = '';
    void refreshDevices();
    void loadInfo(current.value);
  }
}

function startRename() {
  if (!current.value) return;
  renaming.value = true;
  renameText.value = current.value.name ?? '';
  void nextTick(() => renameInput.value?.focus());
}
function saveRename() {
  const d = current.value;
  if (!d) { renaming.value = false; return; }
  const clean = renameText.value.trim();
  if (clean !== (d.name ?? '')) {
    renameDevice(d.key, clean);
    toast(clean ? `已命名为 ${clean}` : '已恢复默认名称');
  }
  renaming.value = false;
}

function openAdd() {
  adding.value = true;
  addAddress.value = '';
  addError.value = '';
}
const NET_ADDRESS = /^[A-Za-z0-9][A-Za-z0-9._-]*:\d{1,5}$/;
async function saveAdd() {
  addError.value = '';
  const address = addAddress.value.trim();
  if (!NET_ADDRESS.test(address)) { addError.value = '格式：IP:端口，例如 192.168.1.50:5555'; return; }
  addBusy.value = true;
  try {
    const r = await adbConnectDevice(address);
    if (!r.ok) { addError.value = r.error ?? '连不上这个地址'; return; }
    rememberDevice(address);
    toast(`已添加 ${address}`);
    adding.value = false;
    emit('select', address);
    void refreshDevices();
  } catch (e) {
    addError.value = (e as Error).message;
  } finally {
    addBusy.value = false;
  }
}

function forget(d: DeviceView) {
  forgetDevice(d.key);
  toast(`已移除 ${deviceLabel(d)}`);
}

onBeforeUnmount(() => { infoToken++; });
</script>

<template>
  <section class="device-picker">
    <button type="button" class="device-context" :aria-expanded="show" title="设备（打开设备窗口）" @click="openDialog">
      <span class="context-label">设备</span>
      <strong>{{ (current ? deviceLabel(current) : (failed ? '设备读取失败' : '选择设备')) }}</strong>
      <span class="device-link">{{ current?.serial || '' }}</span>
      <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
    </button>

    <n-modal :show="show" preset="card" class="device-modal" aria-label="设备" closable
      :style="{width:'min(680px, calc(100vw - 32px))',height:'min(560px, calc(100dvh - 48px))',maxHeight:'calc(100dvh - 48px)'}"
      :content-style="{padding:'0',display:'flex',minHeight:'0',overflow:'hidden'}"
      :segmented="{ content: true }" @update:show="!$event && (show = false)">
      <template #header>
        <span class="device-head">设备 <span v-if="devices.length" class="device-muted">{{ devices.length }}</span></span>
      </template>
      <template #header-extra>
        <n-button size="small" quaternary circle title="刷新" aria-label="刷新" class="device-refresh"
          @click="refreshDevices()">
          <template #icon><n-icon :component="RefreshOutline" /></template>
        </n-button>
      </template>

      <div class="device-dialog-layout"><aside class="device-dialog-nav">
      <!-- 下半：切换列表 -->
      <div class="dev-list">
        <div v-for="d in sortedDevices" :key="d.key" class="dev-item"
          :class="{ active: d.key === current?.key }">
          <button type="button" class="dev-pick" :aria-pressed="d.key === current?.key"
            :aria-label="'选择设备 '+deviceLabel(d)+' '+d.serial" @click="pick(d)">
          <span class="status-dot" :class="dotClass(d)"></span>
          <div class="dev-item-copy">
            <strong>{{ deviceLabel(d) }}</strong>
            <span>{{ rowMeta(d) }}</span>
          </div>
          <span v-if="d.key === current?.key" class="dev-check" aria-label="当前使用"><n-icon size="15" :component="CheckmarkOutline" /></span>
          </button>
          <n-button v-if="d.remembered && d.key !== current?.key" size="tiny" quaternary circle
            class="device-danger" title="移除" aria-label="移除" @click.stop="forget(d)">
            <template #icon><n-icon size="13" :component="TrashOutline" /></template>
          </n-button>
        </div>

        <n-empty v-if="!devices.length" :description="failed ? '设备读取失败' : '没有设备'" size="small"
          class="dev-empty" />
      </div>

      <!-- 底栏：一行添加网络设备 -->
      <footer class="dev-foot">
        <template v-if="adding">
          <div class="dev-add-row">
            <n-input v-model:value="addAddress" size="small" placeholder="IP:端口，如 192.168.1.50:5555" autofocus
              :input-props="{ 'aria-label': '设备地址' }" @keyup.enter="saveAdd" @keyup.esc="adding = false" />
            <n-button size="small" type="primary" :loading="addBusy" @click="saveAdd">连接</n-button>
            <n-button size="small" quaternary @click="adding = false">取消</n-button>
          </div>
          <p v-if="addError" class="dev-add-err">{{ addError }}</p>
        </template>
        <n-button v-else size="small" quaternary class="dev-add-trigger" @click="openAdd">
          <template #icon><n-icon :component="AddOutline" /></template>
          添加网络设备
        </n-button>
      </footer>
      </aside><div class="device-dialog-main">
      <!-- 上半：当前设备摘要（和 AppDialog 顶部卡同构） -->
      <section v-if="current" class="dev-summary">
        <div class="dev-summary-row">
          <span class="device-face" :class="dotClass(current)">
            <n-icon size="20" :component="PhonePortraitOutline" />
          </span>
          <div class="dev-summary-id">
            <n-input v-if="renaming" ref="renameInput" v-model:value="renameText" size="small"
              :placeholder="current.model || current.serial" maxlength="40"
              :input-props="{ 'aria-label': '设备名称' }"
              @keyup.enter="saveRename" @keyup.esc="renaming = false" @blur="saveRename" />
            <div v-else class="dev-summary-title">
              <strong>{{ deviceLabel(current) }}</strong>
              <span class="dev-serial">{{ current.serial }}</span>
            </div>
            <span class="dev-summary-sub">{{ currentStatus }}</span>
          </div>
          <div class="dev-summary-actions">
            <n-button size="small" :loading="busy === current.key" :disabled="!!busy"
              @click="reconnect(current)">重连</n-button>
            <n-button size="small" quaternary circle title="重命名" aria-label="重命名" @click="startRename">
              <template #icon><n-icon :component="CreateOutline" /></template>
            </n-button>
          </div>
        </div>

        <p v-if="specLine" class="dev-spec-line">{{ specLine }}</p>
        <div v-if="ramBar || storageBar" class="dev-bars">
          <div v-if="ramBar" class="dev-bar">
            <span>内存</span>
            <i class="dev-bar-track"><b :style="{ width: `${ramBar.pct}%` }" :class="{ warn: ramBar.pct >= 75, bad: ramBar.pct >= 90 }"></b></i>
            <em>{{ ramBar.text }}</em>
          </div>
          <div v-if="storageBar" class="dev-bar">
            <span>存储</span>
            <i class="dev-bar-track"><b :style="{ width: `${storageBar.pct}%` }" :class="{ warn: storageBar.pct >= 80, bad: storageBar.pct >= 92 }"></b></i>
            <em>{{ storageBar.text }}</em>
          </div>
        </div>
      </section>

      </div></div>
    </n-modal>
  </section>
</template>

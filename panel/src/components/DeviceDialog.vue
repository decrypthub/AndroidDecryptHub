<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue';
import { NModal } from 'naive-ui';
import {
  ChevronDownOutline, CloseOutline, EllipsisHorizontalOutline, RefreshOutline, AddOutline, PhonePortraitOutline,
  TrashOutline, LinkOutline,
} from '@vicons/ionicons5';
import type { DeviceView } from '../store';
import { toast, refreshDevices, deviceLabel, rememberDevice, forgetDevice } from '../store';
import { reconnectDevice, adbConnectDevice, getDeviceInfo, type DeviceInfo } from '../api';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();

const show = ref(false);
const busy = ref('');
const addOpen = ref(false);
const addKind = ref<'usb' | 'net'>('usb');
const addSerial = ref('');
const addAddress = ref('');
const addName = ref('');
const addBusy = ref(false);
const addError = ref('');

// 硬件信息：打开窗口或换设备时读一次（daemon 侧缓存 60s）
const info = ref<DeviceInfo | null>(null);
const infoLoading = ref(false);
const infoFailed = ref('');
const painted = ref(false);
let infoToken = 0;

function isOnline(d: DeviceView) {
  return d.rpc || d.state === 'device' || d.state === 'online' || d.agent?.online === true;
}
const current = computed(() => props.devices.find(d => d.key === props.selected) ?? null);
const usbOptions = computed(() => props.devices
  .filter(d => !d.remembered && !d.net)
  .map(d => ({ label: `${d.model || d.serial} · ${d.serial}`, value: d.serial })));

const STATE_TEXT: Record<string, string> = {
  unauthorized: '未授权', offline: '离线', disconnected: '未连接', unknown: '状态未知',
};
function dotClass(d: DeviceView) {
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
function pluginText(d: DeviceView) {
  const v = d.agent?.version?.trim();
  return v ? `插件 v${v}` : '';
}
function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const date = new Date(ts);
  return `${date.getMonth() + 1}-${date.getDate()}`;
}

// ---- 进度环需要的百分比 ----
function pct(used: number, total: number) {
  if (!total) return 0;
  return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}
const ramPct = computed(() => {
  const i = info.value;
  if (!i || !i.ramBytes) return 0;
  const used = i.ramBytes - (i.ramFreeBytes || 0);
  return pct(used, i.ramBytes);
});
const ramUsedText = computed(() => {
  const i = info.value;
  if (!i || !i.ramBytes) return '';
  const used = (i.ramBytes - (i.ramFreeBytes || 0)) / 1024 / 1024 / 1024;
  const total = i.ramBytes / 1024 / 1024 / 1024;
  return `${used.toFixed(1)} / ${total.toFixed(0)} GB`;
});
const storagePct = computed(() => {
  const i = info.value;
  if (!i || !i.storageTotalBytes) return 0;
  return pct(i.storageTotalBytes - (i.storageFreeBytes || 0), i.storageTotalBytes);
});
const storageText = computed(() => {
  const i = info.value;
  if (!i || !i.storageTotalBytes) return '';
  const free = i.storageFreeBytes / 1024 / 1024 / 1024;
  const total = i.storageTotalBytes / 1024 / 1024 / 1024;
  return `${free.toFixed(0)} / ${total.toFixed(0)} GB 可用`;
});
const batteryPct = computed(() => info.value?.battery ?? null);

// 环形进度：周长固定的圆环，用 stroke-dasharray 过渡
const RING = 2 * Math.PI * 26;
function ringDash(p: number) {
  return `${(RING * p) / 100} ${RING}`;
}

async function loadInfo(d: DeviceView | null) {
  const token = ++infoToken;
  painted.value = false;
  if (!d) { info.value = null; infoFailed.value = ''; return; }
  infoLoading.value = true;
  try {
    const r = await getDeviceInfo(d.serial);
    if (token !== infoToken) return;
    info.value = r.ok && r.info ? r.info : null;
    infoFailed.value = r.ok ? '' : (r.error ?? '读取失败');
  } catch (e) {
    if (token === infoToken) { info.value = null; infoFailed.value = (e as Error).message; }
  } finally {
    if (token !== infoToken) return;
    infoLoading.value = false;
    // 先渲染 0%，下一帧再给真值，进度环/条才有生长动画
    requestAnimationFrame(() => { if (token === infoToken) painted.value = true; });
  }
}

function openDialog() {
  show.value = true;
  addOpen.value = false;
  void refreshDevices();
  void loadInfo(current.value);
}
watch(() => [props.selected, show.value] as const, () => {
  if (!show.value) return;
  void loadInfo(current.value);
});

/** 点列表 = 切换设备 */
function pick(d: DeviceView) {
  emit('select', d.key);
  show.value = false;
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

function openAdd() {
  addOpen.value = true;
  addKind.value = 'usb';
  addSerial.value = '';
  addAddress.value = '';
  addName.value = '';
  addError.value = '';
}
const USABLE_SERIAL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const NET_ADDRESS = /^[A-Za-z0-9][A-Za-z0-9._-]*:\d{1,5}$/;
async function saveAdd() {
  addError.value = '';
  if (addKind.value === 'usb') {
    const serial = addSerial.value.trim();
    if (!USABLE_SERIAL.test(serial)) { addError.value = '串号格式不对；手机开发者选项的 USB 调试里能看到。'; return; }
    rememberDevice(serial, addName.value);
    toast(`已添加 ${addName.value.trim() || serial}`);
    addOpen.value = false;
    return;
  }
  const address = addAddress.value.trim();
  if (!NET_ADDRESS.test(address)) { addError.value = '地址要写成 IP:端口，例如 192.168.1.50:5555'; return; }
  addBusy.value = true;
  try {
    const r = await adbConnectDevice(address);
    if (!r.ok) { addError.value = r.error ?? '连不上这个地址'; return; }
    rememberDevice(address, addName.value);
    toast(`已添加网络设备 ${addName.value.trim() || address}`);
    addOpen.value = false;
  } catch (e) {
    addError.value = (e as Error).message;
  } finally {
    addBusy.value = false;
  }
}

function forget(d: DeviceView) {
  forgetDevice(d.key);
  toast(`已从列表移除 ${deviceLabel(d)}`);
}

function rowTitle(d: DeviceView) {
  const bits = [deviceLabel(d), d.serial, linkText(d), adbText(d)];
  if (d.rpc) bits.push('设备通道已连接');
  if (d.agent?.online) bits.push(`agent ${d.agent.sessionId} 在线`);
  if (!isOnline(d) && d.seenAt) bits.push(`上次在线 ${timeAgo(d.seenAt)}`);
  return bits.join(' · ');
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

    <n-modal :show="show" @update:show="!$event && (show = false)">
      <div class="app-dialog device-dialog show" role="dialog" aria-modal="true" aria-label="设备">
        <!-- 上面一整块：左信息面板 / 右操作面板 -->
        <section class="device-top">
          <div class="device-info">
            <div class="device-hero">
              <span class="device-face" :class="dotClass(current || devices[0])">
                <n-icon size="22" :component="PhonePortraitOutline" />
              </span>
              <div class="device-hero-text">
                <strong>{{ current ? deviceLabel(current) : '没有设备' }}</strong>
                <span v-if="current" class="device-tags">
                  <em class="tag" :class="dotClass(current)">{{ adbText(current) }}</em>
                  <em class="tag"><n-icon size="11" :component="LinkOutline" />{{ linkText(current) }}</em>
                  <em v-if="pluginText(current)" class="tag">{{ pluginText(current) }}</em>
                </span>
                <span v-else class="device-muted">{{ props.failed ? '设备读取失败，保留上次清册' : '插上手机，或用右边的「添加设备」登记' }}</span>
              </div>
            </div>

            <div class="device-gauges">
              <div class="gauge">
                <svg viewBox="0 0 64 64" class="gauge-ring" :class="{ bad: ramPct >= 88, warn: ramPct >= 70 && ramPct < 88 }">
                  <circle cx="32" cy="32" r="26" class="ring-track" />
                  <circle cx="32" cy="32" r="26" class="ring-value" :style="{ strokeDasharray: ringDash(painted ? ramPct : 0) }" />
                </svg>
                <span class="gauge-num">{{ ramPct }}<i>%</i></span>
                <span class="gauge-label">内存</span>
                <span class="gauge-sub">{{ ramUsedText || '—' }}</span>
              </div>

              <div class="gauge">
                <svg viewBox="0 0 64 64" class="gauge-ring" :class="{ warn: storagePct >= 80, bad: storagePct >= 92 }">
                  <circle cx="32" cy="32" r="26" class="ring-track" />
                  <circle cx="32" cy="32" r="26" class="ring-value" :style="{ strokeDasharray: ringDash(painted ? storagePct : 0) }" />
                </svg>
                <span class="gauge-num">{{ storagePct }}<i>%</i></span>
                <span class="gauge-label">存储占用</span>
                <span class="gauge-sub">{{ storageText || '—' }}</span>
              </div>

              <div class="gauge">
                <svg viewBox="0 0 64 64" class="gauge-ring" :class="{ bad: (batteryPct ?? 100) <= 15, warn: (batteryPct ?? 100) <= 30 }">
                  <circle cx="32" cy="32" r="26" class="ring-track" />
                  <circle cx="32" cy="32" r="26" class="ring-value" :style="{ strokeDasharray: ringDash(painted && batteryPct != null ? batteryPct : 0) }" />
                </svg>
                <span class="gauge-num">{{ batteryPct == null ? '—' : batteryPct }}<i v-if="batteryPct != null">%</i></span>
                <span class="gauge-label">电量</span>
                <span class="gauge-sub">{{ batteryPct == null ? '读取中' : '当前电量' }}</span>
              </div>
            </div>

            <div class="device-specs">
              <div><span>型号</span><strong>{{ info?.model || current?.model || '—' }}</strong></div>
              <div><span>系统</span><strong>{{ info ? `Android ${info.android}` : '—' }}</strong></div>
              <div><span>分辨率</span><strong>{{ info?.screen || '—' }}</strong></div>
              <div><span>ABI</span><strong>{{ info?.abi || '—' }}</strong></div>
            </div>
            <p v-if="infoLoading && !info" class="device-info-hint">读取设备信息…</p>
            <p v-else-if="infoFailed" class="device-info-hint bad">{{ infoFailed }}</p>
          </div>

          <aside class="device-actions">
            <button type="button" class="device-action primary" @click="openAdd">
              <n-icon size="16" :component="AddOutline" /><span>添加设备</span>
            </button>
            <button v-if="current" type="button" class="device-action" :disabled="!!busy" @click="reconnect(current)">
              <n-icon size="16" :component="RefreshOutline" />
              <span>{{ busy === current.key ? '重连中…' : '重连' }}</span>
            </button>
            <button type="button" class="device-action" @click="refreshDevices()">
              <n-icon size="16" :component="RefreshOutline" /><span>刷新列表</span>
            </button>
            <button v-if="current?.remembered" type="button" class="device-action danger" @click="forget(current)">
              <n-icon size="16" :component="TrashOutline" /><span>从列表移除</span>
            </button>
            <button type="button" class="device-action quiet" @click="show = false">
              <n-icon size="16" :component="CloseOutline" /><span>关闭</span>
            </button>
          </aside>
        </section>

        <!-- 下面一整块：只有设备列表 -->
        <section class="device-list">
          <header class="device-list-head">
            <h3>设备列表</h3>
            <span class="device-muted">{{ devices.length }} 台 · 点一行切换</span>
          </header>
          <div class="device-rows">
            <button v-for="d in devices" :key="d.key" type="button" class="device-row-item"
              :class="{ current: d.key === selected }" :title="rowTitle(d)" @click="pick(d)">
              <span class="status-dot" :class="dotClass(d)"></span>
              <span class="device-row-copy">
                <strong>{{ deviceLabel(d) }}</strong>
                <span>{{ d.serial }} · {{ linkText(d) }}</span>
              </span>
              <span v-if="d.key === selected" class="device-row-state">使用中</span>
              <span v-else-if="!isOnline(d) && d.seenAt" class="device-row-state muted">{{ timeAgo(d.seenAt) }}在线过</span>
              <span v-else class="device-row-state muted">{{ adbText(d) }}</span>
            </button>
            <div v-if="!devices.length" class="app-empty">没有设备；用上面的「添加设备」登记串号。</div>
          </div>
        </section>

        <div v-if="addOpen" class="device-add-panel">
          <n-radio-group v-model:value="addKind" size="small">
            <n-radio-button value="usb">USB 设备</n-radio-button>
            <n-radio-button value="net">局域网</n-radio-button>
          </n-radio-group>
          <div class="device-add-row">
            <n-select v-if="addKind === 'usb'" v-model:value="addSerial" size="small" filterable tag :options="usbOptions"
              placeholder="选择或输入设备串号，例如 aa165071" />
            <n-input v-else v-model:value="addAddress" size="small" placeholder="IP:端口，例如 192.168.1.50:5555" />
            <n-input v-model:value="addName" size="small" maxlength="40" placeholder="换个好记的名字（可选）" />
            <n-button size="small" type="primary" :loading="addBusy" @click="saveAdd">添加</n-button>
            <n-button size="small" quaternary @click="addOpen = false">取消</n-button>
          </div>
          <p class="device-add-hint">
            {{ addKind === 'usb' ? 'USB 设备直接登记串号；插拔不影响它留在列表里。'
              : '局域网需要手机和电脑在同一网络，且手机上已打开无线调试。' }}
          </p>
          <p v-if="addError" class="device-add-error">{{ addError }}</p>
        </div>
      </div>
    </n-modal>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NModal } from 'naive-ui';
import {
  ChevronDownOutline, CloseOutline, EllipsisHorizontalOutline, RefreshOutline, AddOutline, PhonePortraitOutline,
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

// 设备静态信息（型号/系统/RAM/存储/分辨率/电量）：打开窗口或换设备时读一次，daemon 侧缓存 60s
const info = ref<DeviceInfo | null>(null);
const infoLoading = ref(false);
const infoFailed = ref('');
let infoToken = 0;
async function loadInfo(d: DeviceView | null) {
  const token = ++infoToken;
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
    if (token === infoToken) infoLoading.value = false;
  }
}
const addError = ref('');

function isOnline(d: DeviceView) {
  return d.rpc || d.state === 'device' || d.state === 'online' || d.agent?.online === true;
}
/** 上面这块只描述「当前选中」的那台：点列表里的任意一行就换它。 */
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
/** 连接方式：USB 还是局域网（无线调试）。 */
function linkText(d: DeviceView) {
  return d.net ? '局域网' : 'USB';
}
/** 手机端插件（ADH 模块）版本，来自 agent HELLO 的 agentVer。 */
function pluginText(d: DeviceView) {
  const v = d.agent?.version?.trim();
  return v ? `插件 v${v}` : '';
}
function gbText(bytes: number) {
  if (!bytes) return '';
  const gb = bytes / 1024 / 1024 / 1024;
  return `${gb >= 10 ? Math.round(gb) : gb.toFixed(1)} GB`;
}
function ramText(bytes: number) {
  if (!bytes) return '';
  const gb = bytes / 1024 / 1024 / 1024;
  return `${gb >= 10 ? Math.round(gb) : gb.toFixed(1)} GB`;
}
function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const date = new Date(ts);
  return `${date.getMonth() + 1}-${date.getDate()}`;
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

/** 点列表 = 切换设备（面板立即换到这台）。 */
function pick(d: DeviceView) {
  emit('select', d.key);
  show.value = false;
}

/** 重连：ADB → reverse → 设备域通道 → agent 重拨，四层原因分别回显。 */
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
  }
}

// ---- 添加设备（窗口内面板） ----
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
        <div class="device-head">
          <span v-if="current" class="device-face" :class="dotClass(current)">
            <n-icon size="20" :component="PhonePortraitOutline" />
          </span>
          <div class="app-dialog-id">
            <template v-if="current">
              <strong>{{ deviceLabel(current) }}</strong>
              <span>
                {{ current.serial }} · {{ linkText(current) }}<template v-if="pluginText(current)"> · {{ pluginText(current) }}</template>
              </span>
              <div class="device-chips">
                <span v-if="infoLoading && !info">读取设备信息…</span>
                <template v-else-if="info">
                  <span v-if="info.model && deviceLabel(current) !== info.model">{{ info.model }}</span>
                  <span v-if="info.android">Android {{ info.android }}</span>
                  <span v-if="info.ramBytes">{{ ramText(info.ramBytes) }} 内存</span>
                  <span v-if="info.storageFreeBytes">可用 {{ gbText(info.storageFreeBytes) }}</span>
                  <span v-if="info.screen">{{ info.screen }}</span>
                  <span v-if="info.battery != null">电量 {{ info.battery }}%</span>
                </template>
                <span v-else-if="infoFailed">{{ infoFailed }}</span>
              </div>
            </template>
            <template v-else>
              <strong>没有设备</strong>
              <span>{{ props.failed ? '设备读取失败' : '插上手机，或用「添加设备」登记' }}</span>
            </template>
          </div>
          <div class="app-dialog-actions">
            <n-button size="small" type="primary" @click="openAdd">
              <template #icon><n-icon :component="AddOutline" /></template>添加设备
            </n-button>
            <n-button v-if="current" size="small" :loading="busy === current.key" :disabled="!!busy"
              @click="reconnect(current)">重连</n-button>
            <n-button size="small" quaternary circle aria-label="刷新" title="重新扫描" @click="refreshDevices()">
              <template #icon><n-icon :component="RefreshOutline" /></template>
            </n-button>
            <n-dropdown v-if="current?.remembered" trigger="click" :options="[{ label: '从列表移除', key: 'forget' }]"
              @select="() => current && forget(current)">
              <n-button size="small" quaternary aria-label="更多设备操作">
                <n-icon size="16" :component="EllipsisHorizontalOutline" />
              </n-button>
            </n-dropdown>
            <n-button text class="app-close" aria-label="关闭设备窗口" @click="show = false">
              <n-icon size="18" :component="CloseOutline" />
            </n-button>
          </div>
        </div>

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

        <div class="app-choices device-choices">
          <button v-for="d in devices" :key="d.key" type="button" class="app-item device-item"
            :class="{ current: d.key === selected }" :title="rowTitle(d)" @click="pick(d)">
            <span class="status-dot" :class="dotClass(d)"></span>
            <span class="app-copy">
              <span class="app-name">
                {{ deviceLabel(d) }}
                <span v-if="d.key === selected" class="device-badge accent">当前选中</span>
              </span>
              <span class="app-pkg">{{ d.serial }} · {{ linkText(d) }}</span>
            </span>
            <span v-if="!isOnline(d) && d.seenAt" class="device-seen">{{ timeAgo(d.seenAt) }}</span>
          </button>
          <div v-if="!devices.length" class="app-empty">
            {{ props.failed ? '设备读取失败，保留上次清册' : '没有设备；用上面的「添加设备」登记串号。' }}
          </div>
        </div>
      </div>
    </n-modal>
  </section>
</template>

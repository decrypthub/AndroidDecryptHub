<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { NModal } from 'naive-ui';
import {
  ChevronDownOutline, CloseOutline, EllipsisHorizontalOutline, RefreshOutline, AddOutline, PhonePortraitOutline,
} from '@vicons/ionicons5';
import type { DeviceView } from '../store';
import { toast, refreshDevices, deviceLabel, rememberDevice, renameDevice, forgetDevice } from '../store';
import { reconnectDevice, adbConnectDevice } from '../api';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();

const show = ref(false);
const focusKey = ref('');
const busy = ref('');
const bulkRunning = ref(false);

// 行内重命名 / 添加设备面板（都在这一个窗口里完成，不再套弹窗）
const editingName = ref(false);
const nameDraft = ref('');
const addOpen = ref(false);
const addKind = ref<'usb' | 'net'>('usb');
const addSerial = ref('');
const addAddress = ref('');
const addName = ref('');
const addBusy = ref(false);
const addError = ref('');

function isOnline(d: DeviceView) {
  return d.rpc || d.state === 'device' || d.state === 'online' || d.agent?.online === true;
}
const detail = computed(() => props.devices.find(d => d.key === focusKey.value) ?? props.devices[0] ?? null);
const isCurrent = computed(() => !!detail.value && detail.value.key === props.selected);
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
  focusKey.value = props.selected || props.devices[0]?.key || '';
  editingName.value = false;
  addOpen.value = false;
  void refreshDevices();
}
watch(() => props.selected, key => { if (key) focusKey.value = key; });

function focus(d: DeviceView) {
  focusKey.value = d.key;
  editingName.value = false;
}
function switchTo(d: DeviceView) {
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

async function reconnectAll() {
  const targets = props.devices.filter(d => d.remembered);
  if (!targets.length) { toast('先记住要管理的设备（改个名字即可），再全部重连'); return; }
  if (bulkRunning.value) return;
  bulkRunning.value = true;
  let ok = 0;
  const failed: string[] = [];
  for (const d of targets) {
    try {
      const r = await reconnectDevice(d.serial);
      if (r.ok) ok++;
      else failed.push(`${deviceLabel(d)}（${r.code ?? r.error ?? '失败'}）`);
    } catch (e) {
      failed.push(`${deviceLabel(d)}（${(e as Error).message}）`);
    }
  }
  bulkRunning.value = false;
  void refreshDevices();
  toast(failed.length
    ? `重连 ${targets.length} 台：成功 ${ok}，失败 ${failed.length} — ${failed.join('、')}`
    : `重连 ${targets.length} 台：全部成功`);
}

// ---- 重命名（行内） ----
function startRename(d: DeviceView) {
  editingName.value = true;
  nameDraft.value = d.name || d.model || d.serial;
}
function saveRename() {
  const name = nameDraft.value.trim();
  if (!name) { toast('名字不能为空'); return; }
  if (detail.value) renameDevice(detail.value.key, name);
  editingName.value = false;
  toast(`已改名为 ${name}`);
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
    focusKey.value = serial;
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
    focusKey.value = address;
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
  focusKey.value = props.devices.find(x => x.key !== d.key)?.key ?? '';
}

function detailMenu(d: DeviceView) {
  const items: Array<{ label: string; key: string; disabled?: boolean }> = [{ label: '重命名', key: 'rename' }];
  if (d.remembered) items.push({ label: '从列表移除', key: 'forget' });
  return items;
}

function rowTitle(d: DeviceView) {
  const bits = [deviceLabel(d), d.serial, linkText(d), adbText(d)];
  if (d.rpc) bits.push('设备通道已连接');
  if (d.agent?.online) bits.push(`agent ${d.agent.sessionId} 在线`);
  if (!isOnline(d) && d.seenAt) bits.push(`上次在线 ${timeAgo(d.seenAt)}`);
  return bits.join(' · ');
}

function onDetailAction(key: string) {
  const d = detail.value;
  if (!d) return;
  if (key === 'rename') startRename(d);
  else if (key === 'forget') forget(d);
}
</script>

<template>
  <section class="device-picker">
    <button type="button" class="device-context" :aria-expanded="show" title="设备（打开设备窗口）" @click="openDialog">
      <span class="context-label">设备</span>
      <strong>{{ (devices.find(d => d.key === selected) ? deviceLabel(devices.find(d => d.key === selected)!) : (failed ? '设备读取失败' : '选择设备')) }}</strong>
      <span class="device-link">{{ devices.find(d => d.key === selected)?.serial || '' }}</span>
      <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
    </button>

    <n-modal :show="show" @update:show="!$event && (show = false)">
      <div class="app-dialog device-dialog show" role="dialog" aria-modal="true" aria-label="设备">
        <div class="device-head">
          <h2>设备</h2>
          <span class="device-count">{{ devices.length }} 台</span>
          <n-button text class="app-close" aria-label="关闭设备窗口" @click="show = false">
            <n-icon size="18" :component="CloseOutline" />
          </n-button>
        </div>

        <div class="app-dialog-main">
          <div v-if="detail" class="app-dialog-card">
            <span class="device-face" :class="dotClass(detail)">
              <n-icon size="20" :component="PhonePortraitOutline" />
            </span>
            <div class="app-dialog-id">
              <template v-if="editingName">
                <n-input v-model:value="nameDraft" size="small" maxlength="40" placeholder="设备显示名"
                  @keydown.enter.prevent="saveRename" />
              </template>
              <template v-else>
                <strong>{{ deviceLabel(detail) }}</strong>
                <span>
                  {{ detail.serial }} · {{ linkText(detail) }}<template v-if="pluginText(detail)"> · {{ pluginText(detail) }}</template>
                </span>
              </template>
            </div>
            <div class="app-dialog-actions">
              <template v-if="editingName">
                <n-button size="small" type="primary" @click="saveRename">保存</n-button>
                <n-button size="small" quaternary @click="editingName = false">取消</n-button>
              </template>
              <template v-else>
                <n-button v-if="!isCurrent" size="small" type="primary" @click="switchTo(detail)">切换到此设备</n-button>
                <n-button size="small" :loading="busy === detail.key" :disabled="!!busy" @click="reconnect(detail)">重连</n-button>
                <n-dropdown trigger="click" :options="detailMenu(detail)" @select="onDetailAction">
                  <n-button size="small" quaternary aria-label="更多设备操作">
                    <n-icon size="16" :component="EllipsisHorizontalOutline" />
                  </n-button>
                </n-dropdown>
              </template>
            </div>
          </div>

          <div class="device-toolbar">
            <n-button size="small" type="primary" @click="openAdd">
              <template #icon><n-icon :component="AddOutline" /></template>添加设备
            </n-button>
            <n-button size="small" :loading="bulkRunning" title="只重连改过名字的设备，不动只是插着的手机" @click="reconnectAll">全部重连</n-button>
            <n-button size="small" quaternary circle aria-label="重新扫描" title="重新扫描" @click="refreshDevices()">
              <template #icon><n-icon :component="RefreshOutline" /></template>
            </n-button>
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
              <n-input v-model:value="addName" size="small" maxlength="40" placeholder="显示名（可选）" />
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
              :class="{ active: d.key === focusKey, current: d.key === selected }" :title="rowTitle(d)" @click="focus(d)">
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
      </div>
    </n-modal>
  </section>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { ChevronDownOutline, EllipsisHorizontalOutline } from '@vicons/ionicons5';
import type { DeviceView } from '../store';
import {
  toast, refreshDevices, deviceLabel, rememberDevice, renameDevice, forgetDevice, setDefaultDevice,
} from '../store';
import { connectDevice, disconnectDevice, reconnectDevice, adbConnectDevice } from '../api';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();
const open = ref(false);
const busy = ref('');

// 设备管理弹窗状态
const addOpen = ref(false);
const addKind = ref<'usb' | 'net'>('usb');
const addSerial = ref('');
const addAddress = ref('');
const addName = ref('');
const addBusy = ref(false);
const addError = ref('');
const renameOpen = ref(false);
const renameKey = ref('');
const renameName = ref('');
const forgetOpen = ref(false);
const forgetKey = ref('');
const bulkRunning = ref(false);

const cur = computed(() => props.devices.find(d => d.key === props.selected));

const groups = computed(() => {
  const rows = props.devices;
  return [
    { label: '已连接', rows: rows.filter(d => d.rpc) },
    { label: '在线', rows: rows.filter(d => !d.rpc && (d.state === 'device' || d.state === 'online')) },
    { label: '未连接', rows: rows.filter(d => !d.rpc && d.state !== 'device' && d.state !== 'online') },
  ].filter(g => g.rows.length);
});

const usbOptions = computed(() => props.devices
  .filter(d => !d.remembered && !d.net)
  .map(d => ({ label: `${d.model || d.serial} · ${d.serial}`, value: d.serial })));

const managedCount = computed(() => props.devices.filter(d => d.remembered).length);

const STATE_TEXT: Record<string, string> = {
  unauthorized: '未授权（手机上允许 USB 调试）', offline: '离线', disconnected: '未连接', unknown: '状态未知',
};

function isOnline(d: DeviceView) {
  return d.rpc || d.state === 'device' || d.state === 'online' || d.agent?.online === true;
}
function dotClass(d: DeviceView) {
  if (isOnline(d)) return 'ok';
  if (d.state === 'unauthorized' || d.state === 'offline' || d.state === 'disconnected') return 'bad';
  return '';
}
function timeAgo(ts: number) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  const date = new Date(ts);
  return `${date.getMonth() + 1}-${date.getDate()}`;
}
function statusLine(d: DeviceView) {
  const bits: string[] = [];
  if (d.rpc) bits.push('设备通道已连接');
  if (d.observed) bits.push(d.agent?.online ? `agent 在线 · ${d.agent.sessionId}` : 'agent 离线');
  if (!bits.length) {
    bits.push(d.state === 'device' || d.state === 'online' ? 'ADB 已连接' : (STATE_TEXT[d.state] ?? d.state));
  }
  if (d.net) bits.push('网络');
  if (!isOnline(d) && d.seenAt) bits.push(`上次 ${timeAgo(d.seenAt)}`);
  return bits.join(' · ');
}

function pick(key: string) {
  emit('select', key);
  open.value = false;
}

async function connect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.key;
  try {
    await connectDevice(d.serial);
    toast(`设备通道已连上 ${deviceLabel(d)}`);
  } catch (e) {
    toast(`连接失败：${(e as Error).message}`);
  } finally {
    busy.value = '';
    void refreshDevices();
  }
}
async function disconnect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.key;
  try {
    const r = await disconnectDevice(d.serial);
    toast(r.dropped === false ? `${deviceLabel(d)} 没有活动连接` : `已断开 ${deviceLabel(d)} 的设备通道`);
  } catch (e) {
    toast(`断开失败：${(e as Error).message}`);
  } finally {
    busy.value = '';
    void refreshDevices();
  }
}

/** 重连：ADB → reverse → 设备通道 → agent 重拨，四层原因分别回显。 */
async function reconnect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.key;
  const label = deviceLabel(d);
  try {
    const r = await reconnectDevice(d.serial);
    if (r.ok) {
      const detail = r.agent
        ? `agent ${r.agent.online ? '已连上' : '仍离线'} · ${r.agent.waitedMs}ms`
        : r.rpc ? '设备通道已连接' : '已连接';
      const warn = r.warnings.length ? `（注意：${r.warnings[0]}）` : '';
      toast(`${label} 重连成功：${detail}${warn}`);
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
  if (!targets.length) { toast('先在设备菜单里记住要管理的设备，再全部重连'); return; }
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

// ---- 添加设备 ----
function openAdd() {
  addKind.value = 'usb';
  addSerial.value = '';
  addAddress.value = '';
  addName.value = '';
  addError.value = '';
  addOpen.value = true;
}
const USABLE_SERIAL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const NET_ADDRESS = /^[A-Za-z0-9][A-Za-z0-9._-]*:\d{1,5}$/;
async function saveAdd() {
  addError.value = '';
  if (addKind.value === 'usb') {
    const serial = addSerial.value.trim();
    if (!USABLE_SERIAL.test(serial)) { addError.value = '串号格式不对；请在手机开发者选项里看 adb 设备串号。'; return; }
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

// ---- 重命名 / 忘记 ----
function openRename(d: DeviceView) {
  renameKey.value = d.key;
  renameName.value = d.name || d.model || d.serial;
  renameOpen.value = true;
}
function saveRename() {
  const name = renameName.value.trim();
  if (!name) { toast('名字不能为空'); return; }
  renameDevice(renameKey.value, name);
  toast(`已改名为 ${name}`);
  renameOpen.value = false;
}
function askForget(d: DeviceView) {
  forgetKey.value = d.key;
  forgetOpen.value = true;
}
function confirmForget() {
  const device = props.devices.find(d => d.key === forgetKey.value);
  forgetDevice(forgetKey.value);
  toast(`已从列表移除 ${device ? deviceLabel(device) : '设备'}`);
  forgetOpen.value = false;
}

const forgetTarget = computed(() => props.devices.find(d => d.key === forgetKey.value));

function rowOptions(d: DeviceView) {
  const items: Array<{ label: string; key: string; disabled?: boolean }> = [];
  if (d.rpc) items.push({ label: '断开设备通道', key: 'disconnect' });
  else if (d.state === 'device' || d.state === 'online') items.push({ label: '连接设备通道', key: 'connect' });
  items.push({ label: '重连', key: 'reconnect' });
  items.push({ label: d.isDefault ? '已是默认设备' : '设为默认设备', key: 'default', disabled: !!d.isDefault });
  items.push({ label: '重命名', key: 'rename' });
  items.push(d.remembered ? { label: '忘记这台设备', key: 'forget' } : { label: '记住这台设备', key: 'remember' });
  return items;
}
function onRowAction(key: string, d: DeviceView) {
  if (key === 'connect') void connect(d);
  else if (key === 'disconnect') void disconnect(d);
  else if (key === 'reconnect') void reconnect(d);
  else if (key === 'default') { setDefaultDevice(d.key); toast(`默认设备设为 ${deviceLabel(d)}`); }
  else if (key === 'rename') openRename(d);
  else if (key === 'forget') askForget(d);
  else if (key === 'remember') { rememberDevice(d.key); toast(`已记住 ${deviceLabel(d)}`); }
}

function onDocClick(e: MouseEvent) {
  const target = e.target as HTMLElement;
  if (target.closest('.device-picker')) return;
  // 行菜单与弹窗由 naive-ui teleport 到 body，点它们不算「点到了面板外面」，
  // 否则选一个行操作就会把设备菜单一起收起来（重命名/记住这类连续操作会被打断）。
  if (target.closest('.n-dropdown-menu, .n-modal-container, .n-modal, .v-binder-follower-container')) return;
  open.value = false;
}
onMounted(() => document.addEventListener('click', onDocClick));
onUnmounted(() => document.removeEventListener('click', onDocClick));
</script>

<template>
  <section class="device-picker" @keydown.esc.stop="open = false; ($event.currentTarget as HTMLElement).querySelector('button')?.focus()">
    <button type="button" class="device-context" :aria-expanded="open" title="设备管理" @click.stop="open = !open">
      <span class="context-label">设备</span>
      <strong>{{ cur ? deviceLabel(cur) : (failed ? '设备读取失败' : '选择设备') }}</strong>
      <span class="device-link">{{ cur?.serial || '' }}</span>
      <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
    </button>

    <div class="popover device-menu" :class="{ show: open }">
      <div class="device-menu-head">
        <span class="device-menu-label">设备</span>
        <div class="device-menu-tools">
          <n-button size="tiny" quaternary :loading="bulkRunning" title="重连所有已记住的设备" @click.stop="reconnectAll">全部重连</n-button>
          <n-button size="tiny" quaternary title="重新扫描设备列表" @click.stop="refreshDevices()">重新扫描</n-button>
          <n-button size="tiny" type="primary" @click.stop="openAdd">添加设备</n-button>
        </div>
      </div>

      <template v-for="g in groups" :key="g.label">
        <div class="app-section">{{ g.label }}</div>
        <div v-for="d in g.rows" :key="d.key" class="device-row">
          <button type="button" class="app-item" :class="{ active: d.key === selected }" @click="pick(d.key)">
            <span class="app-copy">
              <span class="app-name">
                <span class="status-dot" :class="dotClass(d)" style="margin-right:7px"></span>{{ deviceLabel(d) }}
                <span v-if="d.isDefault" class="device-badge">默认</span>
                <span v-if="d.observed" class="device-badge accent">观察中</span>
              </span>
              <span class="app-pkg">{{ d.serial }}<template v-if="d.net"> · 无线</template> · {{ statusLine(d) }}</span>
            </span>
          </button>
          <span class="device-row-actions">
            <n-button size="tiny" quaternary :loading="busy === d.key" :disabled="!!busy" @click.stop="reconnect(d)">重连</n-button>
            <n-dropdown trigger="click" :options="rowOptions(d)" @select="(key: string) => onRowAction(key, d)">
              <n-button size="tiny" quaternary aria-label="更多设备操作">
                <n-icon size="15" :component="EllipsisHorizontalOutline" />
              </n-button>
            </n-dropdown>
          </span>
        </div>
      </template>
      <div v-if="!devices.length" class="app-empty">没有设备；用「添加设备」登记串号，或检查手机是否插好。</div>
      <div class="device-menu-foot">
        已记住 {{ managedCount }} 台 · 添加过的设备重启后会留在列表里
      </div>
    </div>

    <!-- 添加设备 -->
    <n-modal v-model:show="addOpen" preset="card" title="添加设备" class="device-modal" :bordered="false">
      <n-radio-group v-model:value="addKind" size="small" class="device-add-kind">
        <n-radio-button value="usb">USB 设备</n-radio-button>
        <n-radio-button value="net">无线调试</n-radio-button>
      </n-radio-group>
      <template v-if="addKind === 'usb'">
        <p class="device-add-hint">从当前已插上的设备里选，或直接输入串号（手机开发者选项 → USB 调试里能看到）。</p>
        <n-select v-model:value="addSerial" size="small" filterable tag :options="usbOptions"
          placeholder="选择或输入设备串号，例如 aa165071" />
      </template>
      <template v-else>
        <p class="device-add-hint">手机和电脑要在同一网络，且手机已开启「无线调试」。格式：IP:端口。</p>
        <n-input v-model:value="addAddress" size="small" placeholder="例如 192.168.1.50:5555" />
      </template>
      <n-input v-model:value="addName" size="small" class="device-add-name" placeholder="显示名（可选），例如 测试机" />
      <p v-if="addError" class="device-add-error">{{ addError }}</p>
      <template #footer>
        <div class="device-modal-actions">
          <n-button size="small" quaternary :disabled="addBusy" @click="addOpen = false">取消</n-button>
          <n-button size="small" type="primary" :loading="addBusy" @click="saveAdd">保存</n-button>
        </div>
      </template>
    </n-modal>

    <!-- 重命名 -->
    <n-modal v-model:show="renameOpen" preset="card" title="重命名设备" class="device-modal" :bordered="false">
      <n-input v-model:value="renameName" size="small" maxlength="40" show-count placeholder="设备显示名" />
      <template #footer>
        <div class="device-modal-actions">
          <n-button size="small" quaternary @click="renameOpen = false">取消</n-button>
          <n-button size="small" type="primary" @click="saveRename">保存</n-button>
        </div>
      </template>
    </n-modal>

    <!-- 忘记设备 -->
    <n-modal v-model:show="forgetOpen" preset="card" title="忘记这台设备？" class="device-modal" :bordered="false">
      <p class="device-add-hint">
        只会从面板列表里移除{{ forgetTarget ? '「' + deviceLabel(forgetTarget) + '」' : '' }}，不会断开手机、不改手机上的任何设置。
      </p>
      <template #footer>
        <div class="device-modal-actions">
          <n-button size="small" quaternary @click="forgetOpen = false">取消</n-button>
          <n-button size="small" type="error" @click="confirmForget">忘记</n-button>
        </div>
      </template>
    </n-modal>
  </section>
</template>

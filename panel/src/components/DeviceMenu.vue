<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { ChevronDownOutline } from '@vicons/ionicons5';
import type { DeviceView } from '../store';
import { toast, refreshDevices } from '../store';
import { connectDevice, disconnectDevice } from '../api';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();
const open = ref(false);
const busy = ref('');

const cur = computed(() => props.devices.find(d => d.key === props.selected));
function pick(key: string) { emit('select', key); open.value = false; }

// 已连接 = adh.device/1 RPC 通道在线；其余 adb 能看到的都算可发现（含未授权/离线，如实显示状态）
const groups = computed(() => [
  { label: '已连接', rows: props.devices.filter(d => d.rpc) },
  { label: '可发现', rows: props.devices.filter(d => !d.rpc) },
].filter(g => g.rows.length));

function dotClass(d: DeviceView) {
  if (d.state === 'device' || d.state === 'online') return 'ok';
  if (d.state === 'unauthorized' || d.state === 'offline' || d.state === 'disconnected') return 'bad';
  return '';
}
// adb state 与 localUsb linkState 两套词汇在这里汇合，只翻译已知状态，其余原样显示
const STATE_TEXT: Record<string, string> = { unauthorized: '未授权', offline: '离线', disconnected: '已拔掉', unknown: '状态未知' };
function stateText(d: DeviceView) {
  if (d.state === 'device' || d.state === 'online') return '';
  return STATE_TEXT[d.state] ?? d.state;
}

async function connect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.serial;
  try {
    await connectDevice(d.serial);
    toast(`已连接 ${d.model || d.serial}`);
  } catch (e) {
    toast(`连接失败：${(e as Error).message}`);
  } finally {
    busy.value = '';
    void refreshDevices();
  }
}
async function disconnect(d: DeviceView) {
  if (busy.value) return;
  busy.value = d.serial;
  try {
    const r = await disconnectDevice(d.serial);
    toast(r.dropped === false ? `${d.model || d.serial} 没有活动连接` : `已断开 ${d.model || d.serial}`);
  } catch (e) {
    toast(`断开失败：${(e as Error).message}`);
  } finally {
    busy.value = '';
    void refreshDevices();
  }
}

function onDocClick(e: MouseEvent) {
  if (!(e.target as HTMLElement).closest('.device-picker')) open.value = false;
}
onMounted(() => document.addEventListener('click', onDocClick));
onUnmounted(() => document.removeEventListener('click', onDocClick));
</script>

<template>
  <section class="device-picker" @keydown.esc.stop="open = false; ($event.currentTarget as HTMLElement).querySelector('button')?.focus()">
    <button type="button" class="device-context" :aria-expanded="open" title="切换设备" @click.stop="open = !open">
      <span class="context-label">设备</span>
      <strong>{{ cur?.model || (failed ? '设备读取失败' : '选择设备') }}</strong>
      <span class="device-link">{{ cur?.serial || '' }}</span>
      <span class="menu-chevron"><n-icon size="11" :component="ChevronDownOutline" /></span>
    </button>
    <div class="popover device-menu" :class="{ show: open }">
      <div class="device-menu-label">设备</div>
      <template v-for="g in groups" :key="g.label">
        <div class="app-section">{{ g.label }}</div>
        <div v-for="d in g.rows" :key="d.key" class="device-row">
          <button type="button" class="app-item" :class="{ active: d.key === selected }" @click="pick(d.key)">
            <span class="app-copy">
              <span class="app-name">
                <span class="status-dot" :class="dotClass(d)"
                  style="margin-right:7px"></span>{{ d.model }}</span>
              <span class="app-pkg">{{ d.serial }}<template v-if="d.observed"> · 观察 {{ d.observed }}</template><template v-if="stateText(d)"> · {{ stateText(d) }}</template></span>
            </span>
          </button>
          <span class="device-row-actions">
            <button v-if="d.rpc" type="button" class="dev-action" :disabled="!!busy"
              @click.stop="disconnect(d)">断开</button>
            <button v-else-if="d.state === 'device'" type="button" class="dev-action" :disabled="!!busy"
              @click.stop="connect(d)">连接</button>
          </span>
        </div>
      </template>
      <div v-if="!devices.length" class="app-empty">没有设备</div>
    </div>
  </section>
</template>

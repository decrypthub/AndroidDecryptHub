<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import type { DeviceView } from '../store';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();
const open = ref(false);

const cur = computed(() => props.devices.find(d => d.key === props.selected));
function pick(key: string) { emit('select', key); open.value = false; }

function onDocClick(e: MouseEvent) {
  if (!(e.target as HTMLElement).closest('.device-picker')) open.value = false;
}
onMounted(() => document.addEventListener('click', onDocClick));
onUnmounted(() => document.removeEventListener('click', onDocClick));
</script>

<template>
  <section class="device-picker">
    <button type="button" class="device-context" :aria-expanded="open" title="切换设备" @click.stop="open = !open">
      <span class="context-label">设备</span>
      <strong>{{ cur?.model || '读取中…' }}</strong>
      <span class="device-link">{{ cur?.serial || '' }}</span>
      <span class="menu-chevron"><svg viewBox="0 0 12 12" width="10" height="10" fill="none" stroke="currentColor"
          stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M2.5 4.5l3.5 3.5 3.5-3.5" /></svg></span>
    </button>
    <div class="popover device-menu" :class="{ show: open }">
      <div class="device-menu-label">设备</div>
      <div v-for="d in devices" :key="d.key" class="device-row">
        <button type="button" class="app-item" :class="{ active: d.key === selected }" @click="pick(d.key)">
          <span class="app-copy">
            <span class="app-name">
              <span class="status-dot" :class="d.online === false ? 'bad' : 'ok'"
                style="margin-right:7px"></span>{{ d.model }}</span>
            <span class="app-pkg">{{ d.serial }}<template v-if="d.observed"> · 观察 {{ d.observed }}</template></span>
          </span>
        </button>
      </div>
      <div v-if="!devices.length" class="app-empty">没有设备</div>
    </div>
  </section>
</template>

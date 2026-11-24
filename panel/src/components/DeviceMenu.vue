<script setup lang="ts">
import { ref, computed } from 'vue';
import type { DeviceView } from '../store';

const props = defineProps<{ devices: DeviceView[]; failed: boolean; selected: string }>();
const emit = defineEmits<{ select: [key: string] }>();
const open = ref(false);

const cur = computed(() => props.devices.find(d => d.key === props.selected));
function pick(key: string) { emit('select', key); open.value = false; }
</script>

<template>
  <div class="devmenu">
    <button class="btn dev-btn" @click="open = !open">
      <span class="status-dot" :class="cur?.online === false ? 'bad' : 'ok'"></span>
      {{ cur?.model || '选择设备' }}
      <span v-if="failed" class="badge fail">读取失败</span>
    </button>
    <div v-if="open" class="devmenu-pop" @mouseleave="open = false">
      <button v-for="d in devices" :key="d.key" class="devmenu-item" :class="{ on: d.key === selected }"
        @click="pick(d.key)">
        <span class="status-dot" :class="d.online === false ? 'bad' : 'ok'"></span>
        <span class="devmenu-model">{{ d.model }}</span>
        <span class="mono muted">{{ d.serial }}</span>
        <span v-if="d.observed" class="badge">观察 {{ d.observed }}</span>
      </button>
      <div v-if="!devices.length" class="devmenu-item muted">没有设备</div>
    </div>
  </div>
</template>

<style scoped>
.devmenu { position: relative; }
.devmenu-pop {
  position: absolute; top: calc(100% + 6px); left: 0; z-index: 40;
  min-width: 280px; background: var(--surface-2); border: 1px solid var(--line);
  border-radius: 10px; padding: 6px; box-shadow: 0 12px 32px #000a;
}
.devmenu-item {
  display: flex; align-items: center; gap: 8px; width: 100%;
  padding: 8px 10px; border: 0; border-radius: 7px; background: none;
  color: var(--ink-2); cursor: pointer; text-align: left; font-size: 13px;
}
.devmenu-item:hover { background: var(--surface-3); }
.devmenu-item.on { background: var(--surface-3); }
.devmenu-model { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>

import { computed, onMounted, onUnmounted, ref, watchEffect } from 'vue';

export type Appearance = 'system' | 'light' | 'dark';
const key = 'decrypthub.panel.appearance';
const media = window.matchMedia('(prefers-color-scheme: dark)');
const normalize = (s: string | null): Appearance => s === 'light' || s === 'dark' ? s : 'system';
function read(): Appearance { try { return normalize(localStorage.getItem(key)); } catch { return 'system'; } }
export const appearance = ref<Appearance>(read());
const systemDark = ref(media.matches);
export const isDark = computed(() => appearance.value === 'system' ? systemDark.value : appearance.value === 'dark');
export function setAppearance(value: Appearance) {
  appearance.value = value;
  try { localStorage.setItem(key, value); } catch { /* Session-only preference. */ }
}
export function useAppearance() {
  const onMedia = () => { systemDark.value = media.matches; };
  const onStorage = (e: StorageEvent) => { if (e.key === key || e.key === null) appearance.value = read(); };
  watchEffect(() => {
    document.documentElement.dataset.appearance = isDark.value ? 'dark' : 'light';
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', isDark.value ? '#090b0d' : '#fbfcfd');
  });
  onMounted(() => { onMedia(); media.addEventListener('change', onMedia); window.addEventListener('storage', onStorage); });
  onUnmounted(() => { media.removeEventListener('change', onMedia); window.removeEventListener('storage', onStorage); });
}


<script setup lang="ts">
import {ref,watch} from 'vue';import {OpenOutline,HelpCircleOutline} from '@vicons/ionicons5';import {getHealth} from '../api';import {SUPPORT_LINKS,COPYRIGHT,LICENSE_NAME} from '../support';
const show=ref(false),hostVersion=ref('读取中…');let request=0;
watch(show,async open=>{if(!open){request++;return;}const n=++request;hostVersion.value='读取中…';try{const h=await getHealth();if(n===request)hostVersion.value=h.ok&&typeof h.version==='string'?h.version:'版本未提供';}catch{if(n===request)hostVersion.value='暂时无法读取';}});
</script>
<template>
 <n-tooltip trigger="hover"><template #trigger><n-button quaternary circle size="small" aria-label="帮助与关于" @click="show=true"><template #icon><n-icon size="19" :component="HelpCircleOutline" /></template></n-button></template>帮助与关于</n-tooltip>
 <n-modal v-model:show="show" preset="card" title="帮助与关于" class="help-modal ui-window" :style="{width:'min(440px, calc(100vw - 24px))',maxHeight:'calc(100dvh - 48px)'}" :content-style="{overflow:'auto'}">
  <div class="help-product"><img src="/raven.svg" alt=""><div><h2>Android DecryptHub</h2><p>电脑端版本 {{ hostVersion }}</p></div></div>
  <div class="help-links"><a v-for="item in SUPPORT_LINKS" :key="item.label" :href="item.url" target="_blank" rel="noopener noreferrer"><span><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span><n-icon :component="OpenOutline" /></a></div>
  <footer class="help-footer"><span>{{ COPYRIGHT }}</span><span>{{ LICENSE_NAME }}</span></footer>
 </n-modal>
</template>
<style scoped>.help-product{display:flex;align-items:center;gap:14px;margin:0 0 22px}.help-product img{width:40px;height:40px;border-radius:10px}.help-product h2{margin:0;font-size:17px;color:var(--ink);font-weight:600}.help-product p{margin:5px 0 0;font-size:12px;color:var(--muted)}.help-links{display:grid;gap:4px}.help-links a{display:flex;align-items:center;justify-content:space-between;gap:16px;text-decoration:none;color:var(--ink);padding:13px 12px;border-radius:8px;transition:background .15s}.help-links a:hover,.help-links a:focus-visible{background:var(--surface-2)}.help-links a>span{display:grid;gap:4px}.help-links strong{font-size:13px;font-weight:550}.help-links small,.help-links .n-icon{font-size:12px;color:var(--muted)}.help-footer{margin-top:20px;padding-top:15px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11px}</style>

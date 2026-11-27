<script setup lang="ts">
import {ref} from 'vue';
import {getHostSettingsSnapshot,exportHostSettings,importHostSettings,type HostSettingsView} from '../api';
import {downloadBlob} from '../user_actions';
const fileInput=ref<HTMLInputElement|null>(null),busy=ref(false),error=ref(''),notice=ref(''),blocked=ref(false);
const preview=ref<null|{name:string;patch:Record<string,unknown>;view:HostSettingsView}>(null);
async function selectFile(event:Event){
 const input=event.target as HTMLInputElement,file=input.files?.[0];input.value='';if(!file||busy.value)return;
 busy.value=true;error.value='';notice.value='';blocked.value=false;preview.value=null;
 try{
  if(file.size>256*1024)throw new Error('设置文件超过 256 KiB，未读取');
  const patch=JSON.parse(await file.text());if(!patch||typeof patch!=='object'||Array.isArray(patch)||!Object.keys(patch).length)throw new Error('设置文件顶层须为非空 JSON 对象');
  const view=await getHostSettingsSnapshot();preview.value={name:file.name,patch,view};
 }catch(e){error.value=(e as Error).message;}finally{busy.value=false;}
}
async function confirmImport(){
 if(!preview.value||busy.value||blocked.value)return;const target=preview.value;busy.value=true;error.value='';notice.value='';
 try{const result=await importHostSettings(target.view,target.patch);if(result?.ok!==true||result?.persisted!==true)throw Object.assign(new Error('写入未确认；请刷新核查，不要直接重发导入'),{uncertain:true});notice.value='已导入并确认保存';preview.value=null;}
 catch(e){blocked.value=true;error.value=(e as Error).message;}
 finally{busy.value=false;}
}
async function downloadSettings(){
 if(busy.value)return;busy.value=true;error.value='';notice.value='';
 try{const data=await exportHostSettings();downloadBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),'adh-host-settings.json');notice.value='已发起下载，请查看浏览器下载';}
 catch(e){error.value=(e as Error).message;}finally{busy.value=false;}
}
</script>
<template>
 <section class="advanced-host-settings" aria-label="电脑端设置与 AI 客户端">
  <h3>电脑端设置</h3>
  <div class="host-settings-actions">
   <n-button size="small" secondary :disabled="busy" @click="downloadSettings">导出电脑端设置</n-button>
   <n-button size="small" secondary :disabled="busy" @click="fileInput?.click()">导入电脑端设置…</n-button>
   <n-button size="small" text tag="a" href="/api/mcp/config" target="_blank" rel="noopener noreferrer">连接 AI 客户端</n-button>
  </div>
  <input ref="fileInput" type="file" accept=".json,application/json" class="sr-only" aria-label="选择电脑端设置文件" :disabled="busy" @change="selectFile" />
  <p class="host-settings-note">文件可能含连接信息。仅备份电脑端配置，不包含每台设备的两级 Hook 选择。</p>
  <p v-if="error" class="host-settings-error" role="alert">{{ error }}</p>
  <p v-if="notice" role="status">{{ notice }}</p>
  <n-modal :show="!!preview" preset="card" title="导入电脑端设置" :closable="!busy" :mask-closable="!busy" :close-on-esc="!busy"
   style="width:min(480px,calc(100vw - 28px))" @update:show="!$event && !busy && (preview=null)">
   <p>将修改电脑端的全局配置，可能影响其他连接；不会自动导入或应用设备 Hook 选择。</p>
   <p v-if="preview">{{ preview.name }} · 分区：{{ Object.keys(preview.patch).join('、') }}</p>
   <p v-if="error" class="host-settings-error" role="alert">{{ error }}</p>
   <p v-if="blocked">此请求不自动重试。请关闭后核查当前设置及操作记录，再决定是否重新选择文件。</p>
   <template #footer><div class="host-settings-actions"><n-button :disabled="busy" @click="preview=null">取消</n-button><n-button type="primary" :loading="busy" :disabled="blocked" @click="confirmImport">确认导入</n-button></div></template>
  </n-modal>
 </section>
</template>
<style scoped>
.advanced-host-settings{margin-top:24px;padding-top:18px;border-top:1px solid var(--line)}
.advanced-host-settings h3{font-size:14px;margin:0 0 12px}
.host-settings-actions{display:flex;flex-wrap:wrap;align-items:center;gap:12px}
.host-settings-note{font-size:12px;color:var(--muted);line-height:1.7}
.host-settings-error{color:var(--red);overflow-wrap:anywhere}
</style>

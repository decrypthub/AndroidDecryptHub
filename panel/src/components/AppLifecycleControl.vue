<script setup lang="ts">
import {computed,ref,watch} from 'vue';
import {PlayOutline,StopOutline} from '@vicons/ionicons5';
import {appControl,type AppInfo} from '../api';
import {store,refreshApps,toast} from '../store';
const props=defineProps<{serial:string;package:string;app?:AppInfo}>();
const busy=ref(false),confirmed=ref<{key:string;before:unknown;running:boolean}|null>(null);
const targetKey=computed(()=>props.serial+'\n'+props.package);
const running=computed<boolean|null>(()=>{
 if(confirmed.value?.key===targetKey.value&&props.app?.running===confirmed.value.before)return confirmed.value.running;
 if([...store.sessions.values()].some(s=>s.online&&s.package===props.package&&s.deviceBinding?.serial===props.serial))return true;
 if(props.app?.running==='foreground'||props.app?.running==='background')return true;
 if(props.app?.running==='')return false;
 return null;
});
const disabled=computed(()=>busy.value||!props.serial||!props.package||running.value===null);
const label=computed(()=>!props.serial||!props.package?'先选择设备和应用':running.value===null?'应用运行状态尚未确认':(running.value?'终止 ':'启动 ')+(props.app?.label||props.package));
watch(()=>targetKey.value+'\n'+String(props.app?.running??'unknown'),()=>{confirmed.value=null;});
async function toggle(){
 if(disabled.value)return;
 const serial=props.serial,pkg=props.package,name=props.app?.label||pkg,key=targetKey.value,before=props.app?.running,action=running.value?'stop':'open';
 busy.value=true;
 try{const result=await appControl(pkg,action,serial) as {ok?:boolean;error?:string};if(result?.ok!==true)throw Error(result?.error||'手机未确认操作');
  if(targetKey.value===key)confirmed.value={key,before,running:action==='open'};
  toast(name+(action==='open'?' 已启动':' 已终止'));void refreshApps();
 }catch(e){toast(name+' 操作未确认：'+(e as Error).message+'；请核对状态后再操作');void refreshApps();}
 finally{busy.value=false;}
}
</script>
<template><n-tooltip trigger="hover"><template #trigger><span class="app-lifecycle"><n-button quaternary circle size="small" :loading="busy" :disabled="disabled" :aria-label="label" @click="toggle"><template #icon><n-icon :component="running?StopOutline:PlayOutline" /></template></n-button></span></template>{{ label }}</n-tooltip></template>
<style scoped>.app-lifecycle{display:inline-flex;flex:none}.app-lifecycle .n-button{width:32px;height:32px}</style>

<script setup lang="ts">
import {computed,ref,watch,onBeforeUnmount} from 'vue';
import {store,appSessions,selectedSerial,toast} from '../store';
import {getCaptureControls,type CaptureControlsView} from '../api';
import {setBoardCapture} from '../board_capture';
import {BOARD_LABEL,boardCaptureState,type CaptureBoard} from '../../../daemon/src/capture_boards';
const props=defineProps<{kind:CaptureBoard}>();
const views=ref<CaptureControlsView[]>([]),loading=ref(false),busy=ref(false),error=ref('');let request=0,disposed=false;
const ids=computed(()=>[...new Set(appSessions.value.filter(s=>s.online&&s.package===store.chosenPkg&&s.deviceBinding?.serial===selectedSerial()).map(s=>s.sessionId))].sort());
const identity=()=>selectedSerial()+'\n'+store.chosenPkg+'\n'+props.kind+'\n'+ids.value.join(',');
const state=computed(()=>boardCaptureState(views.value,props.kind));
const disabled=computed(()=>loading.value||busy.value||!ids.value.length||!views.value.length||state.value.uncertain||views.value.some(v=>v.foreignOwner||v.lastIntent?.state==='unknown'||(v.control as any)?.uncertainOperations?.length));
const hint=computed(()=>error.value||(!ids.value.length?'连接当前 APP 后可控制本板块采集':views.value.some(v=>v.foreignOwner)?'此 APP 有进程由其他 Hook 计划控制':state.value.uncertain?'运行状态待确认，请先在设置中核查':'只控制当前设备、APP 的'+BOARD_LABEL[props.kind]+'采集，细分选择保留'));
async function load(){const key=identity(),n=++request,serial=selectedSerial(),pkg=store.chosenPkg,sessions=[...ids.value];views.value=[];if(!serial||!pkg||!sessions.length)return;loading.value=true;error.value='';try{const result=await Promise.all(sessions.map(id=>getCaptureControls(serial,pkg,id)));if(!disposed&&n===request&&key===identity())views.value=result;}catch(e){if(n===request)error.value=(e as Error).message;}finally{if(n===request)loading.value=false;}}
async function toggle(enabled:boolean){if(disabled.value)return;const target={serial:selectedSerial(),package:store.chosenPkg,kind:props.kind,sessions:[...ids.value]},key=identity();busy.value=true;error.value='';try{await setBoardCapture(target,enabled);toast(target.package+' 的'+BOARD_LABEL[target.kind]+'采集已'+(enabled?'开启':'停止'));}catch(e){error.value=(e as Error).message;toast('采集状态未全部确认：'+error.value);}finally{if(!disposed&&key===identity())await load();busy.value=false;}}
watch(()=>identity(),()=>void load(),{immediate:true});watch(()=>store.settingsOpen,open=>{if(!open&&!busy.value)void load();});watch(()=>store.wsState,s=>{if(s==='live'&&!busy.value)void load();});onBeforeUnmount(()=>{disposed=true;request++;});
</script>
<template><n-tooltip trigger="hover"><template #trigger><div class="board-capture-control"><span class="board-capture-label">{{ state.uncertain?'状态未确认':state.partial?'部分采集':state.checked?'采集中':'未采集' }}</span><n-switch :value="state.checked" :loading="busy||loading" :disabled="disabled" :aria-label="BOARD_LABEL[kind]+'采集总开关'" @update:value="toggle" /></div></template>{{ hint }}</n-tooltip></template>
<style scoped>.board-capture-control{display:flex;align-items:center;gap:9px;white-space:nowrap}.board-capture-label{font-size:12px;color:var(--muted)}@media(max-width:600px){.board-capture-label{display:none}}</style>

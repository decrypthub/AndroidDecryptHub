<script setup lang="ts">
import {computed,reactive,ref,shallowRef,watch,onMounted,onUnmounted,onActivated,onDeactivated,nextTick,onScopeDispose} from 'vue';
import {store,belongsToApp,capRemoveWhere,capDisplayCap,DISPLAY_CAPS,panelDisplay,savePanelDisplay,toast} from '../store';
import {downloadBlob} from '../user_actions';
import {createCaptureExport} from '../capture_export';
import {getCaptures,getExchanges,getCaptureDetail,clearCaptureBoard,type Cap} from '../api';
import {LogTimeline,virtualWindow} from '../log_timeline';
import {cacheLogRows,confirmCacheGeneration,clearCachedScope,cachedGeneration,cachedCount,readCachedRows,saveCachedPage,readCachedPage,saveCachedDetail,readCachedDetail,cacheWarning,refreshPreference,removeCachedRow} from '../log_cache';
import {catClass,cryptoView,capturePreviewPlaceholder,exchangeInputPreview,captureLengths,rowLens,systemRow,fmtTime,CATLABEL,type CatKey} from '../capview';
import {SearchOutline} from '@vicons/ionicons5';
import CapDetail from './CapDetail.vue';import ExchangeDetail from './ExchangeDetail.vue';
const props=defineProps<{kind:'crypto'|'system'|'net'}>();
interface Exchange {id:string;order?:number;seq?:number;displayId?:number;captureGeneration?:string;label?:string;status?:string;conn?:string;ts?:number;tsNs?:number;captureIds?:number[];note?:string;request?:any;response?:any;[key:string]:unknown}
const active=ref(true),filter=reactive({q:'',min:null as number|null,max:null as number|null,cat:-2,paused:false,kind:'all'}),advOpen=ref(false);
const sel=ref<number|string|null>(null),selDetail=ref<Record<string,unknown>|null>(null),selExchange=ref<Exchange|null>(null);
const listWidth=ref(0),dragging=ref(false),scrollTop=ref(0),viewportHeight=ref(700),newCount=ref(0),followBottom=ref(true),positioned=ref(false);
const pauseCeiling=ref<number|null>(null);
const pageLoading=ref(false),generation=ref(''),hasOlder=ref(true),oldestCursor=ref<number|null>(null),cacheCount=ref(0),loadError=ref(''),cacheNote=ref(''),archiveCount=ref(0);
const loaded=shallowRef<Cap[]>([]),exchanges=shallowRef<Exchange[]>([]),frozenCaptures=shallowRef<Cap[]|null>(null),frozenExchanges=shallowRef<Exchange[]|null>(null);
const capModel=new LogTimeline<any>(),netModel=new LogTimeline<any>();let request=0,poll=0,resize:ResizeObserver|null=null,suppressScroll=false;
const modalOpen=computed(()=>!!(store.settingsOpen||store.appDialogOpen||store.deviceDialogOpen));
const fromMs=ref<number|null>(null),toMs=ref<number|null>(null),fromTs=computed(()=>fromMs.value),toTs=computed(()=>toMs.value),hasTimeRange=computed(()=>fromTs.value!==null||toTs.value!==null);
const LIST_ID:Record<string,string>={crypto:'cc-list',system:'sy-list',net:'nt-list'},BOARD_LABEL:Record<string,string>={crypto:'加解密',system:'系统',net:'网络'},HEAD_LABELS:Record<string,[string,string,string]>={crypto:['算法','输入预览','输入 → 输出'],system:['函数','输入对象','操作'],net:['请求','请求预览','状态']};
const CAT_BY_SEL:Record<number,CatKey>={0:'digest',1:'hmac',2:'sym',3:'asym',4:'aead'},SYS_KINDS:Array<[string,string]>=[['all','全部活动'],['system','系统调用'],['file','文件读写']];
const searchPlaceholder=computed(()=>props.kind==='crypto'?'搜索 #序号、算法、Hook 或预览':'搜索 #序号、操作、Hook 或预览');
const identity=()=>store.selectedDeviceKey+'\n'+store.chosenPkg+'\n'+props.kind;
const scope=()=>({serial:store.devices.find(d=>d.key===store.selectedDeviceKey)?.serial||'',package:store.chosenPkg,kind:props.kind});
const panelCats=()=>props.kind==='crypto'?['crypto']:props.kind==='net'?['net']:['system','file'];
const serverCategory=()=>props.kind==='crypto'?'crypto':props.kind==='net'?'net':filter.kind==='all'?'system,file':filter.kind;
const matchesPanel=(c:Cap)=>panelCats().includes(c.category)&&(props.kind!=='system'||filter.kind==='all'||c.category===filter.kind);
const scoped=computed(()=>store.capItems.filter(c=>matchesPanel(c)&&belongsToApp(c)));
function applyClientFilter(source:Cap[]){return source.filter(c=>{if(!matchesPanel(c)||!belongsToApp(c))return false;if(c.category==='crypto'&&cryptoView(c).show===false)return false;if(fromTs.value!=null&&c.ts<fromTs.value||toTs.value!=null&&c.ts>toTs.value)return false;const q=filter.q.trim().toLowerCase();if(/^#\d+$/.test(q)){if(String(c.displayId??c.id)!==q.slice(1))return false;}else if(q&&![(c.algo||''),(c.op||''),(c.func||''),(c.path||''),(c.preview||''),(c.javaTarget||''),(c.captureMethodId||''),cryptoView(c).title].join(' ').toLowerCase().includes(q))return false;const n=captureLengths(c).input.bytes;if(filter.min!=null&&(n==null||n<filter.min)||filter.max!=null&&(n==null||n>filter.max))return false;if(props.kind==='crypto'&&filter.cat>=0&&catClass(c)!==CAT_BY_SEL[filter.cat])return false;return true;});}
const rows=computed(()=>props.kind==='net'?[]:applyClientFilter(filter.paused?frozenCaptures.value??[]:loaded.value));
const matchedExchanges=computed(()=>(filter.paused?frozenExchanges.value??[]:exchanges.value).filter(ex=>{if(fromTs.value!=null&&(ex.ts??0)<fromTs.value||toTs.value!=null&&(ex.ts??0)>toTs.value)return false;const q=filter.q.trim().toLowerCase();if(/^#\d+$/.test(q))return String(ex.displayId??ex.seq??'')===q.slice(1);const size=(ex.request?.bodyBytes??0)+(ex.response?.bodyBytes??0);return (!q||[ex.label,ex.status,ex.note,ex.request?.startLine,ex.request?.headerText,ex.request?.bodyText,ex.response?.startLine,ex.response?.bodyText].join(' ').toLowerCase().includes(q))&&(filter.min==null||size>=filter.min)&&(filter.max==null||size<=filter.max);}));
const matchedExchangesAll=matchedExchanges;
const exLoadedOnce=computed(()=>positioned.value);
const allRows=computed<Array<Cap|Exchange>>(()=>props.kind==='net'?matchedExchanges.value:rows.value),rowHeight=computed(()=>panelDisplay.density==='compact'?64:88),windowed=computed(()=>virtualWindow(allRows.value.length,scrollTop.value,viewportHeight.value,rowHeight.value));
const renderedRows=computed(()=>rows.value.slice(windowed.value.start,windowed.value.end)),renderedExchanges=computed(()=>matchedExchanges.value.slice(windowed.value.start,windowed.value.end));
const isHistoricalMode=computed(()=>!followBottom.value),canPrevPage=computed(()=>hasOlder.value&&!pageLoading.value),canNextPage=computed(()=>!followBottom.value),pageNumber=computed(()=>Math.max(1,Math.ceil(allRows.value.length/capDisplayCap.value))),countText=computed(()=>`${allRows.value.length} 条`);
const advCount=computed(()=>Number(filter.min!=null||filter.max!=null)+Number(props.kind==='crypto'&&filter.cat>=0)+Number(props.kind==='system'&&filter.kind!=='all')+Number(hasTimeRange.value));
const filterActive=computed(()=>!!(filter.q.trim()||advCount.value));
const listFootLeft=computed(()=>`当前列表 ${allRows.value.length.toLocaleString('zh-CN')} 条`);
const footHint=computed(()=>[listFootLeft.value,`浏览器缓存 ${cacheCount.value.toLocaleString('zh-CN')} 条`,`Host归档 ${archiveCount.value.toLocaleString('zh-CN')} 条${props.kind==='net'?'原始TLS':''}`,filter.paused?'持续刷新已关闭；采集与缓存继续':'持续刷新已开启',hasOlder.value?'向上滚动继续加载更早记录':'已到最早记录',loadError.value,cacheNote.value,'浏览器缓存不会主动淘汰；配额、浏览器清理仍可能影响，不代替备份'].filter(Boolean).join(' · '));
const listLoading=computed(()=>pageLoading.value&&!allRows.value.length),emptyText=computed(()=>!store.chosenPkg?'先在顶部选择应用。':loadError.value||((pageLoading.value)?'正在读取日志…':filterActive.value?'没有符合筛选条件的记录。':'还没有记录。'));
function listElement(){return document.getElementById(LIST_ID[props.kind]);}
async function bottom(){await nextTick();const el=listElement();if(el){suppressScroll=true;el.scrollTop=Math.max(0,el.scrollHeight-el.clientHeight);scrollTop.value=el.scrollTop;viewportHeight.value=el.clientHeight;await nextTick();suppressScroll=false;}followBottom.value=true;newCount.value=0;}
function mergeRecords(items:any[],network=false){const model=network?netModel:capModel,added=model.merge(items.map(c=>({...c,order:Number(c.order??c.seq??c.id)})));if(network)exchanges.value=[...model.items];else loaded.value=[...model.items];return added;}
async function loadServerPage(beforeId:number|null,force=false){
 if(pageLoading.value||!scope().serial||!store.chosenPkg)return;const target=identity(),token=++request,cacheScope=scope(),wasFollowing=followBottom.value&&!filter.paused,el=listElement(),anchorIndex=Math.floor((el?.scrollTop??0)/rowHeight.value),anchor=allRows.value[anchorIndex]?.id,offset=(el?.scrollTop??0)-anchorIndex*rowHeight.value;
 pageLoading.value=true;loadError.value='';const sig=JSON.stringify(['input-preview/1',beforeId,capDisplayCap.value,filter.q,filter.kind,fromTs.value,toTs.value,pauseCeiling.value]);
 try{
  let reply:any=!force&&beforeId!==null&&generation.value?await readCachedPage(cacheScope,generation.value,sig):null;
  if(!reply)reply=props.kind==='net'?await getExchanges(store.chosenPkg,{history:true,maxId:filter.paused?pauseCeiling.value:null,beforeId,limit:capDisplayCap.value,fromTs:fromTs.value,toTs:toTs.value}):await getCaptures({history:true,maxId:filter.paused?pauseCeiling.value:null,package:store.chosenPkg,category:serverCategory(),beforeId,fromTs:fromTs.value,toTs:toTs.value,q:filter.q.trim()||undefined,limit:capDisplayCap.value});
  if(target!==identity()||token!==request)return;if(reply.historyVersion!==1||!reply.generation||reply.scope?.serial!==cacheScope.serial||reply.scope?.package!==cacheScope.package)throw new Error('请更新Host以启用设备隔离的日志归档');
  if(generation.value&&generation.value!==reply.generation){capModel.clear();netModel.clear();loaded.value=[];exchanges.value=[];await clearCachedScope(cacheScope,reply.generation);oldestCursor.value=null;}
  generation.value=reply.generation;await confirmCacheGeneration(cacheScope,reply.generation);if(target!==identity()||token!==request)return;
  const items=props.kind==='net'?reply.exchanges??[]:reply.captures??[];mergeRecords(items,props.kind==='net');
  if(!positioned.value&&!filterActive.value&&props.kind!=='net'&&capModel.items.length){const source=capModel.items;let first=source.length-1;while(first>0&&Number(source[first-1].displayId)+1===Number(source[first].displayId))first--;const tail=source.slice(first);capModel.clear();mergeRecords(tail);}

  if(beforeId!==null||oldestCursor.value===null){oldestCursor.value=reply.nextBeforeId??(items.length?Math.min(...items.map((c:any)=>Number(c.order??c.seq??c.id))):beforeId);hasOlder.value=!!reply.hasMore;if(beforeId===null&&props.kind!=='net'&&!filterActive.value&&loaded.value.length)oldestCursor.value=Math.min(oldestCursor.value??Infinity,loaded.value[0].id);}
  archiveCount.value=reply.matched??archiveCount.value;cacheNote.value=reply.archiveError?'Host归档写入异常：'+reply.archiveError:cacheWarning();
  await cacheLogRows(cacheScope,reply.generation,items);if(beforeId!==null)await saveCachedPage(cacheScope,reply.generation,sig,reply);cacheCount.value=await cachedCount(cacheScope,reply.generation);
  if(target!==identity()||token!==request)return;if(filter.paused)freezeInputs();
  await nextTick();if(beforeId!==null&&anchor!=null){const index=allRows.value.findIndex(r=>r.id===anchor);if(index>=0&&el){suppressScroll=true;el.scrollTop=index*rowHeight.value+offset;scrollTop.value=el.scrollTop;await nextTick();suppressScroll=false;}}
  else if(wasFollowing||!positioned.value)await bottom();positioned.value=true;
 }catch(e){if(target!==identity()||token!==request)return;loadError.value=(e as Error).message;if(!allRows.value.length){const g=generation.value||await cachedGeneration(cacheScope);if(g){generation.value=g;const items=await readCachedRows(cacheScope,g,beforeId,capDisplayCap.value);if(target!==identity()||token!==request)return;mergeRecords(items,props.kind==='net');oldestCursor.value=items.length?Number(items[0].order??items[0].id):beforeId;hasOlder.value=items.length>0;cacheCount.value=await cachedCount(cacheScope,g);cacheNote.value='离线缓存；尚未确认Host最新清理状态。';if(filter.paused){frozenCaptures.value=[...loaded.value];frozenExchanges.value=[...exchanges.value];}await bottom();}}}
 finally{if(target===identity()&&token===request)pageLoading.value=false;}
}
async function loadExchanges(){if(props.kind==='net')await loadServerPage(null,true);}
let networkDebounce=0;function scheduleExchanges(){if(!active.value||filter.paused||modalOpen.value)return;if(networkDebounce)return;networkDebounce=window.setTimeout(()=>{networkDebounce=0;void loadExchanges();},250);}
async function prevPage(){if(canPrevPage.value&&oldestCursor.value!==null)await loadServerPage(oldestCursor.value);}
async function nextPage(){await jumpLatest();}
async function jumpLatest(){pauseCeiling.value=null;await loadServerPage(null,true);if(filter.paused){frozenCaptures.value=[...loaded.value];frozenExchanges.value=[...exchanges.value];}await bottom();}
function onScroll(e:Event){const el=e.target as HTMLElement;scrollTop.value=el.scrollTop;viewportHeight.value=el.clientHeight;followBottom.value=el.scrollHeight-el.clientHeight-el.scrollTop<48;if(followBottom.value)newCount.value=0;if(!suppressScroll&&positioned.value&&el.scrollTop<72&&canPrevPage.value)void prevPage();}
function resetLoaded(){request++;pageLoading.value=false;capModel.clear();netModel.clear();loaded.value=[];exchanges.value=[];oldestCursor.value=null;hasOlder.value=true;sel.value=null;selDetail.value=null;selExchange.value=null;followBottom.value=true;positioned.value=false;newCount.value=0;scrollTop.value=0;generation.value='';pauseCeiling.value=null;}
async function refreshFilter(){const ceiling=pauseCeiling.value;resetLoaded();pauseCeiling.value=ceiling;await loadServerPage(null,true);}
function setQuickMinutes(mins:number){fromMs.value=Date.now()-mins*60000;toMs.value=null;void refreshFilter();}function clearTimeRange(){fromMs.value=null;toMs.value=null;void refreshFilter();}function applyTimeRange(){void refreshFilter();}
function resetFilter(){filter.q='';filter.min=null;filter.max=null;filter.cat=-2;filter.kind='all';fromMs.value=null;toMs.value=null;void refreshFilter();}
function onPageCapChange(value:number){if(DISPLAY_CAPS.includes(value)){savePanelDisplay({...panelDisplay,limit:value});}}
async function selectRow(c:Cap){const target=identity(),g=generation.value,cacheScope=scope();sel.value=c.id;selExchange.value=null;selDetail.value={_loading:true};try{let d:any;try{d=await getCaptureDetail(c.id,store.chosenPkg);if(d.id!==c.id||d.deviceBinding?.serial!==cacheScope.serial||d.package!==cacheScope.package)throw new Error('详情归属不一致');void saveCachedDetail(cacheScope,g,c.id,d);}catch(e){d=await readCachedDetail(cacheScope,g,c.id);if(!d)throw e;}if(target===identity()&&g===generation.value&&sel.value===c.id)selDetail.value=d;}catch{if(target===identity()&&sel.value===c.id)selDetail.value={_error:'Host和浏览器均没有此记录的已保留详情',cap:c};}}
function selectExchange(ex:Exchange){sel.value=ex.id;selDetail.value=null;selExchange.value=ex;}
function closeDetail(){sel.value=null;selDetail.value=null;selExchange.value=null;}async function onCapDeleted(id:number){request++;pageLoading.value=false;const pending=removeCachedRow(scope(),generation.value,id);capRemoveWhere(c=>c.id===id);capModel.remove(id);loaded.value=[...capModel.items];if(frozenCaptures.value)frozenCaptures.value=frozenCaptures.value.filter(c=>c.id!==id);closeDetail();await pending;}
const exportBusy=ref(false);
async function downloadView(){if(exportBusy.value)return;const target=identity(),g=generation.value,cacheScope=scope(),items=JSON.parse(JSON.stringify(allRows.value));if(!items.length){toast('没有可导出的记录');return;}if(!confirm('导出可能包含密钥、明文或网络内容；只包含当前筛选后已加载的记录。继续？'))return;exportBusy.value=true;const check=()=>{if(target!==identity()||g!==generation.value)throw new Error('设备、应用或清理代次改变，导出取消');};try{let data:any;if(props.kind==='net')data={schema:'adh.exchange-export/1',serial:cacheScope.serial,package:cacheScope.package,generation:g,mode:'loaded-reassembled-exchanges',records:items};else data=await createCaptureExport({...cacheScope,ids:items.map(r=>Number(r.id))},async id=>{try{return await getCaptureDetail(id,cacheScope.package,cacheScope.serial);}catch(e){const cached=await readCachedDetail(cacheScope,g,id);if(!cached)throw e;return cached;}},check,{maxRecords:items.length});check();downloadBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),`adh-${props.kind}-loaded-${Date.now()}.json`);toast('已发起导出 '+items.length+' 条');}catch(e){toast('未导出：'+(e as Error).message);}finally{exportBusy.value=false;}}
async function applyClear(data:any){if(data.serial&&data.serial!==scope().serial||data.package&&data.package!==store.chosenPkg||data.kind&&data.kind!==props.kind)return;if(data.generation&&data.generation===generation.value)return;const g=data.generation||'';resetLoaded();generation.value=g;if(g)await clearCachedScope(scope(),g);frozenCaptures.value=[];frozenExchanges.value=[];cacheCount.value=0;archiveCount.value=0;}
async function clearView(){if(!store.chosenPkg||!confirm('清空当前设备、当前APP的本板块日志及其浏览器缓存？\n显示序号将从1重新开始，内部唯一ID不复用；其它设备、APP和板块不受影响。'))return;const target=identity();try{const r=await clearCaptureBoard(store.chosenPkg,props.kind);if(target!==identity())return;await applyClear({...r,...scope(),what:'captures'});await loadServerPage(null,true);toast('已清空本板块，显示序号从1重新计数');}catch(e){toast('未确认清理：'+(e as Error).message);}}
const MORE_OPTS=computed(()=>[{label:'导出',key:'export',disabled:exportBusy.value},{label:'清空',key:'clear',disabled:exportBusy.value}]);
function onMoreSelect(key:string){if(key==='export')void downloadView();else if(key==='clear'&&!exportBusy.value)void clearView();}
function openNetworkHooks(){const serial=scope().serial;if(!serial||!store.chosenPkg)return;store.hookSource={serial,package:store.chosenPkg,feature:'tls',session:'',returnView:'nt'};store.view='settings';}
function startDrag(e:MouseEvent){e.preventDefault();const ws=(e.target as HTMLElement).parentElement!,rect=ws.getBoundingClientRect();const move=(ev:MouseEvent)=>{dragging.value=true;listWidth.value=Math.max(220,Math.min(rect.width*.7,rect.width-260,ev.clientX-rect.left));};const up=()=>{document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',up);dragging.value=false;};document.addEventListener('mousemove',move);document.addEventListener('mouseup',up);}
function cryptoRow(c:Cap){return{...cryptoView(c),cc:catClass(c)};}
function freezeInputs(){if(pauseCeiling.value===null)pauseCeiling.value=props.kind==='net'?exchanges.value.reduce((n,e)=>Math.max(n,...(e.captureIds??[Number(e.order??e.seq??0)])),0):loaded.value.reduce((n,c)=>Math.max(n,c.id),0);frozenCaptures.value=JSON.parse(JSON.stringify(loaded.value.filter(c=>c.id<=pauseCeiling.value!)));frozenExchanges.value=JSON.parse(JSON.stringify(exchanges.value.filter(e=>Number(e.order??e.seq??0)<=pauseCeiling.value!)));}
watch(()=>filter.paused,p=>{refreshPreference(scope(),!p);if(p){if(loaded.value.length||exchanges.value.length||generation.value)freezeInputs();else{pauseCeiling.value=null;frozenCaptures.value=[];frozenExchanges.value=[];}}else{pauseCeiling.value=null;frozenCaptures.value=null;frozenExchanges.value=null;}if(!p){void loadServerPage(null,true);if(followBottom.value)void bottom();}},{flush:'sync'});
watch(()=>store.capItems.filter(c=>belongsToApp(c)&&matchesPanel(c)).map(c=>c.id).join(','),()=>{const items=store.capItems;if(props.kind==='net'){scheduleExchanges();return;}if(modalOpen.value||!active.value)return;const incoming=items.filter(c=>belongsToApp(c)&&matchesPanel(c)&&(!generation.value||!c.captureGeneration||c.captureGeneration===generation.value));if(!generation.value&&incoming[0]?.captureGeneration)generation.value=String(incoming[0].captureGeneration);const added=mergeRecords(incoming);if(!filterActive.value&&capModel.items.length&&oldestCursor.value!==null){const items=capModel.items;let first=items.length-1;while(first>0&&Number(items[first-1].displayId)+1===Number(items[first].displayId))first--;if(first>0){oldestCursor.value=Number(items[first].id);hasOlder.value=true;}else oldestCursor.value=Math.min(oldestCursor.value,Number(items[0].id));}if(added){if(filter.paused||!followBottom.value)newCount.value+=added;else void bottom();}},{immediate:true});
let debounce:ReturnType<typeof setTimeout>|undefined;watch([()=>filter.q,()=>filter.kind],()=>{clearTimeout(debounce);debounce=setTimeout(()=>void refreshFilter(),250);});
watch([()=>store.selectedDeviceKey,()=>store.chosenPkg,()=>props.kind],()=>{resetLoaded();filter.paused=!refreshPreference(scope());filter.q='';filter.kind='all';filter.cat=-2;filter.min=null;filter.max=null;fromMs.value=null;toMs.value=null;if(active.value)void loadServerPage(null,true);});
const clearListener=(e:Event)=>{void applyClear((e as CustomEvent).detail);};
function startPolling(){if(poll)return;poll=window.setInterval(()=>{if(active.value&&!filter.paused&&!modalOpen.value&&store.wsState!=='live')void loadServerPage(null,true);cacheNote.value=cacheWarning()||cacheNote.value;},3000);}function stopPolling(){if(poll)clearInterval(poll);poll=0;clearTimeout(networkDebounce);networkDebounce=0;}
onMounted(()=>{filter.paused=!refreshPreference(scope());window.addEventListener('adh:capture-clear',clearListener);startPolling();void loadServerPage(null,true);if(typeof ResizeObserver!=='undefined'){resize=new ResizeObserver(entries=>{viewportHeight.value=entries[0]?.contentRect.height||700;});const el=listElement();if(el)resize.observe(el);}});
onActivated(()=>{active.value=true;startPolling();if(!filter.paused||!loaded.value.length&&!exchanges.value.length)void loadServerPage(null,true);});onDeactivated(()=>{active.value=false;stopPolling();});onUnmounted(()=>{request++;stopPolling();resize?.disconnect();clearTimeout(debounce);window.removeEventListener('adh:capture-clear',clearListener);});


onScopeDispose(()=>{request++;clearTimeout(debounce);});
</script>

<template>
  <div class="cap-view">
    <h1 class="sr-only">{{ BOARD_LABEL[kind] }}</h1>
    <div class="filters">
      <div class="toolbar-main capture-list-head" role="group" aria-label="日志浏览工具栏">
        <n-input v-model:value="filter.q" size="small" clearable :placeholder="searchPlaceholder" class="toolbar-search-input"><template #prefix><n-icon :component="SearchOutline" /></template></n-input>
        <span class="log-summary" :title="footHint">{{ listFootLeft }}</span>
        <n-select :value="capDisplayCap" size="small" class="page-cap-select" aria-label="每批加载条数" :options="DISPLAY_CAPS.map(cap=>({label:cap+' 条/批',value:cap}))" @update:value="onPageCapChange" />
        <n-checkbox :checked="!filter.paused" aria-label="持续刷新列表" @update:checked="filter.paused=!$event">持续刷新</n-checkbox>
        <n-button size="small" :type="advCount?'primary':'default'" :aria-expanded="advOpen" @click="advOpen=true">筛选<template v-if="advCount"> · {{ advCount }}</template></n-button>
        <n-button size="small" @click="jumpLatest">最新</n-button>
        <n-dropdown trigger="click" :options="MORE_OPTS" @select="onMoreSelect"><n-button quaternary size="small" aria-label="记录列表操作">⋯</n-button></n-dropdown>
      </div>
      <span v-if="loadError||cacheNote" class="log-storage-note" role="status">{{ loadError||cacheNote }}</span>
    </div>

    <n-modal v-model:show="advOpen" preset="card" title="筛选" size="small" content-scrollable
      style="width:min(430px, calc(100vw - 28px))">
      <div class="filter-modal-body">
        <fieldset v-if="kind === 'system'" class="system-filter">
          <legend>活动类型</legend>
          <n-radio-group v-model:value="filter.kind" size="small">
            <n-radio-button v-for="[k, l] in SYS_KINDS" :key="k" :value="k">{{ l }}</n-radio-button>
          </n-radio-group>
        </fieldset>
        <label v-if="kind === 'crypto'" class="filter-field">分类
          <n-select v-model:value="filter.cat" size="small" class="cat-select" :options="[
              { label: '全部', value: -2 }, { label: '摘要', value: 0 }, { label: 'HMAC', value: 1 },
              { label: '对称', value: 2 }, { label: '非对称', value: 3 }, { label: 'AEAD', value: 4 },
            ]" />
        </label>
        <div class="size-filter">
          <label>输入大小</label>
          <n-input-number v-model:value="filter.min" size="small" :min="0" placeholder="0" class="size-num" />
          <span class="sep">—</span>
          <n-input-number v-model:value="filter.max" size="small" :min="0" placeholder="不限" class="size-num" />
          <span class="unit">B</span>
        </div>
        <fieldset class="time-filter">
          <legend>时间范围</legend>
          <div class="time-quick">
            <n-button size="tiny" @click="setQuickMinutes(1)">近 1 分钟</n-button>
            <n-button size="tiny" @click="setQuickMinutes(5)">近 5 分钟</n-button>
            <n-button size="tiny" @click="setQuickMinutes(30)">近 30 分钟</n-button>
            <n-button v-if="hasTimeRange" size="tiny" tertiary @click="clearTimeRange">清除</n-button>
          </div>
          <div class="time-inputs">
            <n-date-picker v-model:value="fromMs" type="datetime" size="small" clearable
              placeholder="开始时间" @update:value="applyTimeRange" />
            <span class="sep">至</span>
            <n-date-picker v-model:value="toMs" type="datetime" size="small" clearable
              placeholder="结束时间" @update:value="applyTimeRange" />
          </div>
        </fieldset>
      </div>
      <template #footer>
        <div class="filter-modal-footer">
          <n-button text size="small" type="primary" :disabled="!filterActive" @click="resetFilter">重置筛选</n-button>
          <n-button size="small" type="primary" @click="advOpen = false">完成</n-button>
        </div>
      </template>
    </n-modal>

    <div class="workspace capture-workspace" :class="{ 'compact-captures': panelDisplay.density === 'compact', 'detail-open': sel !== null, 'no-results': !listLoading && sel === null && !(kind === 'net' ? matchedExchanges.length : rows.length) }">
      <div class="list-pane" :style="listWidth ? { width: listWidth + 'px' } : undefined">
        <div class="new-banner" :class="{ show: newCount > 0 }">
          <span>{{ newCount }} 条新记录</span>
          <n-button text size="tiny" type="primary" @click="jumpLatest">跳到最新</n-button>
        </div>

        <div v-if="sel === null && (kind === 'net' ? matchedExchanges.length : rows.length)" class="ledger-head adh-grid" aria-hidden="true"><span>序号</span><span>{{ HEAD_LABELS[kind][0] }}</span><span>{{ HEAD_LABELS[kind][1] }}</span><span>{{ HEAD_LABELS[kind][2] }}</span><span>时间</span></div>
        <div class="cap-list virtualized" :style="{'--timeline-row-height':rowHeight+'px'}" :class="{ loading: listLoading }" :id="LIST_ID[kind]" tabindex="0" :aria-busy="listLoading" @scroll="onScroll">
          <div class="timeline-spacer" :style="{height:windowed.top+'px'}" aria-hidden="true"></div>
          <template v-if="kind === 'net'">
            <div v-for="ex in renderedExchanges" :key="ex.id" class="row cat-net" :class="{ selected: sel === ex.id }"
              role="button" tabindex="0" @keydown.enter.prevent="selectExchange(ex)" @keydown.space.prevent="selectExchange(ex)" @click="selectExchange(ex)">
              <div class="top">
                <span class="seq">#{{ ex.displayId??ex.seq??'—' }}</span>
                <span class="pill net">网络</span>
                <span class="algo">{{ ex.label }}</span>
                <span v-if="ex.status" class="op">{{ ex.status }}</span>
                <span class="ts">{{ fmtTime(ex.ts) }}</span>
              </div>
              <div class="lens">{{ exchangeInputPreview(ex) }}</div>
            </div>
            <div v-if="!matchedExchanges.length && !listLoading" class="empty-row" role="status"><p>{{ emptyText }}</p><template v-if="store.chosenPkg"><div class="network-empty-actions" role="group" aria-label="网络记录后续操作"><n-button text type="primary" @click="openNetworkHooks">查看 TLS Hook 配置</n-button><n-button text @click="advOpen=true">检查显示筛选</n-button></div><p class="muted">配置不代表进程已启用。确认后在目标应用触发请求；自定义网络栈可能不受当前 Hook 覆盖。</p></template></div>
          </template>

          <template v-else>
            <div v-for="c in renderedRows" :key="c.id" class="row"
              :class="[`cat-${catClass(c)}`, { selected: sel === c.id, 'crypto-row': c.category === 'crypto' }]"
              role="button" tabindex="0" @keydown.enter.prevent="selectRow(c)" @keydown.space.prevent="selectRow(c)" @click="selectRow(c)">
              <template v-if="c.category === 'crypto'">
                <div class="top">
                  <span class="seq">#{{ c.displayId??c.id }}</span>
                  <span class="algo">{{ cryptoRow(c).title }}</span>
                  <span v-if="cryptoRow(c).direction" class="op">{{ cryptoRow(c).direction }}</span>
                  <span v-if="cryptoRow(c).sizeLabel" class="sizes">{{ cryptoRow(c).sizeLabel }}</span>
                  <span v-if="cryptoRow(c).hasKey" class="mark">有密钥</span>
                  <span class="ts">{{ fmtTime(c.ts) }}</span>
                </div>
                <div class="subline">
                  <span class="preview" :class="{'preview-absent':!cryptoRow(c).preview}">{{ cryptoRow(c).preview || capturePreviewPlaceholder(c) }}</span>
                  <span v-if="cryptoRow(c).hook" class="hook">{{ cryptoRow(c).hook }}</span>
                </div>
              </template>
              <template v-else>
                <div class="top">
                  <span class="seq">#{{ c.displayId??c.id }}</span>
                  <span class="pill" :class="catClass(c)">{{ CATLABEL[catClass(c)] }}</span>
                  <span class="algo" :title="systemRow(c).method">{{ systemRow(c).method }}</span>
                  <span class="op">{{ systemRow(c).result }}</span>
                  <span class="ts">{{ fmtTime(c.ts) }}</span>
                </div>
                <div class="lens" :title="rowLens(c)">{{ rowLens(c) }}</div>
                <div v-if="c.preview && c.category !== 'net' && c.category !== 'file' && c.category !== 'system'"
                  class="preview">{{ c.preview }}</div>
              </template>
            </div>
            <p v-if="!rows.length && !listLoading" class="empty-row" role="status">{{ emptyText }}</p>
          </template>
          <div class="timeline-spacer" :style="{height:windowed.bottom+'px'}" aria-hidden="true"></div>
        </div>

      </div>

      <div class="splitter" :class="{ dragging }" @mousedown="startDrag"></div>

      <section class="capture-detail-shell">
        <div class="capture-detail-nav">
          <n-button quaternary size="small" @click="closeDetail">‹ 返回列表</n-button>
        </div>
        <div class="detail-pane">
          <ExchangeDetail v-if="selExchange" :ex="selExchange" />
          <CapDetail v-else-if="selDetail" :detail="selDetail" @deleted="onCapDeleted" />
          <div v-else class="detail-empty detail-placeholder">
            选择一条记录查看详情
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.cap-list { outline: none; }
.cap-empty { padding: 48px 16px; }
/* 加载中不铺骨架：列表为空时只把光标切成加载态，数据来了直接出现，不再有骨架→内容的跳动。 */
.cap-list.loading, .cap-list.loading .row { cursor: progress; }
.detail-placeholder { min-height: 62vh; display: grid; place-items: center; padding: 0; }
.ph-title { font-size: 15px; font-weight: 600; color: var(--ink-2); }
.ph-desc { margin-top: 6px; font-size: 12.5px; color: var(--muted); }
.toolbar-search-input { flex: 1; min-width: 160px; }
.search-ico { font-size: 14px; opacity: 0.55; }
.pager-controls {
  display: flex;
  align-items: center;
  gap: 6px;
}
.page-cap-select { width: 96px; }
.filter-modal-body { display: grid; gap: 12px; }
.filter-modal-footer { width: 100%; display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.cat-select { width: 110px; }
.size-num { width: 88px; }
.time-filter {
  border: 0;
  padding: 0;
  margin: 10px 0 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.time-filter legend {
  font-size: 12px;
  opacity: 0.78;
  margin-bottom: 2px;
}
.time-quick {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.time-inputs {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.time-inputs :deep(.n-date-picker) { flex: 1; min-width: 150px; }
.time-banner {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.network-empty-actions { display:flex; flex-wrap:wrap; align-items:center; justify-content:center; gap:12px; }
</style>

import {getCaptureControls,writeCaptureControls,type CaptureControlsView} from './api';
import {BOARD_FEATURES,type CaptureBoard} from '../../daemon/src/capture_boards';
interface BoardTarget{serial:string;package:string;kind:CaptureBoard;sessions:string[]}
interface Dependencies{read:typeof getCaptureControls;write:typeof writeCaptureControls}
/** Freeze the whole selected APP's online process set. Never guess or replay a new process. */
export async function setBoardCapture(target:BoardTarget,enabled:boolean,deps:Dependencies={read:getCaptureControls,write:writeCaptureControls}){
 const t={...target,sessions:[...new Set(target.sessions)]};if(!t.serial||!t.package||!t.sessions.length)throw Error('请先连接当前 APP');
 const views=await Promise.all(t.sessions.map(id=>deps.read(t.serial,t.package,id)));
 const validate=(v:CaptureControlsView,id:string)=>{if(v.serial!==t.serial||v.package!==t.package||v.session!==id||!v.runtime)throw Error('应用进程已改变，未继续');if(v.foreignOwner)throw Error('当前 APP 有进程由其他 Hook 计划控制');if(v.lastIntent?.state==='unknown'||(v.control as any)?.uncertainOperations?.length)throw Error('上次操作结果未确认，请先核查');const methods=v.catalogs?.methods??[];for(const f of Object.values(v.config.features)as any[])for(const mid of f.methods)if(!methods.some((m:any)=>m.id===mid))throw Error('当前 APP 的方法目录不完整，请先在设置中读取并核对');};
 views.forEach((v,i)=>validate(v,t.sessions[i]));let revision=views[0].revision;if(views.some(v=>v.revision!==revision))throw Error('采集配置正在变化，请刷新后操作');
 if(enabled&&!BOARD_FEATURES[t.kind].some(k=>views[0].config.features[k].enabled&&views[0].config.features[k].methods.length))throw Error('请先在设置中选择本板块需要的 Hook');
 const applied:string[]=[];for(let i=0;i<t.sessions.length;i++){const v=i===0?views[i]:await deps.read(t.serial,t.package,t.sessions[i]);validate(v,t.sessions[i]);if(v.revision!==revision)throw Error('配置已被其他操作修改，未继续覆盖');const result=await deps.write(v,'board',{kind:t.kind,enabled},true);if(result?.ok!==true)throw Error(result?.error||'采集状态未确认；没有自动重试');revision=result.revision;applied.push(t.sessions[i]);}
 return {ok:true,applied,revision};
}

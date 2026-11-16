((scope) => {
  const M=scope.AdhWorkbenchModel;
  const element=(tag,text,className)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(className)node.className=className;return node;};
  const button=(text,fn,className)=>{const node=element('button',text,className);node.type='button';node.onclick=fn;return node;};
  const badge=state=>{const node=element('span',M.states[state]||state,'aw-state');node.dataset.state=state;node.title=state;return node;};
  const json=value=>JSON.stringify(value,null,2);
  function download(value,name){const url=URL.createObjectURL(new Blob([json(value)],{type:'application/json;charset=utf-8'}));const link=element('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function mount(root,client,options={}) {
    root.classList.add('adh-workbench');
    root.innerHTML=`<header class="aw-header"><div><div class="aw-brand">ADH / HUMAN CONSOLE</div><h1>任务工作台</h1><p>AI 自主分析 · 人类观察、修改与接管</p></div><div class="aw-row"><span id="awRole" class="aw-state"></span><button id="awClose">返回分析现场</button></div></header>
      <details class="aw-auth" id="awAuth"><summary>操作员连接 · 凭据仅保留在当前页面内存</summary><form id="awAuthForm"><div class="aw-row"><input id="awKey" type="password" autocomplete="off" aria-label="操作员访问密钥" placeholder="操作员访问密钥"><button type="submit" class="aw-primary">连接操作员</button><button type="button" id="awDisconnect">断开操作员</button></div></form><p>查看任务无需接管。只有明确修改、暂停或切换控制权时才使用操作员权限。</p></details>
      <nav class="aw-tabs" aria-label="工作台视图"><button id="awTasksTab" aria-pressed="true">任务与结果</button><button id="awConfigTab" aria-pressed="false">配置编辑</button><label class="aw-check"><input id="awAuto" type="checkbox" checked>自动刷新（5 秒）</label><button id="awRefresh">刷新状态</button></nav>
      <section id="awNotice" class="aw-notice" role="alert" hidden><h3 id="awNoticeTitle"></h3><p id="awNoticeText"></p><code id="awNoticeCode"></code><div id="awNoticeActions" class="aw-row"></div><button id="awNoticeDismiss">关闭提示</button></section>
      <section class="aw-control" aria-label="控制权"><div class="aw-row"><label for="awScope">控制范围</label><select id="awScope"><option value="host">整个 Host</option></select><button id="awTake" data-mutate>接管此范围</button><button id="awRelease" data-mutate>交还 AI</button></div><p id="awControlText" class="aw-version">正在读取控制状态…</p><div id="awUncertain" class="aw-unknown" hidden><p>写入已隔离：存在执行结果未知的操作。先查看副作用与晚到结果，再核对目标实际状态。</p><div class="aw-row"><button id="awUnknownDetail">查看未知操作</button><label class="aw-check"><input id="awAck" type="checkbox">我已核对实际状态</label><button id="awResolve" data-mutate>确认核对并解除隔离</button></div><p class="aw-spaced">解除隔离不代表目标已停止，也不会回滚已执行步骤。</p></div></section>
      <section id="awTasksView" class="aw-task-grid"><aside class="aw-task-nav" aria-label="任务列表"><div class="aw-search"><input id="awSearch" type="search" aria-label="搜索全部任务" placeholder="搜索任务名称或 ID"><div class="aw-row"><select id="awState" aria-label="按任务状态筛选"><option value="">全部状态</option><option value="active">分析中</option><option value="paused">已暂停</option><option value="unknown">结果未知</option><option value="cancel_requested">已请求取消</option><option value="completed">已完成</option><option value="cancelled">已取消</option></select><select id="awOwner" aria-label="按负责人筛选"><option value="">全部负责人</option><option value="ai">AI</option><option value="operator">人类</option></select></div></div><p id="awTaskCount" class="aw-muted aw-spaced">正在读取任务…</p><div id="awTaskList" class="aw-task-list" aria-live="polite"></div><div class="aw-row"><button id="awTaskPrev">上一页任务</button><button id="awTaskNext">下一页任务</button></div></aside>
      <section class="aw-detail"><div id="awTaskHead" class="aw-empty"><strong>选择一项任务</strong>AI 提交的任务会显示在左侧。查看任务不会暂停分析，也不会改变控制权。</div><section id="awOperationsSection" class="aw-detail-section" hidden><div class="aw-row aw-between"><h3>执行记录</h3><span id="awOperationCount" class="aw-muted"></span></div><div class="aw-table-wrap"><table class="aw-table"><thead><tr><th>操作</th><th>状态</th><th>来源</th><th>创建时间</th><th>详情</th></tr></thead><tbody id="awOperationRows"></tbody></table></div><div class="aw-row aw-spaced"><button id="awOpPrev">上一页操作</button><button id="awOpNext">下一页操作</button></div></section><article id="awOperationDetail" class="aw-detail-section" hidden></article></section></section>
      <section id="awConfigView" class="aw-config" hidden><div class="aw-content"><div class="aw-row aw-between"><h2>Host 全局配置</h2><div class="aw-row"><button id="awConfigRead">读取配置并核对</button><button id="awExport">导出已读配置</button><button id="awImportButton">导入为草稿</button><input id="awImport" type="file" accept="application/json,.json" hidden></div></div><p class="aw-muted aw-spaced">修改先保留在本页草稿。提交会接管整个 Host；完成后可显式交还 AI。保留策略只修改配置，不自动删除历史数据。</p><p id="awConfigVersion" class="aw-version aw-spaced">尚未读取配置</p><div id="awConfigCompare" class="aw-config-compare" hidden></div><form id="awConfigForm" class="aw-config-form"></form><section class="aw-detail-section"><h3>待提交的修改</h3><p id="awDraftHint" class="aw-muted aw-spaced"></p><pre id="awPatch">{}</pre></section><div class="aw-config-save"><div class="aw-row"><button id="awSave" class="aw-primary" data-mutate>提交配置修改</button><span id="awSaveStatus" role="status" class="aw-muted"></span><button id="awLegacy" hidden>数据维护与历史设置</button></div></div></div></section>`;
    const $=id=>root.querySelector('#'+id),s={view:'tasks',visible:true,busy:false,listOffset:0,opOffset:0,taskId:null,task:null,opId:null,op:null,resultLoaded:false,resultSignature:'',draft:null,conflict:null,pending:null,intent:null,control:null,listGeneration:0,detailGeneration:0,operationGeneration:0};
    let timer,pendingTimer,searchTimer,controlGeneration=0,lastOpRender='',lastTaskRender='',lastListRender='',lastRowsRender='';
    const notice=(title,text,code='',tone='error',actions=[])=>{$('awNotice').hidden=false;$('awNotice').dataset.tone=tone;$('awNoticeTitle').textContent=title;$('awNoticeText').textContent=text;$('awNoticeCode').textContent=code;$('awNoticeCode').hidden=!code;$('awNoticeActions').replaceChildren(...actions);};
    function report(error){const messages={STALE_TASK:'任务状态已被其他操作更新。请刷新并核对后再操作；没有重发旧指令。',STALE_CONTROL:'状态版本或控制权已变化。请核对最新状态后重新决定；没有重发旧指令。',OPERATION_RUNNING:'Host 仍在等待已派发步骤，暂不能解除隔离。请等待处理结束并核对目标实际状态。',CONTROL_HELD:'当前范围由人类持有，AI 写入保持暂停。',UNKNOWN_EXECUTION:'存在未确认的执行结果，先检查副作用与目标实际状态。'};notice(error.code==='STALE_TASK'?'任务版本冲突':error.code==='STALE_CONTROL'?'控制版本冲突':error.transport?'请求结果未确认':'操作未完成',messages[error.code]||error.message,error.code);}
    async function work(fn){if(s.busy)return;s.busy=true;permissions();try{await fn();}catch(error){report(error);}finally{s.busy=false;permissions();}}
    function permissions(){
      $('awRole').textContent=client.operator?'操作员已连接':'观察模式';$('awRole').dataset.state=client.operator?'paused':'active';
      for(const node of root.querySelectorAll('[data-mutate]'))node.disabled=s.busy||!client.operator;
      for(const node of root.querySelectorAll('[data-navigate]'))node.disabled=s.busy;
      for(const id of ['awTasksTab','awConfigTab','awRefresh'])$(id).disabled=s.busy;
      $('awScope').disabled=s.busy;
      const editingBlocked=s.busy||!!s.pending||!!s.intent||!!s.checkingPending;
      for(const node of $('awConfigForm').querySelectorAll('input,textarea'))node.disabled=editingBlocked;
      $('awImport').disabled=editingBlocked;$('awImportButton').disabled=editingBlocked;$('awConfigRead').disabled=editingBlocked;
      $('awDisconnect').disabled=!client.operator;
      $('awTake').disabled ||= !s.control||s.control.owner==='operator';
      $('awRelease').disabled ||= !s.control||s.control.owner!=='operator'||!!s.control.uncertain;
      $('awResolve').disabled ||= !s.control?.uncertain||!$('awAck').checked;
      let dirty=false;try{dirty=!!s.draft&&!!Object.keys(s.draft.patch()).length;}catch{}
      $('awSave').disabled ||= !dirty||!!s.conflict||!!s.pending||!!s.intent||!!s.checkingPending;
    }
    client.subscribe(permissions);
    $('awAuthForm').onsubmit=event=>{event.preventDefault();work(async()=>{const key=$('awKey').value;$('awKey').value='';await client.connect(key);$('awAuth').open=false;notice('操作员已连接','尚未接管任何范围。AI 仍按现有控制状态继续分析。','','success');await refresh();});};
    $('awDisconnect').onclick=()=>{client.disconnect();notice('已断开操作员','页面已清除凭据。既有控制权不会自动释放，请在离开前按需交还 AI。','','success');};
    $('awNoticeDismiss').onclick=()=>{$('awNotice').hidden=true;};
    $('awClose').onclick=()=>options.close?options.close():location.assign('/');
    function view(name){s.view=name;$('awTasksView').hidden=name!=='tasks';$('awConfigView').hidden=name!=='configuration';$('awTasksTab').setAttribute('aria-pressed',String(name==='tasks'));$('awConfigTab').setAttribute('aria-pressed',String(name==='configuration'));if(name==='configuration'&&!s.draft)work(loadConfiguration);}
    $('awTasksTab').onclick=()=>view('tasks');$('awConfigTab').onclick=()=>view('configuration');
    const filters=()=>({q:$('awSearch').value,state:$('awState').value,owner:$('awOwner').value});
    function filter(){s.listOffset=0;refreshList().catch(report);}
    $('awSearch').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(filter,250);};$('awState').onchange=filter;$('awOwner').onchange=filter;
    $('awTaskPrev').onclick=()=>{s.listOffset=Math.max(0,s.listOffset-25);refreshList().catch(report);};$('awTaskNext').onclick=()=>{s.listOffset+=25;refreshList().catch(report);};
    $('awOpPrev').onclick=()=>{s.opOffset=Math.max(0,s.opOffset-25);refreshTask().catch(report);};$('awOpNext').onclick=()=>{s.opOffset+=25;refreshTask().catch(report);};
    $('awRefresh').onclick=()=>work(refresh);$('awScope').onchange=()=>work(async()=>{$('awAck').checked=false;await refreshControl();});$('awAck').onchange=permissions;
    async function refreshControl(){const resource=$('awScope').value,generation=++controlGeneration;
      if(s.control?.resource!==resource){s.control=null;$('awControlText').textContent='正在读取所选范围的控制状态…';$('awUncertain').hidden=true;permissions();}
      const value=await client.management({action:'snapshot',resource});if(resource!==$('awScope').value||generation!==controlGeneration)return;s.control=value;
      $('awControlText').textContent=`${value.owner==='operator'?'人类持有控制':'AI 拥有控制'}${value.uncertain?' · 写入已隔离':''} · 状态版本 ${value.revision} · 控制代次 ${value.epoch} · Host 代次 ${value.hostEpoch}`;
      $('awUncertain').hidden=!value.uncertain;permissions();}
    async function control(action){const observed=s.control;if(!observed)throw Error('请先读取控制状态');await client.controlAction(observed,action,$('awAck').checked);$('awAck').checked=false;notice(action==='release'?'已交还 AI':action==='resolve'?'已记录人工核对':'已接管所选范围',action==='release'?'已失效的旧指令不会自动重放。被人工暂停的任务仍需单独恢复。':action==='resolve'?'原 unknown 记录仍保留；这不证明目标命令已停止。':'旧 AI 写入已受版本约束；查询仍可继续。','','success');await refresh();}
    $('awTake').onclick=()=>work(()=>control('takeover'));$('awRelease').onclick=()=>work(()=>control('release'));$('awResolve').onclick=()=>work(()=>control('resolve'));
    $('awUnknownDetail').onclick=()=>work(()=>goOperation(s.control.uncertain));
    function addScope(resource,label){if(![...$('awScope').options].some(o=>o.value===resource))$('awScope').add(new Option(label||resource,resource));}
    async function refreshAgents(){const {value}=await client.request('/api/agents');for(const a of value.filter(a=>a.online))addScope(`target:${a.sessionId}:${a.pid}:${a.uid}:${a.starttimeTicks||'legacy'}`,`${a.process||a.package} · PID ${a.pid}`);}
    async function refreshList(){const generation=++s.listGeneration;const value=await client.management({action:'list',limit:25,offset:s.listOffset,...filters()});if(generation!==s.listGeneration)return;
      $('awTaskCount').textContent=`${value.totalTasks} 项任务 · 第 ${Math.floor(s.listOffset/25)+1} 页`;$('awTaskPrev').disabled=s.listOffset===0;$('awTaskNext').disabled=value.nextTaskOffset===null;
      const signature=json(value.tasks)+'|'+s.taskId;if(signature===lastListRender)return;lastListRender=signature;
      const rows=value.tasks.map(task=>{const node=button('',()=>work(()=>selectTask(task.id)));node.dataset.navigate='';node.setAttribute('aria-current',String(task.id===s.taskId));node.append(element('span',task.title,'aw-task-title'));const meta=element('span',undefined,'aw-task-meta');meta.append(badge(task.state),element('span',(task.owner==='ai'?'AI':'人类')+` · v${task.revision??0}`));if(task.heldByOperator)meta.append(element('span','人类暂停'));node.append(meta);node.title=task.id;return node;});
      if(!rows.length)rows.push(element('p',value.totalTasks?'当前页没有任务':'没有匹配任务。AI 提交任务后会在此显示。','aw-empty'));
      $('awTaskList').replaceChildren(...rows);permissions();
    }
    async function selectTask(id){s.taskId=id;s.task=null;s.opId=null;s.op=null;s.opOffset=0;s.resultLoaded=false;lastOpRender='';lastTaskRender='';$('awOperationDetail').hidden=true;await refreshTask();await refreshList();}
    async function taskAction(action){const observed=s.task;await client.taskAction(observed,action);notice(action==='pause'?'任务已暂停':action==='resume'?'任务已恢复':'已请求取消任务',action==='pause'?'后续副作用会在检查点停止。已派发的目标命令不会被撤回。':action==='resume'?'恢复任务不会释放控制权，也不会重放已失效的操作。':'请检查每条操作的实际状态；取消请求不等于目标已经停止。','','success');await refresh();}
    async function refreshTask(){if(!s.taskId)return;const id=s.taskId,generation=++s.detailGeneration;const value=await client.management({action:'get',taskId:id,limit:25,offset:s.opOffset});if(id!==s.taskId||generation!==s.detailGeneration)return;
      if(!Number.isSafeInteger(value.task?.revision)||!Array.isArray(value.task?.resources))throw new scope.AdhClientError('任务工作台需要配套 P2 Host，不能只更新静态页面。','TASK_VERSION_REQUIRED');s.task=value.task;
      for(const resource of value.task.resources)addScope(resource);
      const signature=json(value.task);if(signature!==lastTaskRender){lastTaskRender=signature;const head=element('div',undefined,'aw-task-heading');head.append(element('h2',value.task.title),element('div',value.task.id,'aw-mono'));
        const row=element('div',undefined,'aw-row');row.append(badge(value.task.state),element('span',`任务版本 ${value.task.revision} · ${value.task.owner==='ai'?'AI':'人类'}负责`,'aw-muted'));if(value.task.heldByOperator)row.append(element('span','人类暂停，AI 不能自行恢复','aw-state'));head.append(row);
        head.append(element('p',`创建 ${M.time(value.task.createdAt)} · 更新 ${M.time(value.task.updatedAt)} · ${value.task.totalOperations} 条操作`,'aw-muted'));
        const actions=element('div',undefined,'aw-row');for(const [action,label]of [['pause','暂停任务'],['resume','恢复任务'],['cancel','取消整项任务']]){
          if(action==='pause'&&value.task.state!=='active'||action==='resume'&&value.task.state!=='paused'||action==='cancel'&&['completed','cancelled'].includes(value.task.state))continue;
          const node=button(label,()=>work(()=>taskAction(action)),action==='cancel'?'aw-danger':'');node.dataset.mutate='';actions.append(node);
        }head.append(actions);if(value.task.unresolved)head.append(element('p',`${value.task.unresolved} 条操作结果未知；先核对对应范围，不能用取消掩盖未知状态。`,'aw-muted'));
        $('awTaskHead').className='';$('awTaskHead').replaceChildren(head);
      }
      $('awOperationsSection').hidden=false;$('awOperationCount').textContent=`${value.totalOperations} 条 · 第 ${Math.floor(s.opOffset/25)+1} 页`;$('awOpPrev').disabled=s.opOffset===0;$('awOpNext').disabled=value.nextOperationOffset===null;
      const rowsSignature=json(value.operations)+'|'+s.opId;
      if(rowsSignature!==lastRowsRender){lastRowsRender=rowsSignature;
      const rows=value.operations.map(op=>{const row=element('tr');row.dataset.operation=op.id;row.setAttribute('aria-selected',String(op.id===s.opId));const name=element('td');name.append(element('div',op.name),element('div',op.id.slice(0,8),'aw-mono'));const status=element('td');status.append(badge(op.state));if(op.cancelRequested)status.append(element('div','已请求取消','aw-muted'));const actions=element('td'),open=button('查看详情',()=>work(()=>selectOperation(op.id)));open.dataset.navigate='';actions.append(open);row.append(name,status,element('td',`${op.owner==='ai'?'AI':'人类'} · ${op.source}`),element('td',M.time(op.createdAt)),actions);return row;});
      if(!rows.length){const cell=element('td','任务尚无执行记录。');cell.colSpan=5;const row=element('tr');row.append(cell);rows.push(row);}$('awOperationRows').replaceChildren(...rows);}permissions();
      if(s.opId)await refreshOperation();
    }
    async function goOperation(id){const {operation}=await client.management({action:'get',id});view('tasks');if(s.taskId!==operation.taskId)await selectTask(operation.taskId);await selectOperation(id);}
    async function selectOperation(id){s.opId=id;for(const row of $('awOperationRows').querySelectorAll('[data-operation]'))row.setAttribute('aria-selected',String(row.dataset.operation===id));s.op=null;s.resultLoaded=false;s.resultSignature='';lastOpRender='';await refreshOperation();}
    async function refreshOperation(force=false){if(!s.opId)return;const id=s.opId,generation=++s.operationGeneration;let {operation}=await client.management({action:'get',id});if(id!==s.opId||generation!==s.operationGeneration)return;
      const signature=(operation.resultFile||'')+'|'+(operation.lateResultFile||'');
      if(s.resultLoaded&&(force||signature!==s.resultSignature)){({operation}=await client.management({action:'get',id,includeResult:true}));if(id!==s.opId||generation!==s.operationGeneration)return;s.resultSignature=signature;}
      else if(s.resultLoaded){operation.result=s.op?.result;operation.lateResult=s.op?.lateResult;}
      s.op=operation;const renderSignature=json(operation)+'|'+s.resultLoaded;if(renderSignature!==lastOpRender){lastOpRender=renderSignature;renderOperation();}
    }
    function facts(parent,pairs){const list=element('dl',undefined,'aw-facts');for(const [label,value]of pairs){const item=element('div');item.append(element('dt',label),element('dd',value));list.append(item);}parent.append(list);}
    function renderOperation(){const op=s.op,area=$('awOperationDetail');area.hidden=false;area.replaceChildren();const heading=element('div',undefined,'aw-row aw-between');heading.append(element('h2',op.name),badge(op.state));area.append(heading,element('p',op.id,'aw-mono aw-spaced'));
      if(op.state==='unknown'){const unknown=element('div',undefined,'aw-notice');unknown.append(element('h3',op.resolvedAt?'原执行结果未知，已人工核对':'执行结果未知，不能视为失败后安全重试'),element('p','目标可能已经执行。晚到结果不会把 unknown 自动改成成功；已派发步骤不会自动回滚。'));area.append(unknown);}
      if(op.cancelRequested)area.append(element('p',op.state==='succeeded'?'取消请求到达时操作已完成，保留实际成功结果。':'已请求取消；是否已执行、是否仍有命令在等待，请以以下事实为准。','aw-muted aw-spaced'));
      if(op.error)area.append(element('pre',op.error.code+': '+op.error.message));
      facts(area,[['所属任务',op.taskId],['调用来源',`${op.owner==='ai'?'AI':'人类'} · ${op.source} · ${op.actorId}`],['作用范围',op.resource],['效果分类',op.mode],['创建 / Host 开始',`${M.time(op.createdAt)} / ${M.time(op.startedAt)}`],['deadline / 终态记录',`${M.time(op.deadline)} / ${M.time(op.finishedAt)}`],['提交版本 / 应用版本',`${op.expectedRevision??'未要求'} / ${op.appliedRevision??'未记录'}`],['控制代次 / Host 代次',`${op.controlEpoch??'未要求'} / ${op.hostEpoch??'未要求'}`],['已派发受跟踪步骤',op.mayHaveExecuted?'是，可能已产生副作用':'没有派发记录'],['等待确认的步骤',String(op.inFlight??0)],['Host 处理是否结束',op.settled?'已结束':'尚未确认结束'],['部分步骤 / 人工核对',`${op.partialEffects?'部分步骤已派发':'无部分步骤标记'} / ${M.time(op.resolvedAt)}`],['幂等意图键',op.key]]);
      const actions=element('div',undefined,'aw-row');actions.append(button('查看此范围控制权',()=>work(async()=>{addScope(op.resource);$('awScope').value=op.resource;$('awAck').checked=false;await refreshControl();})));
      if(!M.terminal(op.state)){const cancel=button('请求取消此操作',()=>work(async()=>{client.requireOperator();await client.management({action:'cancel',id:op.id});notice('已提交取消请求','请检查实际执行状态。此操作的取消不会取消整个具名任务。','','success');await refresh();}),'aw-danger');cancel.dataset.mutate='';actions.append(cancel);}area.append(actions);
      const effects=element('section',undefined,'aw-detail-section');effects.append(element('h3','副作用记录'),element('p','这里只记录 Host 实际派发与确认的步骤，不推断目标最终状态，也不记录命令参数或密钥。','aw-muted aw-spaced'));
      if(op.effects===undefined)effects.append(element('p','旧记录没有逐步骤日志；以上聚合标记不能还原完整副作用。','aw-muted aw-spaced'));
      else if(!op.effects.length)effects.append(element('p','没有受跟踪的派发步骤。离线计算及未埋点的内部步骤不在此日志中。','aw-muted aw-spaced'));
      else {const list=element('ol',undefined,'aw-effect-list');for(const effect of op.effects){const row=element('li');const state={dispatched:'已派发，等待确认',acknowledged:'已收到响应',failed:'Host 步骤失败',unknown:'未确认执行结果'}[effect.state];row.append(element('div',`${effect.kind} / ${effect.action} · ${state}`),element('small',`${M.time(effect.startedAt)} → ${M.time(effect.completedAt)}${effect.uncertainAt?' · 曾有未知状态 '+M.time(effect.uncertainAt):''}${effect.session?' · '+effect.session:''}`));list.append(row);}effects.append(list);}
      if(op.effectsDropped)effects.append(element('p',`日志达到 64 条上限；另有 ${op.effectsDropped} 条派发步骤未逐条保存，不能把当前列表当成全部证据。`,'aw-muted aw-spaced'));area.append(effects);
      const results=element('section',undefined,'aw-detail-section');results.append(element('h3','已保存结果与晚到证据'));if(!s.resultLoaded)results.append(button('加载已保存结果',()=>work(async()=>{s.resultLoaded=true;await refreshOperation(true);}),'aw-spaced'));
      else {for(const [key,label]of [['result','原始结果'],['lateResult','晚到结果（不改变原终态）']]){const box=element('div',undefined,'aw-result-block');box.append(element('h3',label));if(op[key]===undefined)box.append(element('p','尚无已保存内容；不代表目标没有执行。'));else {const raw=json(op[key]);box.append(element('pre',raw.length>120000?raw.slice(0,120000)+'\n…界面预览已截断':raw));if(raw.length>120000)box.append(element('p','界面预览限制 120000 字符，下载可查看全部已保存内容。'));if(op[key]?.omitted)box.append(element('p','Host 只保存了结果摘要，下载文件也不包含被省略的原始数据。'));box.append(button('下载'+label,()=>download(op[key],`${op.id}-${key}.json`)));}results.append(box);}}
      area.append(results);permissions();
    }
    function buildFields(){const groups=new Map();for(const field of M.fields){if(!groups.has(field.group)){const fieldset=element('fieldset');fieldset.append(element('legend',field.group));const content=element('div',undefined,'aw-fields');fieldset.append(content);groups.set(field.group,{fieldset,content});}
        const label=element('label',undefined,'aw-field'+(field.type==='boolean'?' aw-toggle':'')),input=element(['symbols','packages'].includes(field.type)?'textarea':'input');input.dataset.path=field.path;input.id='awField-'+field.path;input.setAttribute('aria-label',field.label);
        if(input.tagName==='INPUT')input.type=field.type==='boolean'?'checkbox':field.type==='number'?'number':'text';if(field.type==='number'){input.min=field.min;input.max=field.max;input.step=1;}
        if(field.type==='boolean')label.append(input,element('span',field.label));else label.append(element('span',field.label),input);input.oninput=draftChanged;groups.get(field.group).content.append(label);
      }$('awConfigForm').replaceChildren(...[...groups.values()].map(g=>g.fieldset));$('awConfigForm').onsubmit=event=>event.preventDefault();}
    function fillFields(){if(!s.draft)return;for(const field of M.fields){const input=root.querySelector('[data-path="'+field.path+'"]'),value=M.get(s.draft.draft,field.path);if(field.type==='boolean')input.checked=!!value;else input.value=Array.isArray(value)?value.join('\n'):value??'';}patchPreview();}
    function draftChanged(){if(!s.draft)return;try{for(const field of M.fields){const input=root.querySelector('[data-path="'+field.path+'"]');let value=field.type==='boolean'?input.checked:field.type==='number'?(input.value===''?NaN:Number(input.value)):['symbols','packages'].includes(field.type)?input.value.split(/[\n,]/).map(v=>v.trim()).filter(Boolean):input.value.trim();M.set(s.draft.draft,field.path,value);}
        patchPreview();}catch(error){$('awDraftHint').textContent=error.message;$('awSave').disabled=true;}}
    function patchPreview(){try{const patch=s.draft.patch();$('awPatch').textContent=json(patch);$('awDraftHint').textContent=Object.keys(patch).length?'仅提交以上有变化的字段；其他配置保持当前值。':'草稿没有修改。';$('awConfigVersion').textContent=`草稿基于 Host 版本 ${s.draft.control.revision} · 控制代次 ${s.draft.control.epoch} · Host 代次 ${s.draft.control.hostEpoch}`;permissions();}catch(error){$('awDraftHint').textContent=error.message;$('awSave').disabled=true;}}
    async function loadConfiguration(){const snapshot=await client.config();if(!s.draft){s.draft=new M.Draft(snapshot);fillFields();}else showCompare(snapshot);}
    function showCompare(snapshot){s.conflict=snapshot;const box=$('awConfigCompare');box.hidden=false;box.replaceChildren(element('h3','核对最新配置与本地草稿'),element('p',`编辑版本 ${s.draft.control.revision}/${s.draft.control.epoch}/${s.draft.control.hostEpoch} → 当前版本 ${snapshot.control.revision}/${snapshot.control.epoch}/${snapshot.control.hostEpoch}。草稿尚未提交。`,'aw-muted aw-spaced'));
      const table=element('table',undefined,'aw-table'),head=element('tr');for(const label of ['字段','编辑时','当前值','草稿意图'])head.append(element('th',label));const thead=element('thead');thead.append(head);table.append(thead);const body=element('tbody');
      for(const row of s.draft.compare(snapshot)){const tr=element('tr');for(const value of [row.path,json(row.before),json(row.current),row.local?json(row.draft):'保持当前值'])tr.append(element('td',value));body.append(tr);}table.append(body);box.append(table);
      const actions=element('div',undefined,'aw-row aw-spaced');actions.append(button('保留修改，按最新版本重新核对',()=>{s.draft.rebase(snapshot);s.conflict=null;box.hidden=true;fillFields();notice('草稿已重新核对','只保留原本修改的字段，其余采用最新值。请检查待提交修改后再提交；此步骤没有执行写入。','','success');}),button('放弃草稿，载入最新配置',()=>{s.draft.reset(snapshot);s.conflict=null;box.hidden=true;fillFields();}));box.append(actions);permissions();
    }
    async function configConflict(error){report(error);try{showCompare(await client.config());}catch(latestError){report(latestError);}}
    async function saveConfiguration(){client.requireOperator();draftChanged();if(!$('awConfigForm').reportValidity())return;const patch=s.draft.patch();if(!Object.keys(patch).length)return;
      s.intent=client.intent();$('awSaveStatus').textContent='正在提交，尚未确认执行结果…';
      try{const value=await client.submitSettings(patch,s.draft.control,s.intent);s.pending=value.operation;s.intent=null;$('awSaveStatus').textContent='已接受提交，等待实际执行结果';notice('配置操作已进入任务队列','提交被接受不代表应用成功，请查看实际终态。','','success',[button('查看本次操作',()=>work(()=>goOperation(s.pending.id)))]);await checkPending();}
      catch(error){if(error.transport){const key=s.intent;notice('配置提交状态未确认','已保留草稿。请按意图键查询；未找到记录也不能证明一个尚未完成的请求不会执行。',key,'error',[button('按意图键查询',()=>work(async()=>{const value=await client.management({action:'get',idempotencyKey:key});s.pending=value.operation;s.intent=null;await checkPending();}))]);}
        else{s.intent=null;$('awSaveStatus').textContent='未提交成功，草稿已保留';if(['STALE_CONTROL','CONTROL_HELD','UNKNOWN_EXECUTION'].includes(error.code))await configConflict(error);else report(error);}}
    }
    async function checkPending(){if(!s.pending||s.checkingPending)return;s.checkingPending=true;try{const id=s.pending.id;const {operation}=await client.management({action:'get',id,includeResult:true});if(s.pending?.id!==id)return;s.pending=operation;$('awSaveStatus').textContent=`${M.states[operation.state]||operation.state} · ${id.slice(0,8)}`;
      if(M.terminal(operation.state)){s.pending=null;if(operation.state==='succeeded'){const current=await client.config();s.draft.reset(current);s.conflict=null;$('awConfigCompare').hidden=true;fillFields();notice('配置修改已确认完成','Host 已保存并返回应用结果。整个 Host 仍由人类持有控制，需要继续 AI 分析时显式交还。','','success',[button('查看保存与应用结果',()=>work(()=>goOperation(id)))]);await refreshControl();}
        else{notice(operation.state==='unknown'?'配置执行结果未知':'配置操作未全部完成','草稿仍保留。请查看操作结果与副作用，先核对实际配置；不要直接重发写入。',operation.error?.code||operation.state,'error',[button('查看本次操作',()=>work(()=>goOperation(id)))]);try{showCompare(await client.config());}catch(error){report(error);}}permissions();}
    }finally{s.checkingPending=false;permissions();}}
    $('awConfigRead').onclick=()=>work(loadConfiguration);$('awSave').onclick=()=>work(saveConfiguration);
    $('awExport').onclick=()=>{if(s.draft)download(s.draft.baseline,'adh-settings.json');else notice('尚未读取配置','先读取 Host 配置后导出。');};
    $('awImportButton').onclick=()=>$('awImport').click();
    $('awImport').onchange=event=>work(async()=>{const file=event.target.files[0];event.target.value='';if(!file)return;if(file.size>256*1024)throw Error('配置文件超过 256 KiB');if(!s.draft)await loadConfiguration();s.draft.import(JSON.parse(await file.text()));fillFields();notice('配置已导入草稿','尚未提交；请核对字段与版本。','','success');});
    if(options.legacySettings){$('awLegacy').hidden=false;$('awLegacy').onclick=options.legacySettings;}
    async function refresh(){await Promise.all([refreshList(),refreshControl(),refreshAgents()]);await refreshTask();await checkPending();}
    function start(){s.visible=true;if(timer)return;pendingTimer=setInterval(()=>{if(s.visible&&!document.hidden&&!s.busy&&s.pending)checkPending().catch(report);},1000);timer=setInterval(()=>{
      if(!s.visible||document.hidden||!$('awAuto').checked||s.busy||s.refreshing)return;
      if(root.contains(document.activeElement)&&document.activeElement?.matches('input,textarea,select'))return;
      s.refreshing=true;refresh().catch(report).finally(()=>s.refreshing=false);
    },5000);}
    buildFields();permissions();start();refresh().catch(report);
    if(options.standalone){const params=new URLSearchParams(location.search);if(params.get('operation'))work(()=>goOperation(params.get('operation')));else if(params.get('task'))work(()=>selectTask(params.get('task')));}
    return {open(name='tasks'){start();view(name);refresh().catch(report);},pause(){s.visible=false;clearInterval(timer);clearInterval(pendingTimer);timer=undefined;pendingTimer=undefined;},refresh};
  }
  scope.AdhWorkbench={mount};
})(globalThis);

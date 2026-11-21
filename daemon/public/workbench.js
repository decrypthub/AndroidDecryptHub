((scope) => {
  const M=scope.AdhWorkbenchModel;
  const element=(tag,text,className)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(className)node.className=className;return node;};
  const button=(text,fn,className)=>{const node=element('button',text,className);node.type='button';node.onclick=fn;return node;};
  const badge=state=>{const node=element('span',M.states[state]||state,'aw-state');node.dataset.state=state;node.title=state;return node;};
  const json=value=>JSON.stringify(value,null,2);
  function download(value,name){const url=URL.createObjectURL(new Blob([json(value)],{type:'application/json;charset=utf-8'}));const link=element('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function mount(root,client,options={}) {
    root.classList.add('adh-workbench');
    root.innerHTML=`<header class="aw-header"><div><h1>任务</h1></div><div class="aw-row"><button id="awClose">返回分析现场</button></div></header>
      <nav class="aw-tabs" aria-label="工作台视图"><label class="aw-check"><input id="awAuto" type="checkbox" checked>自动刷新（5 秒）</label><button id="awRefresh">刷新状态</button></nav>
      <section id="awNotice" class="aw-notice" role="alert" hidden><h3 id="awNoticeTitle"></h3><p id="awNoticeText"></p><code id="awNoticeCode"></code><div id="awNoticeActions" class="aw-row"></div><button id="awNoticeDismiss">关闭提示</button></section>
      <section id="awTasksView" class="aw-task-grid"><aside class="aw-task-nav" aria-label="任务列表"><div class="aw-search"><input id="awSearch" type="search" aria-label="搜索全部任务" placeholder="搜索任务名称或 ID"><div class="aw-row"><select id="awState" aria-label="按任务状态筛选"><option value="">全部状态</option><option value="active">分析中</option><option value="paused">已暂停</option><option value="unknown">结果未知</option><option value="cancel_requested">已请求取消</option><option value="completed">已完成</option><option value="cancelled">已取消</option></select><select id="awOwner" aria-label="按负责人筛选"><option value="">全部负责人</option><option value="ai">AI</option><option value="operator">人类</option></select></div></div><p id="awTaskCount" class="aw-muted aw-spaced">正在读取任务…</p><div id="awTaskList" class="aw-task-list" aria-live="polite"></div><div class="aw-row"><button id="awTaskPrev">上一页任务</button><button id="awTaskNext">下一页任务</button></div></aside>
      <section class="aw-detail"><div id="awTaskHead" class="aw-empty"><strong>选择一项任务</strong></div><section id="awOperationsSection" class="aw-detail-section" hidden><div class="aw-row aw-between"><h3>执行记录</h3><span id="awOperationCount" class="aw-muted"></span></div><div class="aw-table-wrap"><table class="aw-table"><thead><tr><th>操作</th><th>状态</th><th>来源</th><th>创建时间</th><th>详情</th></tr></thead><tbody id="awOperationRows"></tbody></table></div><div class="aw-row aw-spaced"><button id="awOpPrev">上一页操作</button><button id="awOpNext">下一页操作</button></div></section><article id="awOperationDetail" class="aw-detail-section" hidden></article></section></section>
    `;
    const $=id=>root.querySelector('#'+id),s={view:'tasks',visible:true,busy:false,listOffset:0,opOffset:0,taskId:null,task:null,opId:null,op:null,resultLoaded:false,resultSignature:'',draft:null,conflict:null,pending:null,intent:null,control:null,listGeneration:0,detailGeneration:0,operationGeneration:0};
    let timer,pendingTimer,searchTimer,lastOpRender='',lastTaskRender='',lastListRender='',lastRowsRender='';
    const notice=(title,text,code='',tone='error',actions=[])=>{$('awNotice').hidden=false;$('awNotice').dataset.tone=tone;$('awNoticeTitle').textContent=title;$('awNoticeText').textContent=text;$('awNoticeCode').textContent=code;$('awNoticeCode').hidden=!code;$('awNoticeActions').replaceChildren(...actions);};
    function report(error){const messages={STALE_TASK:'任务状态已被其他操作更新。请刷新并核对后再操作；没有重发旧指令。',STALE_CONTROL:'状态版本或控制权已变化。请核对最新状态后重新决定；没有重发旧指令。',OPERATION_RUNNING:'Host 仍在等待已派发步骤，暂不能解除隔离。请等待处理结束并核对目标实际状态。',CONTROL_HELD:'当前范围由人类持有，AI 写入保持暂停。',UNKNOWN_EXECUTION:'存在未确认的执行结果，先检查副作用与目标实际状态。'};notice(error.code==='STALE_TASK'?'任务版本冲突':error.code==='STALE_CONTROL'?'控制版本冲突':error.transport?'请求结果未确认':'操作未完成',messages[error.code]||error.message,error.code);}
    async function work(fn){if(s.busy)return;s.busy=true;permissions();try{await fn();}catch(error){report(error);}finally{s.busy=false;permissions();}}
    function permissions(){
      for(const node of root.querySelectorAll('[data-navigate]'))node.disabled=s.busy;
      $('awRefresh').disabled=s.busy;
    }
    $('awNoticeDismiss').onclick=()=>{$('awNotice').hidden=true;};
    $('awClose').onclick=()=>options.close?options.close():location.assign('/');
    function view(){s.view='tasks';}
    const filters=()=>({q:$('awSearch').value,state:$('awState').value,owner:$('awOwner').value});
    function filter(){s.listOffset=0;refreshList().catch(report);}
    $('awSearch').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(filter,250);};$('awState').onchange=filter;$('awOwner').onchange=filter;
    $('awTaskPrev').onclick=()=>{s.listOffset=Math.max(0,s.listOffset-25);refreshList().catch(report);};$('awTaskNext').onclick=()=>{s.listOffset+=25;refreshList().catch(report);};
    $('awOpPrev').onclick=()=>{s.opOffset=Math.max(0,s.opOffset-25);refreshTask().catch(report);};$('awOpNext').onclick=()=>{s.opOffset+=25;refreshTask().catch(report);};
    $('awRefresh').onclick=()=>work(refresh);
    async function refreshList(){const generation=++s.listGeneration;const value=await client.management({action:'list',limit:25,offset:s.listOffset,...filters()});if(generation!==s.listGeneration)return;
      $('awTaskCount').textContent=`${value.totalTasks} 项任务 · 第 ${Math.floor(s.listOffset/25)+1} 页`;$('awTaskPrev').disabled=s.listOffset===0;$('awTaskNext').disabled=value.nextTaskOffset===null;
      const signature=json(value.tasks)+'|'+s.taskId;if(signature===lastListRender)return;lastListRender=signature;
      const rows=value.tasks.map(task=>{const node=button('',()=>work(()=>selectTask(task.id)));node.dataset.navigate='';node.setAttribute('aria-current',String(task.id===s.taskId));node.append(element('span',task.title,'aw-task-title'));const meta=element('span',undefined,'aw-task-meta');meta.append(badge(task.state),element('span',(task.owner==='ai'?'AI':'人类')+` · v${task.revision??0}`));if(task.heldByOperator)meta.append(element('span','人类暂停'));node.append(meta);node.title=task.id;return node;});
      if(!rows.length)rows.push(element('p',value.totalTasks?'当前页没有任务':'没有匹配任务。AI 提交任务后会在此显示。','aw-empty'));
      $('awTaskList').replaceChildren(...rows);permissions();
    }
    async function selectTask(id){s.taskId=id;s.task=null;s.opId=null;s.op=null;s.opOffset=0;s.resultLoaded=false;lastOpRender='';lastTaskRender='';$('awOperationDetail').hidden=true;await refreshTask();await refreshList();}
    async function refreshTask(){if(!s.taskId)return;const id=s.taskId,generation=++s.detailGeneration;const value=await client.management({action:'get',taskId:id,limit:25,offset:s.opOffset});if(id!==s.taskId||generation!==s.detailGeneration)return;
      if(!Number.isSafeInteger(value.task?.revision)||!Array.isArray(value.task?.resources))throw new scope.AdhClientError('任务工作台需要配套 P2 Host，不能只更新静态页面。','TASK_VERSION_REQUIRED');s.task=value.task;
      const signature=json(value.task);if(signature!==lastTaskRender){lastTaskRender=signature;const head=element('div',undefined,'aw-task-heading');head.append(element('h2',value.task.title),element('div',value.task.id,'aw-mono'));
        const row=element('div',undefined,'aw-row');row.append(badge(value.task.state),element('span',`任务版本 ${value.task.revision} · ${value.task.owner==='ai'?'AI':'人类'}负责`,'aw-muted'));if(value.task.heldByOperator)row.append(element('span','人类暂停','aw-state'));head.append(row);
        head.append(element('p',`创建 ${M.time(value.task.createdAt)} · 更新 ${M.time(value.task.updatedAt)} · ${value.task.totalOperations} 条操作`,'aw-muted'));
        if(value.task.unresolved)head.append(element('p',`${value.task.unresolved} 条操作结果未知`,'aw-muted'));
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
      const signature=(operation.resultFile||'')+'|'+(operation.lateResultFile||'')+'|'+(operation.reconciliations||[]).map(r=>r.file).join('|');
      if(s.resultLoaded&&(force||signature!==s.resultSignature)){({operation}=await client.management({action:'get',id,includeResult:true}));if(id!==s.opId||generation!==s.operationGeneration)return;s.resultSignature=signature;}
      else if(s.resultLoaded){operation.result=s.op?.result;operation.lateResult=s.op?.lateResult;operation.reconciliations=s.op?.reconciliations;}
      s.op=operation;const renderSignature=json(operation)+'|'+s.resultLoaded;if(renderSignature!==lastOpRender){lastOpRender=renderSignature;renderOperation();}
    }
    function facts(parent,pairs){const list=element('dl',undefined,'aw-facts');for(const [label,value]of pairs){const item=element('div');item.append(element('dt',label),element('dd',value));list.append(item);}parent.append(list);}
    function renderOperation(){const op=s.op,area=$('awOperationDetail');area.hidden=false;area.replaceChildren();const heading=element('div',undefined,'aw-row aw-between');heading.append(element('h2',op.name),badge(op.state));area.append(heading,element('p',op.id,'aw-mono aw-spaced'));
      if(op.state==='unknown')area.append(element('p',op.resolvedAt?'原执行结果未知，已核对':'执行结果未知','aw-muted aw-spaced'));
      if(op.cancelRequested)area.append(element('p','已请求取消','aw-muted aw-spaced'));
      if(op.error)area.append(element('pre',op.error.code+': '+op.error.message));
      facts(area,[['所属任务',op.taskId],['调用来源',`${op.owner==='ai'?'AI':'人类'} · ${op.source} · ${op.actorId}`],['作用范围',op.resource],['效果分类',op.mode],['创建 / Host 开始',`${M.time(op.createdAt)} / ${M.time(op.startedAt)}`],['deadline / 终态记录',`${M.time(op.deadline)} / ${M.time(op.finishedAt)}`],['提交版本 / 应用版本',`${op.expectedRevision??'未要求'} / ${op.appliedRevision??'未记录'}`],['控制代次 / Host 代次',`${op.controlEpoch??'未要求'} / ${op.hostEpoch??'未要求'}`],['已派发受跟踪步骤',op.mayHaveExecuted?'是，可能已产生副作用':'没有派发记录'],['等待确认的步骤',String(op.inFlight??0)],['Host 处理是否结束',op.settled?'已结束':'尚未确认结束'],['部分步骤 / 人工核对',`${op.partialEffects?'部分步骤已派发':'无部分步骤标记'} / ${M.time(op.resolvedAt)}`],['幂等意图键',op.key]]);
      const effects=element('section',undefined,'aw-detail-section');effects.append(element('h3','副作用记录'));
      if(op.effects===undefined)effects.append(element('p','旧记录没有逐步骤日志；以上聚合标记不能还原完整副作用。','aw-muted aw-spaced'));
      else if(!op.effects.length)effects.append(element('p','没有受跟踪的派发步骤。离线计算及未埋点的内部步骤不在此日志中。','aw-muted aw-spaced'));
      else {const list=element('ol',undefined,'aw-effect-list');for(const effect of op.effects){const row=element('li');const state={dispatched:'已派发，等待确认',acknowledged:'已收到响应',failed:'Host 步骤失败',unknown:'未确认执行结果'}[effect.state];row.append(element('div',`${effect.kind} / ${effect.action} · ${state}`),element('small',`${M.time(effect.startedAt)} → ${M.time(effect.completedAt)}${effect.uncertainAt?' · 曾有未知状态 '+M.time(effect.uncertainAt):''}${effect.session?' · '+effect.session:''}`));list.append(row);}effects.append(list);}
      if(op.effectsDropped)effects.append(element('p',`日志达到 64 条上限；另有 ${op.effectsDropped} 条派发步骤未逐条保存，不能把当前列表当成全部证据。`,'aw-muted aw-spaced'));area.append(effects);
      const results=element('section',undefined,'aw-detail-section');results.append(element('h3','已保存结果与晚到证据'));if(!s.resultLoaded)results.append(button('加载已保存结果',()=>work(async()=>{s.resultLoaded=true;await refreshOperation(true);}),'aw-spaced'));
      else {for(const [key,label]of [['result','原始结果'],['lateResult','晚到结果（不改变原终态）']]){const box=element('div',undefined,'aw-result-block');box.append(element('h3',label));if(op[key]===undefined)box.append(element('p','尚无已保存内容；不代表目标没有执行。'));else {const raw=json(op[key]);box.append(element('pre',raw.length>120000?raw.slice(0,120000)+'\n…界面预览已截断':raw));if(raw.length>120000)box.append(element('p','界面预览限制 120000 字符，下载可查看全部已保存内容。'));if(op[key]?.omitted)box.append(element('p','Host 只保存了结果摘要，下载文件也不包含被省略的原始数据。'));box.append(button('下载'+label,()=>download(op[key],`${op.id}-${key}.json`)));}results.append(box);}}
      if(op.reconciliations?.length){results.append(element('p',`已保存 ${op.reconciliations.length} 次设备对账；查询没有重放指令，也不改变 Host 原终态。`,'aw-muted aw-spaced'));
        if(s.resultLoaded)for(const [index,record]of op.reconciliations.entries()){const box=element('div',undefined,'aw-result-block');box.append(element('h3',`设备对账证据 ${index+1}（保留原终态）`));const raw=json(record.evidence);box.append(element('pre',raw.length>120000?raw.slice(0,120000)+'\n…界面预览已截断':raw));box.append(button('下载设备对账证据',()=>download(record,`${op.id}-reconciliation-${index+1}.json`)));results.append(box);}}
      area.append(results);permissions();
    }
    async function refresh(){await refreshList();await refreshTask();}
    function start(){s.visible=true;if(timer)return;timer=setInterval(()=>{
      if(!s.visible||document.hidden||!$('awAuto').checked||s.busy||s.refreshing)return;
      if(root.contains(document.activeElement)&&document.activeElement?.matches('input,textarea,select'))return;
      s.refreshing=true;refresh().catch(report).finally(()=>s.refreshing=false);
    },5000);}
    permissions();start();refresh().catch(report);
    if (options.standalone) {
      const params = new URLSearchParams(location.search);
      if (params.get('operation')) work(() => goOperation(params.get('operation')));
      else if (params.get('task')) work(() => selectTask(params.get('task')));
    }
    return {open(name='tasks'){start();view(name);refresh().catch(report);},pause(){s.visible=false;clearInterval(timer);clearInterval(pendingTimer);timer=undefined;pendingTimer=undefined;},refresh};
  }
  scope.AdhWorkbench={mount};
})(globalThis);

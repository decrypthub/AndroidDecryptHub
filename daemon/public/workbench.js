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
      <nav class="aw-tabs" aria-label="任务刷新"><label class="aw-check"><input id="awAuto" type="checkbox" checked>自动刷新（5 秒）</label><button id="awRefresh">刷新状态</button></nav>
      <section id="awNotice" class="aw-notice" data-tone="error" role="alert" hidden><h3>读取任务失败</h3><p id="awNoticeText"></p><button id="awNoticeDismiss">关闭提示</button></section>
      <section id="awTasksView" class="aw-task-grid"><aside class="aw-task-nav" aria-label="任务列表"><div class="aw-search"><input id="awSearch" type="search" aria-label="搜索全部任务" placeholder="搜索任务名称或 ID"><div class="aw-row"><select id="awState" aria-label="按任务状态筛选"><option value="">全部状态</option><option value="active">分析中</option><option value="paused">已暂停</option><option value="unknown">结果未知</option><option value="cancel_requested">已请求取消</option><option value="completed">已完成</option><option value="cancelled">已取消</option></select><select id="awOwner" aria-label="按负责人筛选"><option value="">全部负责人</option><option value="ai">AI</option><option value="operator">人类</option></select></div></div><p id="awTaskCount" class="aw-muted aw-spaced">正在读取任务…</p><div id="awTaskList" class="aw-task-list" aria-live="polite"></div><div class="aw-row"><button id="awTaskPrev">上一页任务</button><button id="awTaskNext">下一页任务</button></div></aside>
      <section class="aw-detail"><div id="awTaskHead" class="aw-empty"><strong>选择一项任务</strong></div><section id="awOperationsSection" class="aw-detail-section" hidden><div class="aw-row aw-between"><h3>操作结果</h3><span id="awOperationCount" class="aw-muted"></span></div><div class="aw-table-wrap"><table class="aw-table"><thead><tr><th>标题</th><th>状态</th><th>创建时间</th><th>结果</th></tr></thead><tbody id="awOperationRows"></tbody></table></div><div class="aw-row aw-spaced"><button id="awOpPrev">上一页操作</button><button id="awOpNext">下一页操作</button></div></section><article id="awOperationDetail" class="aw-detail-section" hidden></article></section></section>
    `;
    const $=id=>root.querySelector('#'+id);
    const s={visible:true,busy:false,refreshing:false,listOffset:0,opOffset:0,taskId:null,opId:null,savedResults:null,listGeneration:0,detailGeneration:0,operationGeneration:0};
    let timer,searchTimer,lastOpRender='',lastTaskRender='',lastListRender='',lastRowsRender='';
    function report(error){
      $('awNoticeText').textContent=error.message;
      $('awNotice').hidden=false;
    }
    async function work(fn){if(s.busy)return;s.busy=true;permissions();try{await fn();}catch(error){report(error);}finally{s.busy=false;permissions();}}
    function permissions(){
      for(const node of root.querySelectorAll('[data-navigate]'))node.disabled=s.busy;
      $('awRefresh').disabled=s.busy;
    }
    $('awNoticeDismiss').onclick=()=>{$('awNotice').hidden=true;};
    $('awClose').onclick=()=>options.close?options.close():location.assign('/');
    const filters=()=>({q:$('awSearch').value,state:$('awState').value,owner:$('awOwner').value});
    function filter(){s.listOffset=0;refreshList().catch(report);}
    $('awSearch').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(filter,250);};$('awState').onchange=filter;$('awOwner').onchange=filter;
    $('awTaskPrev').onclick=()=>{s.listOffset=Math.max(0,s.listOffset-25);refreshList().catch(report);};$('awTaskNext').onclick=()=>{s.listOffset+=25;refreshList().catch(report);};
    $('awOpPrev').onclick=()=>{s.opOffset=Math.max(0,s.opOffset-25);refreshTask().catch(report);};$('awOpNext').onclick=()=>{s.opOffset+=25;refreshTask().catch(report);};
    $('awRefresh').onclick=()=>work(refresh);
    async function refreshList(){const generation=++s.listGeneration;const value=await client.management({action:'list',limit:25,offset:s.listOffset,...filters()});if(generation!==s.listGeneration)return;
      $('awTaskCount').textContent=`${value.totalTasks} 项任务 · 第 ${Math.floor(s.listOffset/25)+1} 页`;$('awTaskPrev').disabled=s.listOffset===0;$('awTaskNext').disabled=value.nextTaskOffset===null;
      const signature=json(value.tasks)+'|'+s.taskId;if(signature===lastListRender)return;lastListRender=signature;
      const rows=value.tasks.map(task=>{
        const node=button('',()=>work(()=>selectTask(task.id)));
        node.dataset.navigate='';
        node.setAttribute('aria-current',String(task.id===s.taskId));
        const meta=element('span',undefined,'aw-task-meta');
        meta.append(badge(task.state),element('time',M.time(task.updatedAt??task.createdAt)));
        node.append(element('span',task.title,'aw-task-title'),meta);
        return node;
      });
      if(!rows.length)rows.push(element('p',value.totalTasks?'当前页没有任务':'没有匹配任务。AI 提交任务后会在此显示。','aw-empty'));
      $('awTaskList').replaceChildren(...rows);permissions();
    }
    async function selectTask(id){
      s.taskId=id;
      s.opId=null;
      s.opOffset=0;
      s.savedResults=null;
      lastTaskRender='';
      $('awTaskHead').replaceChildren();
      $('awOperationsSection').hidden=true;
      $('awOperationDetail').hidden=true;
      await refreshTask();
      await refreshList();
    }
    async function refreshTask(){if(!s.taskId)return;const id=s.taskId,generation=++s.detailGeneration;const value=await client.management({action:'get',taskId:id,limit:25,offset:s.opOffset});if(id!==s.taskId||generation!==s.detailGeneration)return;
      const {task}=value;
      const signature=json([task.title,task.state,task.createdAt,task.updatedAt]);
      if(signature!==lastTaskRender){
        lastTaskRender=signature;
        const head=element('div',undefined,'aw-task-heading');
        const row=element('div',undefined,'aw-row');
        row.append(element('h2',task.title),badge(task.state));
        head.append(row,element('p',`创建 ${M.time(task.createdAt)} · 更新 ${M.time(task.updatedAt)}`,'aw-muted'));
        $('awTaskHead').className='';$('awTaskHead').replaceChildren(head);
      }
      $('awOperationsSection').hidden=false;$('awOperationCount').textContent=`${value.totalOperations} 条 · 第 ${Math.floor(s.opOffset/25)+1} 页`;$('awOpPrev').disabled=s.opOffset===0;$('awOpNext').disabled=value.nextOperationOffset===null;
      const rowsSignature=json(value.operations)+'|'+s.opId;
      if(rowsSignature!==lastRowsRender){lastRowsRender=rowsSignature;
        const rows=value.operations.map(op=>{
          const row=element('tr');
          row.dataset.operation=op.id;
          row.setAttribute('aria-selected',String(op.id===s.opId));
          const status=element('td');
          status.append(badge(op.state));
          const result=element('td');
          const open=button('查看结果',()=>work(()=>selectOperation(op.id)));
          open.dataset.navigate='';
          result.append(open);
          row.append(element('td',op.name),status,element('td',M.time(op.createdAt)),result);
          return row;
        });
        if(!rows.length){
          const cell=element('td','任务还没有操作记录。');
          cell.colSpan=4;
          const row=element('tr');
          row.append(cell);
          rows.push(row);
        }
        $('awOperationRows').replaceChildren(...rows);
      }
      permissions();
      if(s.opId)await refreshOperation();
    }
    async function goOperation(id){
      const {operation}=await client.management({action:'get',id});
      if(s.taskId!==operation.taskId)await selectTask(operation.taskId);
      await selectOperation(id);
    }
    async function selectOperation(id){
      s.opId=id;
      s.savedResults=null;
      lastOpRender='';
      for(const row of $('awOperationRows').querySelectorAll('[data-operation]')){
        row.setAttribute('aria-selected',String(row.dataset.operation===id));
      }
      $('awOperationDetail').hidden=true;
      await refreshOperation();
    }
    const resultSignature=operation=>json([operation.resultFile,operation.lateResultFile]);
    async function refreshOperation(){
      const id=s.opId,generation=++s.operationGeneration;
      const current=()=>id===s.opId&&generation===s.operationGeneration;
      let includeResult=s.savedResults===null;
      let {operation}=await client.management({action:'get',id,includeResult});
      if(!current())return;
      if(!includeResult&&resultSignature(operation)!==s.savedResults.signature){
        includeResult=true;
        ({operation}=await client.management({action:'get',id,includeResult}));
        if(!current())return;
      }
      if(includeResult){
        s.savedResults={signature:resultSignature(operation),result:operation.result,lateResult:operation.lateResult};
      }
      const {name,state,createdAt,startedAt,finishedAt,error}=operation;
      const renderSignature=json([id,name,state,createdAt,startedAt,finishedAt,error?.message,s.savedResults.signature]);
      if(renderSignature!==lastOpRender){
        lastOpRender=renderSignature;
        renderOperation(operation);
      }
    }
    function renderOperation(op){
      const area=$('awOperationDetail');
      area.hidden=false;
      area.replaceChildren();
      const heading=element('div',undefined,'aw-row aw-between');
      heading.append(element('h2',op.name),badge(op.state));
      area.append(heading,element('p',`创建 ${M.time(op.createdAt)} · 开始 ${M.time(op.startedAt)} · 结束 ${M.time(op.finishedAt)}`,'aw-muted'));
      const results=element('section',undefined,'aw-detail-section');
      results.append(element('h3','已保存结果'));
      if(op.error?.message)results.append(element('p',op.error.message,'aw-muted'));
      if(s.savedResults.result===undefined&&s.savedResults.lateResult===undefined){
        results.append(element('p','尚无已保存结果。','aw-muted'));
      }
      for(const [key,label] of [['result','原始结果'],['lateResult','晚到结果']]){
        const value=s.savedResults[key];
        if(value===undefined)continue;
        const box=element('div',undefined,'aw-result-block');
        const raw=json(value);
        box.append(element('h3',label),element('pre',raw.length>120000?raw.slice(0,120000)+'\n…界面预览已截断':raw));
        if(raw.length>120000)box.append(element('p','界面预览限制 120000 字符，可下载全部已保存内容。'));
        if(value?.omitted)box.append(element('p','Host 只保存了结果摘要。'));
        box.append(button('下载'+label,()=>download(value,`${op.id}-${key}.json`)));
        results.append(box);
      }
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
    return {open(){start();refresh().catch(report);},pause(){s.visible=false;clearInterval(timer);clearTimeout(searchTimer);timer=undefined;},refresh};
  }
  scope.AdhWorkbench={mount};
})(globalThis);

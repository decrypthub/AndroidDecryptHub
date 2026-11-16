// Human panel adapter: the same durable operations/control protocol used by CLI and MCP.
(() => {
  const nativeFetch=window.fetch.bind(window), versions=new Map();
  // getRandomValues also works on the existing trusted-LAN HTTP panel.
  const intentId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
  const clientId=intentId();
  let operatorKey='';
  const fragment=new URLSearchParams(location.hash.slice(1));
  if(fragment.has('operator')) {operatorKey=fragment.get('operator')||'';fragment.delete('operator');history.replaceState(null,'',location.pathname+location.search+(fragment.size?'#'+fragment:''));}
  const headers=()=>({'Content-Type':'application/json','X-Adh-Client-Id':clientId,...(operatorKey?{'X-Adh-Operator-Key':operatorKey}:{})});
  async function management(value) {
    const response=await nativeFetch('/api/operations',{method:'POST',headers:headers(),body:JSON.stringify(value)});
    const body=await response.json();
    if(!response.ok || body.ok===false)throw Error(body.error||'操作未完成');
    return body;
  }
  const metadata=s=>({expectedRevision:s.revision,controlEpoch:s.epoch,hostEpoch:s.hostEpoch,idempotencyKey:intentId()});
  const activeGet=new Set(['/api/trace/qbdi','/api/unpack/trigger','/api/hook/selftest','/api/java/probe','/api/compat/probe','/api/debug/frame_echo']);
  window.fetch=async function(input,init={}) {
    const url=new URL(typeof input==='string'?input:input.url,location.href);
    if(url.origin!==location.origin || !url.pathname.startsWith('/api/') || url.pathname.startsWith('/api/operations'))return nativeFetch(input,init);
    const method=(init.method||'GET').toUpperCase(), outgoing={...init,headers:new Headers(init.headers||{})};
    outgoing.headers.set('X-Adh-Client-Id',clientId);
    if(operatorKey)outgoing.headers.set('X-Adh-Operator-Key',operatorKey);
    if(method!=='GET' || activeGet.has(url.pathname)) {
      let args=Object.fromEntries(url.searchParams);
      if(typeof init.body==='string') {try{args={...args,...JSON.parse(init.body)};}catch{}}
      const response=await nativeFetch('/api/operations/prepare',{method:'POST',headers:headers(),body:JSON.stringify({path:url.pathname,method,arguments:args})});
      const prepared=await response.json();
      if(!response.ok)throw Error(prepared.error||'无法读取操作版本');
      if(prepared.spec.mode==='write') {
        if(!operatorKey)throw Error('请先在“任务与控制权”连接操作员，再修改目标或配置');
        outgoing.headers.set('X-Adh-Operation',JSON.stringify(metadata(versions.get(prepared.resource)||prepared)));
      }
    }
    const response=await nativeFetch(input,outgoing);
    const control=response.headers.get('x-adh-control');
    if(control) {try{const value=JSON.parse(control);versions.set(value.resource,value);}catch{}}
    return response;
  };

  const dialog=document.createElement('dialog');
  dialog.id='operationsDialog';
  dialog.style.cssText='width:min(900px,94vw);max-height:85vh;border:1px solid #35383f;border-radius:12px;padding:24px;background:#17191d;color:#e7e9ed;overflow:auto';
  dialog.innerHTML='<form method="dialog" style="float:right"><button>关闭</button></form><h2>任务与控制权</h2>'+
    '<p>AI 自主分析。操作员修改会拦住旧指令；取消请求不代表目标已停止，已经完成的步骤不会自动回滚。</p>'+
    '<p><input id="operatorKey" type="password" autocomplete="off" placeholder="操作员访问密钥" aria-label="操作员访问密钥"> <button id="operatorConnect">连接操作员</button> <span id="operatorRole"></span></p>'+
    '<p><select id="operationTarget" aria-label="控制范围"><option value="">整个 Host</option></select> <button id="operationTake">接管</button> <button id="operationRelease">交还 AI</button> <button id="operationRefresh">刷新</button></p>'+
    '<p><label><input type="checkbox" id="operationAck">已检查实际状态，接受未确认副作用</label> <button id="operationResolve">解除未知状态阻塞</button></p>'+
    '<pre id="operationControl" style="white-space:pre-wrap"></pre><p id="operationMessage" role="status"></p>'+
    '<table style="width:100%;text-align:left"><thead><tr><th>操作</th><th>状态</th><th>来源</th><th>任务</th><th>控制</th></tr></thead><tbody id="operationRows"></tbody></table>';
  document.body.append(dialog);
  const el=id=>dialog.querySelector('#'+id);
  function role(){el('operatorRole').textContent=operatorKey?'操作员凭据已配置':'只读查看，未连接操作员';}
  function target(){return el('operationTarget').value?{session:el('operationTarget').value}:{};}
  async function refresh() {
    const value=await management({action:'list',limit:30});
    const snapshot=await management({action:'snapshot',...target()});
    versions.set(snapshot.resource,snapshot);
    el('operationControl').textContent=`${snapshot.resource}\n版本 ${snapshot.revision} · 控制代次 ${snapshot.epoch} · ${snapshot.owner==='operator'?'操作员控制':'AI 可操作'}${snapshot.uncertain?' · 存在执行结果未知的操作':''}`;
    el('operationRows').replaceChildren();
    for(const operation of value.operations) {
      const row=document.createElement('tr');
      row.title=operation.id+(operation.error?' · '+operation.error.code+': '+operation.error.message:'');
      for(const text of [operation.name,operation.state+(operation.cancelRequested?'（已请求取消）':'')+(operation.partialEffects?'（部分步骤已派发）':''),operation.source,operation.taskId.slice(0,8)]) {
        const cell=document.createElement('td');cell.textContent=text;row.append(cell);
      }
      const actions=document.createElement('td');
      if(['queued','running','cancel_requested'].includes(operation.state)) {
        const button=document.createElement('button');button.textContent='请求取消';
        button.onclick=()=>work(async()=>{if(!operatorKey)throw Error('需要操作员凭据');await management({action:'cancel',id:operation.id});await refresh();});actions.append(button);
      }
      row.append(actions);el('operationRows').append(row);
    }
  }
  async function work(fn) {try{el('operationMessage').textContent='';await fn();}catch(error){el('operationMessage').textContent=error.message;}}
  el('operatorConnect').onclick=()=>work(async()=>{
    const prior=operatorKey;operatorKey=el('operatorKey').value.trim();
    try{await management({action:'snapshot'});}catch(error){operatorKey=prior;throw error;}
    el('operatorKey').value='';role();await refresh();
  });
  for(const [id,action]of [['operationTake','takeover'],['operationRelease','release'],['operationResolve','resolve']]) {
    el(id).onclick=()=>work(async()=>{
      if(!operatorKey)throw Error('需要操作员凭据');
      const snapshot=await management({action:'snapshot',...target()});
      await management({action,...target(),_operation:metadata(snapshot),acknowledge:el('operationAck').checked});await refresh();
    });
  }
  el('operationRefresh').onclick=()=>work(refresh);
  el('operationTarget').onchange=()=>work(refresh);
  document.getElementById('opBtn').onclick=()=>work(async()=>{
    dialog.showModal();role();
    const response=await nativeFetch('/api/agents');const agents=await response.json();
    const selected=el('operationTarget').value;el('operationTarget').replaceChildren(new Option('整个 Host',''));
    for(const agent of agents.filter(a=>a.online))el('operationTarget').add(new Option(`${agent.process||agent.package} · ${agent.pid}`,agent.sessionId));
    el('operationTarget').value=selected;await refresh();
  });
  window.adhOperations={refresh,setOperatorKey:key=>{operatorKey=String(key||'');role();}};
})();

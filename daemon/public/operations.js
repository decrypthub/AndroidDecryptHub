// Live viewer and workbench share one credential and guarded operation transport.
(() => {
  const client=new AdhOperationClient();
  client.installGuard(window);
  const dialog=document.createElement('dialog');dialog.className='aw-overlay';dialog.id='operationsDialog';
  const root=document.createElement('main');dialog.append(root);document.body.append(dialog);
  let workspace;
  function open(view='tasks') {
    if(!dialog.open)dialog.showModal();
    workspace??=AdhWorkbench.mount(root,client,{close:()=>dialog.close(),legacySettings:()=>{dialog.close();openSettings();}});
    workspace.open(view);
  }
  dialog.addEventListener('close',()=>workspace?.pause());
  document.getElementById('opBtn').textContent='任务工作台';
  document.getElementById('opBtn').onclick=()=>open();
  document.addEventListener('DOMContentLoaded',()=>{const settings=document.getElementById('setBtn');settings.removeEventListener('click',openSettings);settings.onclick=()=>open('configuration');});
  window.adhOperations={open,refresh:()=>workspace?.refresh(),setOperatorKey:key=>client.connect(String(key||''))};
})();

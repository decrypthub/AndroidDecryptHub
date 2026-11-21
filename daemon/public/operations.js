// Live viewer and workbench share one credential and guarded operation transport.
(() => {
  const client=new AdhOperationClient();
  client.installGuard(window);
  const dialog=document.createElement('dialog');dialog.className='aw-overlay';dialog.id='operationsDialog';
  const root=document.createElement('main');dialog.append(root);document.body.append(dialog);
  let workspace;
  function open() {
    if(!dialog.open)dialog.showModal();
    if(workspace)workspace.open();
    else workspace=AdhWorkbench.mount(root,client,{close:()=>dialog.close()});
  }
  dialog.addEventListener('close',()=>workspace?.pause());
  document.getElementById('opBtn').onclick=()=>open();
  window.adhOperations={open,refresh:()=>workspace?.refresh(),setOperatorKey:key=>client.connect(String(key||''))};
})();

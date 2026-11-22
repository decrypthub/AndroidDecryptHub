// The settings panel and its history share the same guarded operation transport.
(() => {
  const client=new AdhOperationClient();
  client.installGuard(window);
  let workspace;
  function showRecords() {
    if(workspace)workspace.open();
    else workspace=AdhWorkbench.mount(document.getElementById('setRecordsPage'),client,{embedded:true});
  }
  window.adhOperations={
    open:()=>window.openSettings('records'), showRecords,
    pause:()=>workspace?.pause(), refresh:()=>workspace?.refresh(),
    setOperatorKey:key=>client.connect(String(key||'')),
  };
})();

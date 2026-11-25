// Keep the live panel's guarded transport after unmounting task history.
(() => {
  const client=new AdhOperationClient();
  client.installGuard(window);
  window.adhOperations={
    setOperatorKey:key=>client.connect(String(key||'')),
    setDemoApi:(body,signal,pkg)=>{
      if(pkg!==undefined&&pkg!=='com.adh.sandbox.apilab') throw Error('当前 APP 没有声明可修改的采集点。');
      const query=pkg?'?package='+encodeURIComponent(pkg):'';
      return client.fetcher('/api/observer/demo-api'+query,{
        method:'POST',mode:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal,
      });
    },
    saveOwnedText:(path,body,signal,root='app')=>{
      if(root!=='app'&&root!=='external') throw Error('当前目录不支持保存。');
      const query=new URLSearchParams({action:'save',root,path});
      return client.fetcher('/api/observer/app-files?'+query,{
        method:'POST',mode:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal,
      });
    },
  };
})();

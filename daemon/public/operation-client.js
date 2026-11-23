// All panel surfaces share credentials and transport through this client instance.
((scope) => {
  class ClientError extends Error {
    constructor(message,code='TRANSPORT_UNCONFIRMED',details={}) {super(message);this.code=code;Object.assign(this,details);}
  }
  class Client {
    constructor(fetcher=scope.fetch.bind(scope),crypto=scope.crypto) {
      this.fetcher=fetcher;this.crypto=crypto;this.key='';this.clientId=this.intent();this.versions=new Map();this.listeners=new Set();
    }
    intent() {return Array.from(this.crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');}
    get operator(){return !!this.key;}
    subscribe(fn){this.listeners.add(fn);return()=>this.listeners.delete(fn);}
    headers(key=this.key) {return {'Content-Type':'application/json','X-Adh-Client-Id':this.clientId,...(key?{'X-Adh-Operator-Key':key}:{})};}
    async request(path,body,options={}) {
      const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),options.timeout??12000);
      try {
        const response=await this.fetcher(path,{method:body===undefined?'GET':'POST',headers:this.headers(options.key===undefined?this.key:options.key),body:body===undefined?undefined:JSON.stringify(body),signal:abort.signal});
        const value=await response.json();
        if(!response.ok||value?.ok===false)throw new ClientError(value?.error||'服务未接受操作',value?.code||'REQUEST_FAILED',{status:response.status,value});
        return {value,response};
      } catch(error) {
        if(error instanceof ClientError)throw error;
        throw new ClientError('未能确认 HTTP 请求结果；Host 或目标可能仍在执行。请查询任务，不要直接重发写入。','TRANSPORT_UNCONFIRMED',{transport:true});
      } finally {clearTimeout(timer);}
    }
    async management(value,options) {return (await this.request('/api/operations',value,options)).value;}
    async connect(key) {if(!key.trim())throw new ClientError('请输入操作员访问密钥','OPERATOR_REQUIRED');await this.management({action:'snapshot'},{key:key.trim()});this.key=key.trim();for(const fn of this.listeners)fn();}
    disconnect(){this.key='';for(const fn of this.listeners)fn();}
    requireOperator(){if(!this.operator)throw new ClientError('先接入操作员凭据，AI 仍可自主分析。','OPERATOR_REQUIRED');}
    metadata(snapshot,key=this.intent()){return {expectedRevision:snapshot.revision,controlEpoch:snapshot.epoch,hostEpoch:snapshot.hostEpoch,idempotencyKey:key};}
    async config(){const {value,response}=await this.request('/api/config');let control;try{control=JSON.parse(response.headers.get('x-adh-control'));}catch{}if(!control||control.resource!=='host')throw new ClientError('服务未提供 P1 状态版本，不能安全编辑','CONTROL_REQUIRED');return {settings:value.settings,control};}
    async submitSettings(patch,control,key){this.requireOperator();return this.management({action:'submit',tool:'settings',arguments:{action:'patch',patch},_operation:this.metadata(control,key)});}
    async taskAction(task,action){this.requireOperator();if(!Number.isSafeInteger(task.revision))throw new ClientError('Host 未提供任务版本，不能安全修改任务','TASK_VERSION_REQUIRED');return this.management({action,taskId:task.id,_operation:{expectedTaskRevision:task.revision}});}
    async controlAction(snapshot,action,acknowledge=false){this.requireOperator();return this.management({action,resource:snapshot.resource,_operation:this.metadata(snapshot),acknowledge});}
    // Legacy live-view actions are guarded too; the workbench editor keeps its own frozen baseline.
    installGuard(target=scope) {
      const active=new Set(['/api/trace/qbdi','/api/unpack/trigger','/api/hook/selftest','/api/java/probe','/api/compat/probe','/api/debug/frame_echo']);
      target.fetch=async(input,init={})=>{
        const url=new URL(typeof input==='string'?input:input.url,target.location.href);
        // Local-observer entry has no operations fence: its HTTP gate is the whole boundary.
        if(url.origin!==target.location.origin||!url.pathname.startsWith('/api/')||url.pathname.startsWith('/api/operations')||target.__adhLocalEntry===true)return this.fetcher(input,init);
        const method=(init.method||input.method||'GET').toUpperCase(),outgoing={...init,headers:new Headers(init.headers||{})};
        outgoing.headers.set('X-Adh-Client-Id',this.clientId);if(this.key)outgoing.headers.set('X-Adh-Operator-Key',this.key);
        if(method!=='GET'||active.has(url.pathname)) {
          let args=Object.fromEntries(url.searchParams);if(typeof init.body==='string'){try{args={...args,...JSON.parse(init.body)};}catch{}}
          const prepared=await this.managementPrepare(url.pathname,method,args);
          if(prepared.spec.mode==='write'){if(!humanPanelWrite(url.pathname,args))this.requireOperator();outgoing.headers.set('X-Adh-Operation',JSON.stringify(this.metadata(this.versions.get(prepared.resource)||prepared)));}
        }
        const response=await this.fetcher(input,outgoing),raw=response.headers.get('x-adh-control');
        if(raw){try{const value=JSON.parse(raw);this.versions.set(value.resource,value);}catch{}}
        return response;
      };
    }
    async managementPrepare(path,method,args){return (await this.request('/api/operations/prepare',{path,method,arguments:args})).value;}
  }
  const FAMILY_KEYS=['digest','hmac','symmetric','asymmetric','tls','aead'];
  function humanPanelWrite(pathname,args){
    if(pathname==='/api/unpack/run')return true;
    if(pathname!=='/api/capture/families'||Object.keys(args).length!==3)return false;
    const {package:pkg,family,enabled}=args;
    return typeof pkg==='string'&&/^[A-Za-z0-9_][A-Za-z0-9_.]*$/.test(pkg)&&!pkg.includes('..')
      &&FAMILY_KEYS.includes(family)&&typeof enabled==='boolean';
  }
  scope.AdhOperationClient=Client;scope.AdhClientError=ClientError;
})(globalThis);

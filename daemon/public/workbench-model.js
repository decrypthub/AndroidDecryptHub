// Shared by the workbench and host-only regression tests; no DOM or I/O.
((scope) => {
  const clone=value=>JSON.parse(JSON.stringify(value));
  const fields=[
    ['ui.displayCap','列表显示上限','number',50,5000,'视图'],
    ['capture.enabled','启用捕获流（不安装 Hook）','boolean',0,0,'捕获'],
    ['capture.autoDumpDex','旧自动 DEX 配置（仅存档）','boolean',0,0,'捕获'],
    ['capture.retain','捕获保留条数','number',50,100000,'保留策略'],
    ['capture.maxAgeDays','捕获保留天数','number',0,365,'保留策略'],
    ['artifacts.maxBytes','工件容量上限（字节）','number',268435456,549755813888,'保留策略'],
    ['artifacts.maxAgeDays','工件保留天数','number',0,365,'保留策略'],
    ['capture.cryptoModule','加密模块','string',0,0,'捕获'],
    ['capture.fileModule','文件模块','string',0,0,'捕获'],
    ['capture.sysModule','系统模块','string',0,0,'捕获'],
    ...['digest','hmac','symmetric','asymmetric','tls','aead'].map(name=>['capture.families.'+name,name,'boolean',0,0,'捕获类型']),
    ['startup.antiDebug','旧启动策略（仅迁移模板）','boolean',0,0,'旧启动方案模板（不自动应用）'],
    ['startup.module','启动策略模块','string',0,0,'旧启动方案模板（不自动应用）'],
    ['startup.packages','适用包名（每行一个，留空为全部）','packages',0,32,'旧启动方案模板（不自动应用）'],
    ['startup.extraTargets','附加符号（每行一个）','symbols',0,16,'旧启动方案模板（不自动应用）'],
    ['startup.widenAfterMs','延迟扩展（毫秒，0 为关闭）','number',0,600000,'旧启动方案模板（不自动应用）'],
    ['startup.widenTargets','扩展符号（每行一个）','symbols',0,8,'旧启动方案模板（不自动应用）'],
  ].map(([path,label,type,min,max,group])=>({path,label,type,min,max,group}));
  const get=(obj,path)=>path.split('.').reduce((value,key)=>value?.[key],obj);
  function set(obj,path,value) {const keys=path.split('.');let node=obj;for(const key of keys.slice(0,-1))node=node[key]??={};node[keys.at(-1)]=clone(value);}
  const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  function validate(field,value) {
    if(field.type==='boolean' && typeof value!=='boolean')throw Error(field.label+' 必须是布尔值');
    if(field.type==='number' && (!Number.isSafeInteger(value)||value<field.min||value>field.max))throw Error(`${field.label} 需要 ${field.min}–${field.max} 范围内的整数`);
    if(field.type==='string' && (typeof value!=='string'||value!==value.trim()))throw Error(field.label+' 需要无首尾空格的文本');
    if(field.path==='startup.module'&&value==='')throw Error('启动策略模块不能为空；使用 libc.so 可恢复默认值');
    if(['symbols','packages'].includes(field.type)) {
      const pattern=field.type==='symbols'?/^[A-Za-z_][A-Za-z0-9_]*$/:/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;
      if(!Array.isArray(value)||value.length>field.max||value.some(v=>typeof v!=='string'||!pattern.test(v)))throw Error(`${field.label} 格式有误，最多 ${field.max} 项`);
    }
  }
  function validatePatch(patch) {
    const visit=(value,path='')=>{
      const field=fields.find(f=>f.path===path);
      if(field){validate(field,value);return;}
      if(!value||typeof value!=='object'||Array.isArray(value))throw Error((path||'配置')+' 需要对象');
      for(const [key,item]of Object.entries(value)) {
        const next=path?path+'.'+key:key;
        if(!fields.some(f=>f.path===next||f.path.startsWith(next+'.')))throw Error('不支持的配置字段：'+next);
        visit(item,next);
      }
    };
    visit(patch);return patch;
  }
  function merge(base,patch) {const result=clone(base);for(const f of fields){const value=get(patch,f.path);if(value!==undefined)set(result,f.path,value);}return result;}
  class Draft {
    constructor(snapshot) {this.reset(snapshot);}
    reset(snapshot) {this.baseline=clone(snapshot.settings);this.draft=clone(snapshot.settings);this.control=clone(snapshot.control);}
    patch() {const result={};for(const f of fields){const value=get(this.draft,f.path);if(!equal(value,get(this.baseline,f.path))){validate(f,value);set(result,f.path,value);}}return result;}
    compare(snapshot) {return fields.filter(f=>!equal(get(this.baseline,f.path),get(snapshot.settings,f.path))||!equal(get(this.baseline,f.path),get(this.draft,f.path)))
      .map(f=>({path:f.path,label:f.label,before:get(this.baseline,f.path),current:get(snapshot.settings,f.path),draft:get(this.draft,f.path),local:!equal(get(this.baseline,f.path),get(this.draft,f.path))}));}
    rebase(snapshot) {const patch=this.patch();this.reset(snapshot);this.draft=merge(this.baseline,patch);return patch;}
    import(patch) {validatePatch(patch);this.draft=merge(this.draft,patch);}
  }
  const states={active:'分析中',paused:'已暂停',cancel_requested:'已请求取消',cancelled:'已取消',completed:'已完成',unknown:'执行结果未知',queued:'等待执行',running:'执行中',succeeded:'执行成功',failed:'执行失败'};
  const terminal=state=>['succeeded','failed','cancelled','unknown'].includes(state);
  const time=value=>value?new Date(value).toLocaleString('zh-CN',{hour12:false}):'未记录';
  scope.AdhWorkbenchModel={fields,get,set,validatePatch,merge,Draft,states,terminal,time,equal};
})(globalThis);

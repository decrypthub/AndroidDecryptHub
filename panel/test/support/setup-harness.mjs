import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';

export const panel = resolve(process.env.ADH_PANEL_ROOT || fileURLToPath(new URL('../../', import.meta.url)));
const require = createRequire(new URL('../../package.json', import.meta.url));
export const Vue = require('vue');
const ts = require('typescript');
const {parse} = require('@vue/compiler-sfc');
const {renderToString} = require('@vue/server-renderer');

function names(binding) {
  return ts.isIdentifier(binding) ? [binding.text] : binding.elements.flatMap(e => e.name ? names(e.name) : []);
}

function evaluate(source, context) {
  const ast = ts.createSourceFile('setup.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const declarations = ast.statements.flatMap(node => {
    if (ts.isVariableStatement(node)) return node.declarationList.declarations.flatMap(d => names(d.name));
    if ((ts.isFunctionDeclaration(node)||ts.isClassDeclaration(node)) && node.name) return [node.name.text];
    return [];
  });
  let code = source;
  const edits = ast.statements.flatMap(node => ts.isImportDeclaration(node)
    ? [{start:node.getFullStart(),end:node.end}]
    : (node.modifiers || []).filter(m=>m.kind===ts.SyntaxKind.ExportKeyword).map(m=>({start:m.getStart(ast),end:m.end})));
  for (const edit of edits.sort((a,b)=>b.start-a.start)) code=code.slice(0,edit.start)+code.slice(edit.end);
  const js = ts.transpileModule(code, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
  return new Function(...Object.keys(context),'exports',`${js}\nreturn {${declarations.join(',')}};`)(...Object.values(context),{});
}

export function viewModel() {
  return evaluate(readFileSync(join(panel,'src/capview.ts'),'utf8'), {panelDisplay:{time:'time'}});
}

export function setupComponent(file, props = {}, bindings = {}) {
  const descriptor = parse(readFileSync(join(panel,'src/components',file),'utf8')).descriptor;
  if(file==='CapturePanel.vue'&&bindings.store){bindings.store.devices??=[];bindings.store.selectedDeviceKey??='';}
  const timeline=readFileSync(join(panel,'src/log_timeline.ts'),'utf8');const cache=readFileSync(join(panel,'src/log_cache.ts'),'utf8');
  if(bindings.window)bindings.window={addEventListener:()=>{},removeEventListener:()=>{},...bindings.window};
  const context = {
    ...evaluate(timeline,{}),...evaluate(cache,{}),
    ...Vue,
    defineProps:() => props,
    defineEmits:() => () => {},
    onMounted:() => {}, onUnmounted:() => {},
    window:{setTimeout:() => 0,setInterval:() => 0},
    document:{getElementById:() => null},
    ...bindings,
  };
  const scope = Vue.effectScope();
  const setup = scope.run(() => evaluate(descriptor.scriptSetup.content,context));
  return {
    ...setup, dispose:() => scope.stop(),
    async html() {
      const app = Vue.createSSRApp({setup:() => ({...context,...props,...setup}),render:Vue.compile(descriptor.template.content)});
      app.config.warnHandler = () => {};
      const stub = {inheritAttrs:false,setup:(_,{slots}) => () => Vue.h('span',slots.default?.())};
      for (const name of new Set([...descriptor.template.content.matchAll(/<(n-[a-z-]+)/g)].map(m=>m[1]))) app.component(name,stub);
      return renderToString(app);
    },
  };
}

import fs from'node:fs';import path from'node:path';import{createRequire}from'node:module';
/** Prove the concrete MCP -> action -> factory -> class -> injected sendCmd closure.
 * Return no operations on an unproven edge; this is not an internal-op exemption. */
export function captureControlReachability(root,overrides={}) {
 const ts=createRequire(path.join(root,'daemon/package.json'))('typescript'),parse=(name,text)=>ts.createSourceFile(name,text,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS),mcp=parse('mcp.ts',overrides.mcp??fs.readFileSync(path.join(root,'daemon/src/mcp.ts'),'utf8')),owner=parse('capture_controls.ts',overrides.owner??fs.readFileSync(path.join(root,'daemon/src/capture_controls.ts'),'utf8')),problems=[],ops=new Set(),seen=new Set();
 const walk=(n,f)=>{f(n);n.forEachChild(c=>walk(c,f));},name=n=>n?.text??'',prop=(n,k)=>n?.properties?.find(p=>ts.isPropertyAssignment(p)&&name(p.name)===k)?.initializer,fail=s=>{throw Error(s);};
 const imported=(source,local,file,exported)=>source.statements.some(s=>ts.isImportDeclaration(s)&&s.moduleSpecifier.text===file&&s.importClause?.namedBindings&&ts.isNamedImports(s.importClause.namedBindings)&&s.importClause.namedBindings.elements.some(e=>e.name.text===local&&(e.propertyName?.text??e.name.text)===exported));
 try{
  let tool;walk(mcp,n=>{if(ts.isObjectLiteralExpression(n)&&prop(n,'name')&&ts.isStringLiteral(prop(n,'name'))&&prop(n,'name').text==='capture_controls')tool=n;});
  if(!tool||!ts.isIdentifier(prop(tool,'handler'))||prop(tool,'handler').text!=='captureControlAction'||!imported(mcp,'captureControlAction','./capture_controls.ts','captureControlAction'))fail('MCP capture_controls handler/import edge not proven');
  const action=owner.statements.find(n=>ts.isFunctionDeclaration(n)&&name(n.name)==='captureControlAction'),factory=owner.statements.find(n=>ts.isFunctionDeclaration(n)&&name(n.name)==='getCaptureControls'),klass=owner.statements.find(n=>ts.isClassDeclaration(n)&&name(n.name)==='CaptureControls');
  if(!action||!factory||!klass||!imported(owner,'sendCmd','./service.ts','sendCmd'))fail('controller action/factory/class/transport import not proven');
  let injection;walk(factory,n=>{if(ts.isNewExpression(n)&&ts.isIdentifier(n.expression)&&n.expression.text==='CaptureControls')injection=n.arguments?.[1];});
  if(!injection||!ts.isIdentifier(prop(injection,'command'))||prop(injection,'command').text!=='sendCmd')fail('factory command must be the actual imported sendCmd');
  const ctor=klass.members.find(ts.isConstructorDeclaration);if(!ctor?.parameters.some(p=>name(p.name)==='deps'))fail('dependency constructor argument not found');
  let bindings=0;walk(klass,n=>{if(!ts.isBinaryExpression(n)||n.operatorToken.kind!==ts.SyntaxKind.EqualsToken)return;const left=n.left.getText(owner);if(left==='this.deps'&&ts.isIdentifier(n.right)&&n.right.text==='deps'){let p=n.parent;while(p&&p!==ctor)p=p.parent;if(p===ctor){bindings++;return;}}if(left==='this.deps'||left.startsWith('this.deps.'))fail('transport dependency reassigned outside constructor binding');});if(bindings!==1)fail('constructor must bind its actual deps exactly once');
  let receiver;walk(action,n=>{if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.initializer&&ts.isCallExpression(n.initializer)&&name(n.initializer.expression)==='getCaptureControls')receiver=n.name.text;});if(!receiver)fail('action controller receiver not bound to factory');
  const methods=new Map(klass.members.filter(ts.isMethodDeclaration).map(n=>[name(n.name),n])),queue=[];walk(action,n=>{if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&ts.isIdentifier(n.expression.expression)&&n.expression.expression.text===receiver)queue.push(n.expression.name.text);});
  if(!['status','discover','change'].every(n=>queue.includes(n)))fail('MCP action branches do not reach status/discover/change');
  while(queue.length){const key=queue.shift();if(seen.has(key))continue;seen.add(key);const method=methods.get(key);if(!method)fail('missing controller method '+key);const wrappers=new Map();
   walk(method,n=>{if(ts.isVariableDeclaration(n)&&ts.isIdentifier(n.name)&&n.initializer&&ts.isArrowFunction(n.initializer)){const arrow=n.initializer,param=arrow.parameters[0]?.name;if(!param||!ts.isIdentifier(param))return;let forwards=false;walk(arrow,c=>{if(ts.isCallExpression(c)&&ts.isPropertyAccessExpression(c.expression)&&c.expression.getText(owner)==='this.deps.command'&&ts.isIdentifier(c.arguments[1])&&c.arguments[1].text===param.text)forwards=true;});if(forwards)wrappers.set(n.name.text,param.text);}});
   walk(method,n=>{if(!ts.isCallExpression(n))return;const e=n.expression;if(ts.isPropertyAccessExpression(e)&&e.expression.kind===ts.SyntaxKind.ThisKeyword&&methods.has(e.name.text))queue.push(e.name.text);
    if(ts.isPropertyAccessExpression(e)&&e.getText(owner)==='this.deps.command'){
     const op=n.arguments[1];if(ts.isStringLiteral(op))ops.add(op.text);else{let parent=n.parent;while(parent&&parent!==method&&!ts.isArrowFunction(parent))parent=parent.parent;if(!parent||!ts.isArrowFunction(parent)||!ts.isIdentifier(op)||name(parent.parameters[0]?.name)!==op.text)fail('unproven dynamic command forwarder in '+key);}
    }
    if(ts.isIdentifier(e)&&wrappers.has(e.text)&&ts.isStringLiteral(n.arguments[0]))ops.add(n.arguments[0].text);
   });
  }
  if(!seen.has('runtime'))fail('status action never reaches runtime readback');
 }catch(e){problems.push(e.message);ops.clear();}
 return{ok:problems.length===0,ops:[...ops].sort(),methods:[...seen].sort(),problems};
}

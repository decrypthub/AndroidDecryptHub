// Independent, bounded ARM64 self-load host. No installed APK or existing process is modified.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const exec=promisify(execFile), repo=fileURLToPath(new URL('../',import.meta.url));
const [serial,base='http://127.0.0.1:18088']=process.argv.slice(2);
if(!serial||process.argv.length>4)throw new Error('usage: node tools/run_native_fixture.mjs SERIAL [test-daemon-url]');
const adb=async args=>(await exec('adb',['-s',serial,...args],{timeout:20000,windowsHide:true})).stdout.trim();
const files=[['agent/build/adh-native-host','adh-native-host'],['agent/build/libadh_agent.so','libadh_agent.so'],['agent/third_party/qbdi/lib/libQBDI.so','libQBDI.so']];
for(const [file] of files)if(!existsSync(join(repo,file)))throw new Error(`build missing ${file}`);
const id=randomUUID(), dir=`/data/local/tmp/adh-native-${id}`, stop=`${dir}/stop`;
const data=join(repo,'adhd-data/tool-hardening');mkdirSync(data,{recursive:true});
await adb(['shell','mkdir',dir]);
for(const [file,name] of files)await adb(['push',join(repo,file),`${dir}/${name}`]);
await adb(['shell','chmod','755',`${dir}/adh-native-host`]);
// Only the new self-load process will use this mapping; existing sockets stay established.
// A normal daemon's keep-alive can later restore tcp:8761 without affecting this connection.
await adb(['reverse','tcp:8761','tcp:18761']);
const child=spawn('adb',['-s',serial,'shell',`LD_LIBRARY_PATH=${dir} ${dir}/adh-native-host ${dir}/libadh_agent.so ${stop} 300`],{windowsHide:true,stdio:['ignore','pipe','pipe']});
let output='',error='';child.stdout.on('data',b=>{output+=b;process.stdout.write(b);});child.stderr.on('data',b=>{error+=b;process.stderr.write(b);});
const closed=new Promise(resolve=>{child.on('error',e=>resolve({error:e.message}));child.on('close',code=>resolve({code}));});
try{
 let target;
 for(let i=0;i<40;i++){
  const all=await(await fetch(`${base}/api/agents`)).json();
  const expectedPid=Number(/ADH_NATIVE_HOST pid=(\d+)/.exec(output)?.[1]);
  target=all.find(s=>s.online&&s.package==='com.adh.nativefixture'&&s.pid===expectedPid);
  if(target?.selfModule && /(?:memfd:|\/proc\/self\/fd\/)/.test(target.selfModule))break;
  target=null;await new Promise(r=>setTimeout(r,250));
 }
 if(!target)throw new Error(`native self-load host did not connect: ${output} ${error}`);
 if(!target.caps?.ops?.includes('qbdi_read'))throw new Error('native host loaded an older agent');
 const receipt={id,dir,stop,serial,base,sessionId:target.sessionId,pid:target.pid,uid:target.uid,starttimeTicks:target.starttimeTicks,selfModule:target.selfModule,lifetimeSeconds:300};
 writeFileSync(join(data,'native-host.json'),JSON.stringify(receipt,null,2));console.log('NATIVE_HOST_READY '+JSON.stringify(receipt));
 const exit=await closed;console.log('NATIVE_HOST_EXIT '+JSON.stringify(exit));
}finally{
 await adb(['shell','touch',stop]);
 await closed;
 // Only UUID-scoped files created above; no recursive removal and no PID signaling.
 const entries=(await adb(['shell','ls','-1',dir])).split(/\r?\n/).filter(Boolean);
 const known=new Set([...files.map(([,name])=>name),'stop']);
 if(entries.some(n=>!known.has(n)&&!/^libadh_trace_fixture_[0-9a-f]{32}\.so$/.test(n))) throw new Error(`unexpected native fixture file; retain directory for inspection: ${dir}`);
 await adb(['shell','rm','-f',...entries.map(name=>`${dir}/${name}`)]);
 await adb(['shell','rmdir',dir]);
}

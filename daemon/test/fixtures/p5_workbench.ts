// Host-only public entrypoints. No index.ts, device discovery, ADB or real target.
import cp from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';
import {mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import http from 'node:http';
process.env.ADH_DATA_DIR=mkdtempSync(join(tmpdir(),'adh-p5-panel-'));process.env.ADH_SKIP_ARTIFACT_LOAD='1';delete process.env.ADH_CAPTURES_DIR;
process.env.ADH_OPERATOR_TOKEN='synthetic-p5-operator-key';
cp.execFile=(()=>{throw Error('ADB forbidden in P5 fixture');}) as unknown as typeof cp.execFile;
cp.spawn=(()=>{throw Error('device process forbidden in P5 fixture');}) as unknown as typeof cp.spawn;syncBuiltinESMExports();
const {getOperations}=await import('../../src/operation_host.ts');
const {handleHttp}=await import('../../src/http/router.ts');
const server=http.createServer((req,res)=>handleHttp(req,res).catch(error=>{res.writeHead(500);res.end(JSON.stringify({error:String(error)}));}));
server.listen(0,'127.0.0.1',()=>console.log('P5_WORKBENCH='+JSON.stringify({url:'http://127.0.0.1:'+(server.address() as any).port,root:process.env.ADH_DATA_DIR})));
const stop=()=>{server.closeAllConnections();server.close();getOperations().close();process.exit(0);};process.stdin.resume();process.stdin.on('data',line=>{if(String(line).trim()==='stop')stop();});process.on('SIGINT',stop);

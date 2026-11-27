/** Indexed Host archive. RAM/jsonl retention is a hot window, never this history's eviction policy. */
import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
export type HistoryKind='crypto'|'system'|'net';
export const historyKind=(category:string):HistoryKind=>category==='crypto'?'crypto':category==='net'?'net':'system';
export const historyScope=(serial:string,pkg:string,kind:HistoryKind)=>JSON.stringify([serial,pkg,kind]);
export interface HistoryQuery {serial:string;package:string;kind:HistoryKind;beforeId?:number|null;since?:number;maxId?:number|null;limit?:number;fromTs?:number|null;toTs?:number|null;q?:string;category?:string;}
export class CaptureHistory {
 readonly db:DatabaseSync;
 constructor(file:string){mkdirSync(dirname(file),{recursive:true});this.db=new DatabaseSync(file);this.db.exec(`PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS history_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
 INSERT OR IGNORE INTO history_meta VALUES('high_water',0);
 CREATE TABLE IF NOT EXISTS history_scopes(scope TEXT PRIMARY KEY,serial TEXT NOT NULL,package TEXT NOT NULL,kind TEXT NOT NULL,generation TEXT NOT NULL,next_display INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS history_records(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,category TEXT NOT NULL,ts REAL NOT NULL,display_id INTEGER NOT NULL,search TEXT NOT NULL,body TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS history_scope_id ON history_records(scope,id);
 CREATE INDEX IF NOT EXISTS history_scope_time ON history_records(scope,ts,id);`);}
 get highWater(){return Number(this.db.prepare("SELECT value FROM history_meta WHERE key='high_water'").get()!.value);}
 private scope(serial:string,pkg:string,kind:HistoryKind){const key=historyScope(serial,pkg,kind);let row=this.db.prepare('SELECT * FROM history_scopes WHERE scope=?').get(key);if(!row){this.db.prepare('INSERT INTO history_scopes VALUES(?,?,?,?,?,1)').run(key,serial,pkg,kind,randomUUID());row=this.db.prepare('SELECT * FROM history_scopes WHERE scope=?').get(key)!;}return row;}
 append<T extends Record<string,any>>(records:T[]):T[]{
  if(!records.length)return records;const lookup=this.db.prepare('SELECT body FROM history_records WHERE id=?'),insert=this.db.prepare('INSERT INTO history_records VALUES(?,?,?,?,?,?,?)'),scopes=new Map<string,any>();let high=this.highWater;
  this.db.exec('BEGIN IMMEDIATE');try{for(const record of records){const c:any=record;if(!Number.isSafeInteger(c.id)||c.id<=0)throw new Error('invalid capture id');high=Math.max(high,c.id);const existing=lookup.get(c.id);if(existing){const old=JSON.parse(String(existing.body));if(old.package!==c.package||old.deviceBinding?.serial!==c.deviceBinding?.serial)throw new Error('capture identity collision');c.displayId=old.displayId;c.captureGeneration=old.captureGeneration;continue;}
   const serial=c.deviceBinding?.serial??'',pkg=c.package??'',kind=historyKind(c.category),key=historyScope(serial,pkg,kind);let scope=scopes.get(key);if(!scope){scope={...this.scope(serial,pkg,kind)};scopes.set(key,scope);}c.displayId=scope.next_display++;c.captureGeneration=scope.generation;
   const search=[c.algo,c.op,c.func,c.javaTarget,c.captureMethodId,c.path,c.preview].filter(Boolean).join(' ').toLowerCase();insert.run(c.id,key,String(c.category??''),Number(c.ts)||0,c.displayId,search,JSON.stringify(c));
  }for(const [key,s]of scopes)this.db.prepare('UPDATE history_scopes SET next_display=? WHERE scope=?').run(s.next_display,key);this.db.prepare("UPDATE history_meta SET value=? WHERE key='high_water'").run(high);this.db.exec('COMMIT');return records;}catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 page(q:HistoryQuery){
  const scope=this.scope(q.serial,q.package,q.kind),where=['scope=?'],args:any[]=[scope.scope];
  if(q.maxId!=null){where.push('id<=?');args.push(q.maxId);}if(q.fromTs!=null){where.push('ts>=?');args.push(q.fromTs);}if(q.toTs!=null){where.push('ts<=?');args.push(q.toTs);}if(q.category){where.push('category=?');args.push(q.category);}
  if(q.q?.trim()){if(/^#\d+$/.test(q.q.trim())){where.push('display_id=?');args.push(Number(q.q.trim().slice(1)));}else{where.push("search LIKE ? ESCAPE '\\'");args.push('%'+q.q.toLowerCase().replace(/[\\%_]/g,'\\$&')+'%');}}
  const matched=Number(this.db.prepare('SELECT count(*) AS n FROM history_records WHERE '+where.join(' AND ')).get(...args)!.n);
  if(q.beforeId!=null){where.push('id<?');args.push(q.beforeId);}if(q.since){where.push('id>?');args.push(q.since);}
  const limit=Math.max(1,Math.min(Math.floor(q.limit??300),10000)),rows=this.db.prepare('SELECT body FROM history_records WHERE '+where.join(' AND ')+' ORDER BY id DESC LIMIT ?').all(...args,limit+1),hasMore=rows.length>limit;
  const items=rows.slice(0,limit).reverse().map(r=>JSON.parse(String(r.body)));return{items,matched,hasMore,nextBeforeId:hasMore?items[0]?.id??null:null,generation:String(scope.generation),highWater:this.highWater};
 }
 find(id:number){const r=this.db.prepare('SELECT body FROM history_records WHERE id=?').get(id);return r?JSON.parse(String(r.body)):null;}
 neighbors(serial:string,pkg:string,kind:HistoryKind,lo:number,hi:number,maxId=Number.MAX_SAFE_INTEGER){const scope=historyScope(serial,pkg,kind);return [...this.db.prepare('SELECT body FROM history_records WHERE scope=? AND id<? ORDER BY id DESC LIMIT 64').all(scope,lo).reverse(),...this.db.prepare('SELECT body FROM history_records WHERE scope=? AND id>? AND id<=? ORDER BY id ASC LIMIT 64').all(scope,hi,maxId)].map(r=>JSON.parse(String(r.body)));}
 deleteMany(ids:number[]){this.db.exec('BEGIN IMMEDIATE');try{const stmt=this.db.prepare('DELETE FROM history_records WHERE id=?');for(const id of ids)stmt.run(id);this.db.exec('COMMIT');}catch(e){this.db.exec('ROLLBACK');throw e;}}
 clear(serial:string,pkg:string,kind:HistoryKind){const scope=this.scope(serial,pkg,kind),ids=this.db.prepare('SELECT id FROM history_records WHERE scope=?').all(scope.scope).map(r=>Number(r.id)),generation=randomUUID();this.db.exec('BEGIN IMMEDIATE');try{this.db.prepare('DELETE FROM history_records WHERE scope=?').run(scope.scope);this.db.prepare('UPDATE history_scopes SET generation=?,next_display=1 WHERE scope=?').run(generation,scope.scope);this.db.exec('COMMIT');return{ids,generation};}catch(e){this.db.exec('ROLLBACK');throw e;}}
 clearWhere(serial?:string,pkg?:string){const where:string[]=[],args:string[]=[];if(serial){where.push('serial=?');args.push(serial);}if(pkg){where.push('package=?');args.push(pkg);}const scopes=this.db.prepare('SELECT serial,package,kind FROM history_scopes'+(where.length?' WHERE '+where.join(' AND '):'')).all(...args);for(const s of scopes)this.clear(String(s.serial),String(s.package),s.kind as HistoryKind);}
 close(){this.db.close();}
}
const instances=new Map<string,CaptureHistory>();
export function captureHistoryFor(dataDir:string){const key=resolve(dataDir);let history=instances.get(key);if(!history){history=new CaptureHistory(join(key,'capture-history.sqlite'));instances.set(key,history);}return history;}
export function captureHistoryIfOpen(dataDir:string){return instances.get(resolve(dataDir));}

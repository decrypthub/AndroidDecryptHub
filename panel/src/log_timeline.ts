/** Pure model: ascending stable IDs, additive batches, fixed DOM window, additive history. */
export interface TimelineEntry {id:string|number;order:number;[key:string]:unknown}
export class LogTimeline<T extends TimelineEntry>{
 private byId=new Map<T['id'],T>();items:T[]=[];
 merge(incoming:T[]){const fresh:T[]=[];let changed=false;for(const item of incoming){const old=this.byId.get(item.id);if(!old){this.byId.set(item.id,item);fresh.push(item);}else if(Object.keys(item).some(k=>old[k]!==item[k])){this.byId.set(item.id,{...old,...item});changed=true;}}if(changed)this.items=this.items.map(r=>this.byId.get(r.id)!);if(fresh.length){fresh.sort((a,b)=>a.order-b.order||String(a.id).localeCompare(String(b.id)));if(!this.items.length)this.items=fresh;else if(fresh[0].order>this.items.at(-1)!.order)this.items=[...this.items,...fresh];else if(fresh.at(-1)!.order<this.items[0].order)this.items=[...fresh,...this.items];else{const out:T[]=[];let a=0,b=0;while(a<this.items.length&&b<fresh.length)out.push(this.items[a].order<=fresh[b].order?this.items[a++]:fresh[b++]);this.items=[...out,...this.items.slice(a),...fresh.slice(b)];}}return fresh.length;}
 clear(){this.byId.clear();this.items=[];}
 remove(id:T['id']){this.byId.delete(id);this.items=this.items.filter(r=>r.id!==id);}
}
export function virtualWindow(total:number,scrollTop:number,height:number,rowHeight:number,overscan=8){const start=Math.max(0,Math.floor(scrollTop/rowHeight)-overscan),end=Math.min(total,Math.ceil((scrollTop+Math.max(height,1))/rowHeight)+overscan);return{start,end,top:start*rowHeight,bottom:Math.max(0,(total-end)*rowHeight)};}

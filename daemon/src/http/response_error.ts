import type {IncomingMessage,ServerResponse} from 'node:http';

export async function sendHttpError(req:IncomingMessage,res:ServerResponse,error:any):Promise<void>{
  if(res.writableEnded)return;
  const status=error?.status??(error instanceof SyntaxError?400:500);
  if(status===413&&!req.readableEnded&&!req.destroyed){
    // readBody has stopped retaining bytes. Drain the sender's remaining upload for
    // at most one second before closing; an immediate destroy loses the 413 to RST.
    await new Promise<void>(resolve=>{
      const done=()=>{clearTimeout(timer);req.off('end',done);req.off('close',done);req.off('error',done);resolve();};
      const timer=setTimeout(done,1000);timer.unref();
      req.once('end',done);req.once('close',done);req.once('error',done);req.resume();
    });
  }
  if(res.writableEnded)return;
  try{
    if(status===413){res.setHeader('connection','close');if(!req.readableEnded)res.once('finish',()=>req.destroy());}
    res.writeHead(status,{'content-type':'application/json','access-control-allow-origin':'*'});
    res.end(JSON.stringify({error:error?.message??'internal error'}));
  }catch{req.destroy();}
}

package com.adh.daemon.device

import android.net.LocalServerSocket
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.io.DataOutputStream

/** Root companion only. A timeout/missing broker denies cache delivery, never arms defaults. */
internal class EarlyPlanBroker(private val cache:HookPlanCache,socketName:String="adh_early_plans_v1"):AutoCloseable{
    private val server=LocalServerSocket(socketName)
    private val workers=ThreadPoolExecutor(2,2,30,TimeUnit.SECONDS,ArrayBlockingQueue(2))
    private val thread=Thread({while(!server.isClosedCompat()){
        val socket=try{server.accept()}catch(_:Exception){break}
        if(runCatching{socket.peerCredentials.uid}.getOrDefault(-1)!=0){socket.close();continue}
        try{workers.execute{socket.use{try{it.soTimeout=250;val bytes=java.io.ByteArrayOutputStream();val input=it.inputStream
            while(bytes.size()<512){val b=input.read();if(b<0||b==10)break;bytes.write(b)};require(bytes.size()<512)
            val parts=bytes.toString("US-ASCII").split(' ');require(parts.size==2);val uid=parts[1].toInt();require(uid>0)
            val wire=cache.forProcess(parts[0],uid);val out=DataOutputStream(it.outputStream);out.writeInt(wire?.size?:0);if(wire!=null)out.write(wire);out.flush()
        }catch(_:Exception){runCatching{DataOutputStream(it.outputStream).apply{writeInt(0);flush()}}}}}}catch(_:java.util.concurrent.RejectedExecutionException){socket.close()}
    }},"adh-early-broker").apply{isDaemon=true;start()}
    private fun LocalServerSocket.isClosedCompat()=Thread.currentThread().isInterrupted
    override fun close(){thread.interrupt();server.close();workers.shutdownNow()}
}

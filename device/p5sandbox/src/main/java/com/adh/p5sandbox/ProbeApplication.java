package com.adh.p5sandbox;
import android.app.Application;
import android.os.Process;
import java.io.File;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** First app callback. Never dlopens an Agent or calls an early-plan export. */
public final class ProbeApplication extends Application {
    public void onCreate(){super.onCreate();try{
        String maps=new String(Files.readAllBytes(new File("/proc/self/maps").toPath()),StandardCharsets.UTF_8);
        long before=System.nanoTime();int pid=android.system.Os.getpid();long after=System.nanoTime();
        JSONObject receipt=new JSONObject().put("pid",pid).put("uid",Process.myUid()).put("beforeNs",Long.toString(before)).put("afterNs",Long.toString(after)).put("agentMemfdBeforeApplicationProbe",maps.contains("memfd:jit-cache")).put("applicationCallback",true);
        File config=new File(getFilesDir(),"p5-zygisk-probes.json");
        if(config.exists()){
            JSONObject parameters=new JSONObject(new String(Files.readAllBytes(config.toPath()),StandardCharsets.UTF_8));
            String marker=parameters.getString("marker");
            if(!marker.matches("P5Z_[A-Za-z0-9_]+"))throw new IllegalArgumentException("invalid own probe marker");
            long captureBefore=System.nanoTime();JSONObject probes=ProbeService.crypto(marker);
            boolean absent;
            try{absent=!android.system.Os.access("/data/local/tmp/"+marker+"_system",android.system.OsConstants.F_OK);}
            catch(android.system.ErrnoException e){if(e.errno!=android.system.OsConstants.ENOENT)throw e;absent=true;}
            java.util.concurrent.FutureTask<JSONObject> tls=new java.util.concurrent.FutureTask<>(()->
                new JSONObject().put("ok",ProbeService.tls(marker,parameters.getInt("tlsPort"))).put("tid",Process.myTid()));
            new Thread(tls,"p5-application-tls").start();
            JSONObject tlsResult=tls.get(8,java.util.concurrent.TimeUnit.SECONDS);
            probes.put("system",absent).put("tls",tlsResult.getBoolean("ok"));
            receipt.put("marker",marker).put("probes",probes).put("captureBeforeNs",Long.toString(captureBefore))
                .put("captureAfterNs",Long.toString(System.nanoTime())).put("tlsTid",tlsResult.getInt("tid")).put("probesInApplicationCallback",true);
        }
        Files.write(new File(getFilesDir(),"p5-zygisk-application.json").toPath(),receipt.toString().getBytes(StandardCharsets.UTF_8));
    }catch(Exception e){throw new RuntimeException(e);}}
}

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
        Files.write(new File(getFilesDir(),"p5-zygisk-application.json").toPath(),receipt.toString().getBytes(StandardCharsets.UTF_8));
    }catch(Exception e){throw new RuntimeException(e);}}
}

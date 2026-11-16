package com.adh.p5sandbox;
import android.app.*;
import android.content.Intent;
import android.os.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** No Activity: never brings the sandbox in front of the user's analysis app. */
public final class ProbeService extends Service {
    private boolean started=false;
    private static native String bootstrap(String directory,String wire,String sha);
    public IBinder onBind(Intent intent){return null;}
    public int onStartCommand(Intent intent,int flags,int startId){
        NotificationManager manager=getSystemService(NotificationManager.class);manager.createNotificationChannel(new NotificationChannel("p5-test","P5 isolated verification",NotificationManager.IMPORTANCE_LOW));
        startForeground(5,new Notification.Builder(this,"p5-test").setContentTitle("ADH P5 isolated test").setSmallIcon(android.R.drawable.ic_menu_info_details).build());
        if(!started){started=true;try{System.loadLibrary("p5fixture");String result=bootstrap(getApplicationInfo().nativeLibraryDir,new File(getFilesDir(),"p5-wire.bin").getPath(),intent.getStringExtra("agentSha"));Files.write(new File(getFilesDir(),"p5-result.json").toPath(),result.getBytes(StandardCharsets.UTF_8));}catch(Throwable e){throw new RuntimeException(e);}new Handler(Looper.getMainLooper()).postDelayed(()->stopSelf(),120000);}
        return START_NOT_STICKY;
    }
}

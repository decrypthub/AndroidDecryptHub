package com.adh.p5sandbox;
import android.app.*;
import android.content.Intent;
import android.os.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import org.json.JSONObject;

/** Opt-in test APK, no Activity and no production configuration access. */
public final class ProbeService extends Service {
    private boolean started=false;
    private static native String bootstrap(String directory,String wire,String sha,boolean deferred);
    private static native void startAgent();
    private static native int systemProbe(String path);
    public IBinder onBind(Intent intent){return null;}
    private static byte[] data(String marker,String family){return (marker+"_"+family).getBytes(StandardCharsets.UTF_8);}
    private static JSONObject crypto(String marker) throws Exception {
        JSONObject result=new JSONObject();
        byte[] digest=MessageDigest.getInstance("SHA-256","AndroidOpenSSL").digest(data(marker,"digest"));result.put("digest",digest.length==32);
        Mac mac=Mac.getInstance("HmacSHA256","AndroidOpenSSL");mac.init(new SecretKeySpec(new byte[32],"HmacSHA256"));result.put("hmac",mac.doFinal(data(marker,"hmac")).length==32);
        SecretKeySpec key=new SecretKeySpec(new byte[16],"AES");byte[] plain=data(marker,"symmetric"),iv=new byte[16];Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding","AndroidOpenSSL");c.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));byte[] enc=c.doFinal(plain);c.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));result.put("symmetric",Arrays.equals(plain,c.doFinal(enc)));
        KeyPairGenerator gen=KeyPairGenerator.getInstance("EC","AndroidOpenSSL");gen.initialize(256);KeyPair pair=gen.generateKeyPair();Signature sig=Signature.getInstance("SHA256withECDSA","AndroidOpenSSL");sig.initSign(pair.getPrivate());sig.update(data(marker,"asymmetric"));byte[] signed=sig.sign();sig.initVerify(pair.getPublic());sig.update(data(marker,"asymmetric"));result.put("asymmetric",sig.verify(signed));
        plain=data(marker,"aead");c=Cipher.getInstance("AES/GCM/NoPadding","AndroidOpenSSL");c.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,new byte[12]));enc=c.doFinal(plain);c.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,new byte[12]));result.put("aead",Arrays.equals(plain,c.doFinal(enc)));return result;
    }
    private static boolean tls(String marker,int port) throws Exception {
        // Fixture loopback only. No external network or changes to the device trust store.
        TrustManager[] trust={new X509TrustManager(){public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}public void checkClientTrusted(X509Certificate[] c,String a){}public void checkServerTrusted(X509Certificate[] c,String a){}}};
        SSLContext context=SSLContext.getInstance("TLS");context.init(null,trust,new SecureRandom());
        try(SSLSocket socket=(SSLSocket)context.getSocketFactory().createSocket("127.0.0.1",port)){
            socket.setSoTimeout(5000);socket.startHandshake();byte[] hello=new JSONObject().put("protocol","adh.device/1").put("id",marker+"_tls").put("method","device.hello").toString().getBytes(StandardCharsets.UTF_8);
            DataOutputStream out=new DataOutputStream(socket.getOutputStream());out.writeInt(hello.length);out.write(hello);out.flush();DataInputStream in=new DataInputStream(socket.getInputStream());int size=in.readInt();if(size<1||size>4096)throw new IOException("invalid fixture reply");byte[] reply=new byte[size];in.readFully(reply);return new JSONObject(new String(reply,StandardCharsets.UTF_8)).getJSONObject("error").getString("code").equals("AUTH_FAILED");
        }
    }
    public int onStartCommand(Intent intent,int flags,int startId){
        NotificationManager manager=getSystemService(NotificationManager.class);manager.createNotificationChannel(new NotificationChannel("p5-test","P5 isolated verification",NotificationManager.IMPORTANCE_LOW));
        startForeground(5,new Notification.Builder(this,"p5-test").setContentTitle("ADH P5 isolated test").setSmallIcon(android.R.drawable.ic_menu_info_details).build());
        if(!started){started=true;new Thread(()->{try{
            String marker=intent.getStringExtra("marker");boolean capture=marker!=null;if(capture)crypto("warmup");System.loadLibrary("p5fixture");
            JSONObject result=new JSONObject(bootstrap(getApplicationInfo().nativeLibraryDir,new File(getFilesDir(),"p5-wire.bin").getPath(),intent.getStringExtra("agentSha"),capture));
            if(capture){JSONObject probes=crypto(marker);probes.put("system",systemProbe("/data/local/tmp/"+marker+"_system")==-1);probes.put("tls",tls(marker,intent.getIntExtra("tlsPort",0)));result.put("probes",probes).put("marker",marker).put("allProbesBeforeAgentStart",true);startAgent();}
            Files.write(new File(getFilesDir(),"p5-result.json").toPath(),result.toString().getBytes(StandardCharsets.UTF_8));
        }catch(Throwable e){try{Files.write(new File(getFilesDir(),"p5-result.json").toPath(),new JSONObject().put("error",e.toString()).toString().getBytes(StandardCharsets.UTF_8));}catch(Exception ignored){}}},"p5-probes").start();new Handler(Looper.getMainLooper()).postDelayed(()->stopSelf(),120000);}
        return START_NOT_STICKY;
    }
}

package com.adh.daemon

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ApplicationInfo
import android.os.Build
import android.system.Os
import com.adh.core.AdhPaths
import com.adh.core.DeviceRpc
import com.adh.daemon.device.HookBindingProbe
import com.adh.daemon.device.DeviceFault
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.security.MessageDigest

/** Validation metadata only, never target code analysis or loading the agent in the daemon. */
internal class AndroidHookBinding(private val context:Context):HookBindingProbe{
    private var previousKey="";private var previousAgent:JSONObject?=null
    @Synchronized override fun inspect(packageName:String):JSONObject{
        val pm=context.packageManager
        @Suppress("DEPRECATION") val info=try{pm.getPackageInfo(packageName,if(Build.VERSION.SDK_INT>=28)PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)}catch(_:PackageManager.NameNotFoundException){throw DeviceFault("TARGET_NOT_FOUND","package is no longer installed")}
        val app=checkNotNull(info.applicationInfo)
        if(app.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)!=0)throw DeviceFault("TARGET_DENIED","early cache is third-party only")
        @Suppress("DEPRECATION") val signatures=if(Build.VERSION.SDK_INT>=28)info.signingInfo?.apkContentsSigners else info.signatures
        val signerHashes=signatures?.map{DeviceRpc.sha256(it.toByteArray())}?.sorted()?:emptyList();if(signerHashes.isEmpty())throw DeviceFault("IDENTITY_UNVERIFIED","APK signer evidence unavailable")
        val apkFiles=listOf(app.sourceDir)+app.splitSourceDirs.orEmpty().toList()
        val apks=apkFiles.sorted().map{path->val st=Os.stat(path);JSONObject().put("path",path).put("size",st.st_size).put("inode",st.st_ino).put("mtime",st.st_mtime)}
        val file=File(AdhPaths.MODULE_DIR,AdhPaths.AGENT_SO_NAME);if(!file.isFile||file.length()>128*1024*1024)throw DeviceFault("AGENT_UNAVAILABLE","module agent is absent or exceeds validation limit")
        val st=Os.stat(file.path);val key="${st.st_dev}:${st.st_ino}:${st.st_size}:${st.st_mtime}"
        if(key!=previousKey){val hash=MessageDigest.getInstance("SHA-256");file.inputStream().use{input->val bytes=ByteArray(65536);while(true){val n=input.read(bytes);if(n<0)break;hash.update(bytes,0,n)}}
            previousAgent=JSONObject().put("agentSha256",hash.digest().joinToString(""){"%02x".format(it)}).put("earlySupported",AgentEarlyAbi.exported(file));previousKey=key}
        @Suppress("DEPRECATION") val version=if(Build.VERSION.SDK_INT>=28)info.longVersionCode else info.versionCode.toLong()
        return JSONObject(checkNotNull(previousAgent).toString()).put("package",packageName).put("uid",app.uid).put("versionCode",version.toString()).put("signers",JSONArray(signerHashes)).put("apks",JSONArray(apks))
    }
}

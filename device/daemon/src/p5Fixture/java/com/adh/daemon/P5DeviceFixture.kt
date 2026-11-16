package com.adh.daemon

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Looper
import android.os.Handler
import android.os.Process
import android.system.Os
import android.system.OsConstants
import com.adh.daemon.device.*
import org.json.JSONObject
import java.io.File
import java.io.DataInputStream

/** Debug APK only. Own namespace and root, no Binder publisher or AndroidDeviceBackend. */
object P5DeviceFixture {
    @JvmStatic fun main(args:Array<String>){
        check(Process.myUid()==0);require(args.size==2)
        val root=File(args[0]).canonicalFile;val name=args[1]
        require(root.path.matches(Regex("/data/local/tmp/adh-p5-[a-f0-9]{12}"))&&name.matches(Regex("adh_p5_[a-f0-9]{12}")))
        Thread.setDefaultUncaughtExceptionHandler { _,error->File(root,"crash.txt").writeText(error.stackTraceToString());kotlin.system.exitProcess(1) }
        Looper.prepareMainLooper();val context=SystemContext.create()
        val app=context.packageManager.getApplicationInfo("com.adh.p5sandbox",0)
        val agent=File(app.nativeLibraryDir,"libadh_agent.so");check(agent.isFile)
        val files=DeviceFiles(File(root,"domain"),{f,m->Os.chmod(f.path,m)},{directory->val fd=Os.open(directory.path,OsConstants.O_RDONLY,0);try{Os.fsync(fd)}finally{Os.close(fd)}});files.initialize()
        val scope=ScopeDocuments(File(root,"scope.json"),files)
        val identity=DeviceIdentity(files,File("/proc/sys/kernel/random/boot_id").readText().trim())
        val operations=DeviceOperations(identity,files,DeviceBackend { method,params->when(method){
            "device.info"->JSONObject().put("model",android.os.Build.MODEL).put("sdk",android.os.Build.VERSION.SDK_INT).put("isolatedFixture",true).put("padding",params.optString("padding").also{require(it.length<=512)})
            "scope.get"->scope.snapshot()
            "scope.patch"->scope.patch(params)
            else->throw DeviceFault("UNSUPPORTED_METHOD","fixture never dispatches Android device control")
        }})
        val probe=HookBindingProbe { name->val installed=context.packageManager.getApplicationInfo(name,0);AndroidHookBinding(context,File(installed.nativeLibraryDir,"libadh_agent.so")).inspect(name) }
        val cache=HookPlanCache(operations,files,scope,probe)
        val network=DeviceNetwork(operations,files,allowEphemeral=true)
        val broker=EarlyPlanBroker(cache,name+"_early");val rpc=LocalDeviceRpcServer(operations,name){it.printStackTrace()}
        File(root,"ready.json").writeText(JSONObject().put("pid",Process.myPid()).put("uid",app.uid).put("agentPath",agent.path).put("deviceId",identity.deviceId).toString())
        val deadline=System.nanoTime()+900_000_000_000L;val handler=Handler(Looper.getMainLooper())
        val stop=object:Runnable {override fun run(){
            val request=File(root,"stacks-request");if(request.exists()){request.delete();File(root,"stacks.txt").writeText(Thread.getAllStackTraces().entries.joinToString("\n\n"){(thread,stack)->thread.name+" "+thread.state+"\n"+stack.joinToString("\n")})}
            if(File(root,"stop").exists()||System.nanoTime()>deadline){rpc.close();broker.close();network.close();kotlin.system.exitProcess(0)};handler.postDelayed(this,250)}};handler.post(stop)
        Looper.loop()
    }
}

/** Root client exercises actual LocalSocket credentials/timeouts instead of reading cache files. */
object P5BrokerFetch {
    @JvmStatic fun main(args:Array<String>){
        check(Process.myUid()==0);require(args.size==3&&args[0].matches(Regex("adh_p5_[a-f0-9]{12}_early")))
        val file=File(args[2]).canonicalFile;require(file.path.matches(Regex("/data/local/tmp/adh-p5-[a-f0-9]{12}/wire.bin")))
        LocalSocket().use{socket->socket.connect(LocalSocketAddress(args[0],LocalSocketAddress.Namespace.ABSTRACT));socket.soTimeout=3000;check(socket.peerCredentials.uid==0)
            socket.outputStream.write("com.adh.p5sandbox ${args[1].toInt()}\n".toByteArray());val input=DataInputStream(socket.inputStream);val size=input.readInt();require(size in 0..32768);val bytes=ByteArray(size);input.readFully(bytes);file.writeBytes(bytes);java.io.FileOutputStream(java.io.FileDescriptor.out).apply{write("WIRE_BYTES=$size\n".toByteArray());flush()}}
    }
}

package com.adh.daemon.device
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Process
import com.adh.core.DeviceRpc
import com.adh.core.DeviceStdio
import java.io.BufferedInputStream
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream

/** Root-only byte relay for USB on enforcing ROMs. No interpreter, listener or replay. */
object DeviceRpcRelay {
    @JvmStatic fun main(args:Array<String>){
        check(Process.myUid()==0)
        val armored=args.firstOrNull()=="--base64";val names=if(armored)args.drop(1)else args.toList()
        val name=if(names.isEmpty())DeviceRpc.SOCKET_NAME else names.single().also{require(it.matches(Regex("adh_p5_[a-f0-9]{12}")))}
        LocalSocket().use { socket->
            socket.connect(LocalSocketAddress(name,LocalSocketAddress.Namespace.ABSTRACT));socket.soTimeout=60000;check(socket.peerCredentials.uid==0)
            // app_process redirects System.out to logcat; RPC must use the raw descriptors.
            val output=FileOutputStream(FileDescriptor.out)
            Thread({try{val input=BufferedInputStream(FileInputStream(FileDescriptor.`in`));if(armored){while(true){val frame=DeviceStdio.read(input)?:break;socket.outputStream.write(frame)}}else input.copyTo(socket.outputStream);socket.shutdownOutput()}catch(_:Exception){runCatching{socket.close()}}},"adh-usb-stdin").apply{isDaemon=true;start()}
            try{val input=BufferedInputStream(socket.inputStream);if(armored){while(true){val frame=DeviceStdio.frame(input)?:break;DeviceStdio.write(output,frame)}}else socket.inputStream.copyTo(output);output.flush()}catch(_:Exception){/* close, never retry */}
        }
    }
}

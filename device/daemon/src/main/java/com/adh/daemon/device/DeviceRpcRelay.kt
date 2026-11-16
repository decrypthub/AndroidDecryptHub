package com.adh.daemon.device
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Process
import com.adh.core.DeviceRpc
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream

/** Root-only byte relay for USB on enforcing ROMs. No interpreter, listener or replay. */
object DeviceRpcRelay {
    @JvmStatic fun main(args:Array<String>){
        check(Process.myUid()==0)
        val name=if(args.isEmpty())DeviceRpc.SOCKET_NAME else args.single().also{require(it.matches(Regex("adh_p5_[a-f0-9]{12}")))}
        LocalSocket().use { socket->
            socket.connect(LocalSocketAddress(name,LocalSocketAddress.Namespace.ABSTRACT));socket.soTimeout=60000;check(socket.peerCredentials.uid==0)
            // app_process redirects System.out to logcat; RPC must use the raw descriptors.
            val output=FileOutputStream(FileDescriptor.out)
            Thread({try{FileInputStream(FileDescriptor.`in`).copyTo(socket.outputStream);socket.shutdownOutput()}catch(_:Exception){runCatching{socket.close()}}},"adh-usb-stdin").apply{isDaemon=true;start()}
            try{socket.inputStream.copyTo(output);output.flush()}catch(_:Exception){/* close, never retry */}
        }
    }
}

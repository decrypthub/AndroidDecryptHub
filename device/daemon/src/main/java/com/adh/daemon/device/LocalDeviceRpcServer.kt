package com.adh.daemon.device

import android.net.LocalServerSocket
import android.net.LocalSocket
import com.adh.core.DeviceRpc
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** USB ADB forwards to this abstract UDS. No TCP/LAN listener is opened on the phone. */
internal class LocalDeviceRpcServer(private val operations: DeviceOperations,socketName:String=DeviceRpc.SOCKET_NAME,private val onError:(Exception)->Unit={}) : AutoCloseable {
    private val socket = LocalServerSocket(socketName)
    private val clients = java.util.concurrent.ConcurrentHashMap.newKeySet<LocalSocket>()
    private val workers = ThreadPoolExecutor(4, 4, 30, TimeUnit.SECONDS, ArrayBlockingQueue(4))
    private val accept = Thread({
        while (!Thread.currentThread().isInterrupted) {
            val client = try { socket.accept() } catch (_: Exception) { break }
            // adbd may run as root or shell. An app UID cannot use this root RPC endpoint.
            val uid = runCatching { client.peerCredentials.uid }.getOrDefault(-1)
            if (uid !in setOf(0, 2000)) { onError(IllegalStateException("local RPC peer denied uid=$uid"));client.close(); continue }
            clients.add(client)
            try { workers.execute {
                try { client.soTimeout = 30_000; client.use { DeviceRpcSession(operations).serve(it.inputStream, it.outputStream) } }
                catch (error: Exception) { onError(error) /* close incomplete/authenticated streams; never replay */ }
                finally { clients.remove(client); runCatching { client.close() } }
            } } catch (_: java.util.concurrent.RejectedExecutionException) { clients.remove(client); client.close() }
        }
    }, "adh-device-rpc").apply { isDaemon = true; start() }
    override fun close() { accept.interrupt(); socket.close(); clients.forEach { runCatching { it.close() } }; workers.shutdownNow() }
}

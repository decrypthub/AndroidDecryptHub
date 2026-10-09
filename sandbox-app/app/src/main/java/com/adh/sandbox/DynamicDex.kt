package com.adh.sandbox

import android.util.Base64
import android.util.Log
import dalvik.system.InMemoryDexClassLoader
import java.nio.ByteBuffer

// Loads a known, deterministic dex (built by d8, sha256 b10aea03…) via
// InMemoryDexClassLoader — the ground-truth target for v0.3 ART structural capture.
// The loader is set as the main thread's context ClassLoader so the agent can
// discover it generically (by walking live threads' loaders), then dump the dex
// straight from ART's DexFile and match its sha256 to this known content.
object DynamicDex {
    private const val TAG = "ADH_SANDBOX"

    // 728-byte dex from com.idh.probe.Probe (d8 --release --min-api 26).
    // Hash-bound legacy fixture: package/string names are part of the fixed b10aea03… sha256;
    // do not rename com.idh.probe / IDH_PROBE_OK without regenerating and re-verifying the hash.
    private const val PROBE_DEX_B64 =
        "ZGV4CjAzOAAldROcj4AnW/EXyPvKv8zYfcWhEh6enuXYAgAAcAAAAHhWNBIAAAAAAAAAAFACAAAKAAAAcAAAAAQAAACYAAAAAgAAAKgAAAAAAAAAAAAAAAMAAADAAAAAAQAAANgAAADgAQAA+AAAADABAAA4AQAARgEAAEkBAABgAQAAdAEAAIgBAACUAQAAlwEAAJ4BAAADAAAABAAAAAUAAAAHAAAAAgAAAAIAAAAAAAAABwAAAAMAAAAAAAAAAAABAAAAAAAAAAAACAAAAAEAAQAAAAAAAAAAAAEAAAABAAAAAAAAAAYAAAAAAAAAQAIAAAAAAAABAAAAAAAAACgBAAADAAAAGgABABEAAAABAAEAAQAAACwBAAAEAAAAcBACAAAADgADAA4AAgAOAAY8aW5pdD4ADElESF9QUk9CRV9PSwABTAAVTGNvbS9pZGgvcHJvYmUvUHJvYmU7ABJMamF2YS9sYW5nL09iamVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwAKUHJvYmUuamF2YQABVgAFaGVsbG8AnwF+fkQ4eyJiYWNrZW5kIjoiZGV4IiwiY29tcGlsYXRpb24tbW9kZSI6InJlbGVhc2UiLCJoYXMtY2hlY2tzdW1zIjpmYWxzZSwibWluLWFwaSI6MjYsInNoYS0xIjoiYTdhZDE4YTcwNDYwYjc5OWQwNDgyZTQ5N2MxMDlhNzViZjdmOTFkZSIsInZlcnNpb24iOiI4LjEwLjktZGV2In0AAAACAACBgASQAgEJ+AEAAAsAAAAAAAAAAQAAAAAAAAABAAAACgAAAHAAAAACAAAABAAAAJgAAAADAAAAAgAAAKgAAAAFAAAAAwAAAMAAAAAGAAAAAQAAANgAAAABIAAAAgAAAPgAAAADIAAAAgAAACgBAAACIAAACgAAADABAAAAIAAAAQAAAEACAAAAEAAAAQAAAFACAAA="

    // Keep strong references so ART keeps the dex mapped.
    @JvmStatic private var loader: InMemoryDexClassLoader? = null
    @JvmStatic private var probeClass: Class<*>? = null

    fun load() {
        try {
            val bytes = Base64.decode(PROBE_DEX_B64, Base64.DEFAULT)
            val buf = ByteBuffer.allocateDirect(bytes.size).apply { put(bytes); rewind() }
            val ldr = InMemoryDexClassLoader(buf, MainActivity::class.java.classLoader)
            val cls = ldr.loadClass("com.idh.probe.Probe")          // force ART to map the dex
            val hello = cls.getMethod("hello").invoke(null)
            loader = ldr
            probeClass = cls
            // Make the loader discoverable to the agent via the main thread's context loader.
            Thread.currentThread().contextClassLoader = ldr
            Log.i(TAG, "InMemoryDex loaded: ${bytes.size} bytes, Probe.hello()=$hello, ctxLoader set")
        } catch (t: Throwable) {
            Log.w(TAG, "InMemoryDex load failed: ${t.message}")
        }
    }
}

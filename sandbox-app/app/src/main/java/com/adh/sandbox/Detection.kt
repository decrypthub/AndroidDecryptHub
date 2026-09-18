package com.adh.sandbox

import android.util.Log

// Bridge to libadhdetect.so — the mock native anti-analysis lib. Loaded at startup
// so its GOT exists; the agent installs GOT hooks then invokes run() reflectively.
object Detection {
    private const val TAG = "ADH_SANDBOX"
    @JvmStatic external fun run(): Int
    @JvmStatic external fun staticCrypto(): Int
    @JvmStatic external fun nativeHookProbe(): Int
    @JvmStatic external fun jniRegisterProbe(): Int
    @JvmStatic external fun jniRegisteredProbe(): Int
    // v4.18 JNIEnv table probe: native code calls FindClass / GetMethodID / GetStaticMethodID /
    // NewStringUTF / GetStringUTFChars through this JNIEnv, so one trigger exercises every
    // JNIEnv table hook. jniEnvValue exists only to be resolved by GetStaticMethodID.
    @JvmStatic external fun jniEnvProbe(): Int
    @JvmStatic fun jniEnvValue(): String = "ADH_JNI_ENV_VALUE"
    // v4.19 fixture for the field-ID / byte-array JNIEnv hooks: native code performs
    // GetFieldID / GetStaticFieldID / SetByteArrayRegion / GetByteArrayElements in one call.
    @JvmStatic external fun jniEnvArrayProbe(): Int
    // Exists so the probe can resolve a static field ID on this class.
    @JvmField val jniEnvStaticField: Int = 0x51
    // v4.20 invariant fixture: hooking member-ID lookups must not change the target's
    // exception state (a failed lookup must still leave its error pending).
    @JvmStatic external fun jniEnvExceptionProbe(): Int
    // v4.24 fixture for the Call*Method / NewObject table hooks (all three JNI forms).
    @JvmStatic external fun jniCallProbe(): Int
    // v4.26 fixture: byte[] written back in place via ReleaseByteArrayElements and the
    // primitive-array critical pair (the post-decryption pattern).
    @JvmStatic external fun jniArrayWriteProbe(): Int
    // v4.27 fixture: every remaining Call* return type (Boolean/Byte/Char/Short/Long/
    // Float/Double, instance + static) has a target method exercised from native code.
    @JvmStatic external fun jniCallTypesProbe(): Int
    // v4.28 fixture: construct JniCtorTarget(21) through JNI so a constructor hook sees the
    // argument and the object is still usable afterwards (total must stay 42).
    @JvmStatic external fun jniCtorProbe(): Int
    // v4.30 fixtures for the load-time JNI_OnLoad watch: these libraries are NOT loaded at
    // startup, the verifier triggers the load after arming the watch.
    // v4.32 anti-hook self-audit: inspects this library's own mappings and code bytes (anonymous
    // executable mappings, prologue self-integrity, an "agent"-named module, an entry that branches
    // outside its own module) and returns the raw numbers as JSON. Used to prove both that an
    // inline hook IS visible this way and that the opt-in stealth pool removes the anonymous page.
    @JvmStatic external fun antiHookProbe(): String
    // v4.33 fixture for call-site ("sites") hooking: native code reaches adh_add_target through an
    // ordinary BL, which the sites backend rewrites while leaving adh_add_target's prologue intact.
    @JvmStatic external fun siteProbe(): Int
    // v4.35 fixture: reaches adh_add_target only through a function-pointer table (indirect call), so
    // intercepting it requires patching the data slot, not any code.
    @JvmStatic external fun slotProbe(): Int
    // Address of that table (slot 0 = adh_add_target, slot 1 = a different function).
    @JvmStatic external fun vtableAddress(): Long
    // Same target reached through a real BL (result consumed) instead of a tail call, so both
    // patch forms are exercised.
    @JvmStatic external fun siteProbeBl(): Int
    // v4.34 cross-module fixture: implemented in libadhplugin_a.so (not in libadhdetect.so), so it
    // reaches adh_add_target through another module's PLT. Requires loadPluginA() first.
    @JvmStatic external fun pluginProbe(): Int
    @JvmStatic fun loadPluginA() { System.loadLibrary("adhplugin_a") }
    @JvmStatic fun loadPluginB() { System.loadLibrary("adhplugin_b") }

    fun load() {
        try {
            System.loadLibrary("adhdetect")
            Log.i(TAG, "adhdetect loaded")
        } catch (t: Throwable) {
            Log.w(TAG, "adhdetect not loaded: ${t.message}")
        }
    }
}

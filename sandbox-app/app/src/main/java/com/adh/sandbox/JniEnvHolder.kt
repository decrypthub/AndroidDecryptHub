package com.adh.sandbox

// v4.19 fixture for the JNIEnv table hooks: an *instance* field so native code can resolve a
// field ID through JNIEnv->GetFieldID (the static-field case uses Detection.jniEnvStaticField).
class JniEnvHolder {
    @JvmField val marker: Int = 0x51
}
// libadhdetect.so — a mock "anti-analysis" native lib for the sandbox.
// Mimics what evasive/gray-market apps do in native code (to dodge Java hooks):
// debugger detection (ptrace TRACEME + /proc TracerPid), root detection (su paths),
// and property checks (ro.debuggable). The IDH agent GOT-hooks these libc calls to
// OBSERVE (module V) — and can neutralize (module S). Deterministic for verify.

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define TAG "ADH_DETECT"

// A "stripped native crypto" signature target for the H.4 constant scan: the real
// AES forward S-box + a Base64 alphabet. Marked volatile-used in run() so the
// linker keeps them (mimics an app that does crypto in native without symbols).
const unsigned char ADH_AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};
const char ADH_B64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// A DIRECT syscall (gettid, nr 178) via `svc #0`, bypassing libc — the exact
// evasion the E.9 scanner locates. Not marked static so it isn't inlined away.
long adh_direct_gettid(void) {
    long ret;
    __asm__ volatile("mov x8, #178\n\t svc #0\n\t mov %0, x0" : "=r"(ret) : : "x8", "x0", "memory");
    return ret;
}

// libc-MEDIATED syscall fixture. Ordinary app code never issues its own `svc`; it calls bionic
// wrappers, whose stubs live in libc.so (`mov x8, #160 ; svc #0` for uname). A scan of THIS module
// finds nothing, which is exactly why the syscall watch must also be able to target libc.so and
// attribute the number statically before hooking. uname is used because it is rare (no noise) and
// deterministic. The return value is a stable checksum of utsname.sysname/version so the caller can
// assert the call really happened.
#include <sys/utsname.h>
__attribute__((noinline, visibility("default")))
long adh_libc_uname_probe(void) {
    struct utsname u;
    memset(&u, 0, sizeof(u));
    if (uname(&u) != 0) return -1;
    long sum = 0;
    for (const char *p = u.sysname; *p; p++) sum += (unsigned char)*p;
    for (const char *p = u.machine; *p; p++) sum = sum * 3 + (unsigned char)*p;
    return sum;
}

// Caller-chain fixture for the hook-hit backtrace (v4.39): the host walks the x29 chain captured at
// the hook hit, so the chain must contain REAL frame records. Built with -fno-omit-frame-pointer
// (see CMakeLists) - the same choice AOSP makes, because without it the chain is empty and the
// backtrace would honestly report only the return address.
__attribute__((noinline, used, visibility("default")))
int adh_bt_target(void);
__attribute__((noinline, used, visibility("default")))
int adh_bt_mid2(void);
__attribute__((noinline, used, visibility("default")))
int adh_bt_mid1(void);
__attribute__((noinline, used, visibility("default")))
int adh_bt_outer(void);

// The seed is volatile so clang cannot constant-fold the whole chain away (the first version
// compiled all four functions into "mov w0, #imm; ret" - 8 bytes each, no calls, no frames).
volatile int adh_bt_seed = 1;

__attribute__((noinline, used, visibility("default")))
int adh_bt_target(void) { return 0x40 + (adh_bt_seed - 1); }   // 64

__attribute__((noinline, used, visibility("default")))
int adh_bt_mid2(void) { return adh_bt_target() + 1 + (adh_bt_seed - 1); }   // 65

__attribute__((noinline, used, visibility("default")))
int adh_bt_mid1(void) { return adh_bt_mid2() * adh_bt_seed + 1; }           // 66

__attribute__((noinline, used, visibility("default")))
int adh_bt_outer(void) { return adh_bt_mid1() + 1; }                        // 67

// Static-linked crypto-shaped target for the WS-A inline-hook acceptance path. It is
// deliberately not a PLT call: the JNI entry below calls this function directly, so a GOT
// replacement cannot observe it. A real target may replace this with a statically linked
// BoringSSL update routine using the same five-argument ABI.
__attribute__((noinline, visibility("default")))
int adh_static_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outl,
                                const unsigned char *in, int inl) {
    (void)ctx;
    if (!out || !outl || !in || inl < 0) return 0;
    for (int i = 0; i < inl; i++) out[i] = (unsigned char)(in[i] ^ 0x5a);
    *outl = inl;
    return 1;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_staticCrypto(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    static const unsigned char marker[] = "ADH_INLINE_CRYPTO_v1";
    unsigned char out[sizeof(marker)]; int outl = 0;
    return adh_static_EVP_CipherUpdate(NULL, out, &outl, marker, (int)sizeof(marker) - 1);
}

// Deterministic target for QBDI instruction trace: sum i*3 for i in 0..4 -> 30.
// (volatile prevents constant-folding so QBDI sees real loop instructions.)
__attribute__((noinline, visibility("default")))
int adh_trace_target(void) {
    volatile int s = 0;
    for (volatile int i = 0; i < 5; i++) s += i * 3;
    return s;   // 0+3+6+9+12 = 30
}

// Attributes MUST be on the first declaration as well: with a plain prototype here the compiler
// inlined the body into the fixtures (the definition's noinline did not apply), which silently left
// the call-site tests with no call at all - v70 caught that loudly.
__attribute__((noinline, used, visibility("default")))
long adh_add_target(long a, long b);
// v4.35 fixture for pointer-slot ("vtable") hooking: a const table of function pointers lands in
// .data.rel.ro (read-only after relocation), and the probe reaches adh_add_target ONLY through it,
// so an indirect call can be intercepted without touching either the function or a call site.
// const volatile keeps the compiler from folding the load and devirtualising the call.
struct adh_vt { long (*add)(long, long); long (*sub)(long, long); };
volatile long adh_site_sink;           // forces adh_site_probe_bl to make a real call instead of a tail call


// v4.33 fixture: the ONLY caller of adh_add_target inside this module, so a call-site hook has an
// unambiguous BL to rewrite. noinline on both sides keeps the call a real BL instead of an inlined
// add. The entry-prologue self-audit must stay clean while this call is intercepted.
// The arguments live in a volatile array on purpose: with literal constants the compiler folded the
// whole call into "mov w0, #84; ret" (IPA constant propagation), which silently left the fixture with
// no call site at all - and the sites backend then correctly reported "no B/BL call site found".
volatile long adh_site_args[2] = { 20, 22 };

__attribute__((noinline, used, visibility("default")))
long adh_site_probe(void) {
    return adh_add_target(adh_site_args[0], adh_site_args[1]);   // tail call (b) through the PLT stub
}

// Same call, but the result is consumed, so the compiler emits a real BL instead of a tail call.
// The sites backend must match the instruction FORM of each site (b vs bl); covering only one of
// them hid a bug where a tail call was patched with a BL and the target spun at its own entry.
__attribute__((noinline, used, visibility("default")))
long adh_site_probe_bl(void) {
    long v = adh_add_target(adh_site_args[0], adh_site_args[1]);
    adh_site_sink = v;
    return v;
}

// Deterministic active-call target: (a + b) * 2, exported for native_call acceptance.
__attribute__((noinline, used, visibility("default")))
__attribute__((noinline, used, visibility("default")))
long adh_sub_target(long a, long b) {
    return a - b;
}

long adh_add_target(long a, long b) {
    return (a + b) * 2;
}
// Deterministic trigger for the generic native-hook manager: an explicit JNI call into
// adh_trace_target() lets the acceptance script install an inline/GOT hook and observe it.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_nativeHookProbe(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return adh_trace_target();
}
// v4.55 fixture: drive the JNIEnv FIELD accessors. Native code that reads/writes fields through the
// env table (instead of reflection or bytecode) is what the agent's new slots exist for, so this
// probe goes through GetStaticObjectField -> Get/Set<Type>Field on the live HeapProbe.sConfig and
// Get/SetStaticIntField on the holder. It returns the number of accessor calls it made (0 = the
// fixture object is not initialized yet).
// v4.63 fixture: drive the string-copy and direct-buffer JNIEnv entries. Native fingerprint code
// lifts Java strings into its own buffers (GetStringRegion / GetStringUTFRegion) and hands payloads
// to Java as direct ByteBuffers (NewDirectByteBuffer + the two lookups). Returns the number of
// accessor calls it made so the caller can assert the probe really ran.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniStringProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int calls = 0;
    jstring text = (*env)->NewStringUTF(env, "ADH-STRING-PROBE-0123456789");
    if (!text) { (*env)->ExceptionClear(env); return 0; }

    jchar wbuf[32];
    memset(wbuf, 0, sizeof(wbuf));
    (*env)->GetStringRegion(env, text, 4, 12, wbuf);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;

    char ubuf[48];
    memset(ubuf, 0, sizeof(ubuf));
    (*env)->GetStringUTFRegion(env, text, 4, 12, ubuf);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;

    // v4.65: the pin/unpin pair - a direct pointer to the Java string's characters.
    jboolean is_copy = JNI_FALSE;
    const jchar *pinned = (*env)->GetStringChars(env, text, &is_copy);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;
    if (pinned) {
        (*env)->ReleaseStringChars(env, text, pinned);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;
    }

    static unsigned char payload[64];
    for (int i = 0; i < 64; i++) payload[i] = (unsigned char)(i + 0x41);
    jobject direct = (*env)->NewDirectByteBuffer(env, payload, (jlong)sizeof(payload));
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;
    if (direct) {
        void *addr = (*env)->GetDirectBufferAddress(env, direct);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;
        jlong cap = (*env)->GetDirectBufferCapacity(env, direct);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); else calls++;
    }
    return (jint)calls;
}

// v4.70 fixture: drive the array-region family (Get/Set<Type>ArrayRegion). Native code moves whole
// arrays through these entries (unpacking, checksums, protocol parsing), so the fixture walks all
// seven primitive types with fixed contents: every entry has to emit its own event carrying
// start/len and a bounded preview, and the values are read back and compared - hooking them must
// not change what the target observes. Returns 0xAD7000 | bits, bit i = family i round-tripped.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniArrayRegionProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jint bits = 0;
    // Boolean: 1,0,1,0
    {
        jbooleanArray a = (*env)->NewBooleanArray(env, 4);
        const jboolean seed[4] = { 1, 0, 1, 0 };
        jboolean back[4] = { 0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetBooleanArrayRegion(env, a, 0, 4, seed);
        (*env)->GetBooleanArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 1;
        (*env)->DeleteLocalRef(env, a);
    }
    // Char: 65,68,72,33
    {
        jcharArray a = (*env)->NewCharArray(env, 4);
        const jchar seed[4] = { 65, 68, 72, 33 };
        jchar back[4] = { 0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetCharArrayRegion(env, a, 0, 4, seed);
        (*env)->GetCharArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 2;
        (*env)->DeleteLocalRef(env, a);
    }
    // Short: 1000,2000,3000,4000
    {
        jshortArray a = (*env)->NewShortArray(env, 4);
        const jshort seed[4] = { 1000, 2000, 3000, 4000 };
        jshort back[4] = { 0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetShortArrayRegion(env, a, 0, 4, seed);
        (*env)->GetShortArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 4;
        (*env)->DeleteLocalRef(env, a);
    }
    // Int: 100000,200000,300000,400000
    {
        jintArray a = (*env)->NewIntArray(env, 4);
        const jint seed[4] = { 100000, 200000, 300000, 400000 };
        jint back[4] = { 0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetIntArrayRegion(env, a, 0, 4, seed);
        (*env)->GetIntArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 8;
        (*env)->DeleteLocalRef(env, a);
    }
    // Long: 10000000000,20000000000,30000000000,40000000000
    {
        jlongArray a = (*env)->NewLongArray(env, 4);
        const jlong seed[4] = { 10000000000LL, 20000000000LL, 30000000000LL, 40000000000LL };
        jlong back[4] = { 0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetLongArrayRegion(env, a, 0, 4, seed);
        (*env)->GetLongArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 16;
        (*env)->DeleteLocalRef(env, a);
    }
    // Float: 1.5,2.5,3.5,4.5
    {
        jfloatArray a = (*env)->NewFloatArray(env, 4);
        const jfloat seed[4] = { 1.5f, 2.5f, 3.5f, 4.5f };
        jfloat back[4] = { 0.0f };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetFloatArrayRegion(env, a, 0, 4, seed);
        (*env)->GetFloatArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 32;
        (*env)->DeleteLocalRef(env, a);
    }
    // Double: 1.25,2.25,3.25,4.25
    {
        jdoubleArray a = (*env)->NewDoubleArray(env, 4);
        const jdouble seed[4] = { 1.25, 2.25, 3.25, 4.25 };
        jdouble back[4] = { 0.0 };
        if (!a) {
            // An allocation failure leaves an exception pending, and the next JNI call with one
            // pending is illegal (CheckJNI aborts) - bail out instead of driving the probe on.
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD7000 | bits);
        }
        (*env)->SetDoubleArrayRegion(env, a, 0, 4, seed);
        (*env)->GetDoubleArrayRegion(env, a, 0, 4, back);
        if (memcmp(seed, back, sizeof(seed)) == 0) bits |= 64;
        (*env)->DeleteLocalRef(env, a);
    }
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return (jint)0xAD7000; }
    return (jint)(0xAD7000 | bits);
}

// v4.74 fixture: drive the array-elements family (Get/Release<Type>ArrayElements). Each type is
// seeded through Set<Type>ArrayRegion, pinned with Get<Type>ArrayElements, mutated in the pinned
// buffer, released with mode 0 (copy back) and read back - so the release preview and the target's
// own view of the array have to agree. A last round mutates an int[] and releases with JNI_ABORT:
// the read-back must still show the OLD value, because the hook must not turn "discard" into
// "commit". Returns 0xAD8000 | bits (one bit per type, 0x80 for the abort round).
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniArrayElementsProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jint bits = 0;
    // Every Get<Type>ArrayElements call asks for the out-param: the wrapper must report the VALUE the
    // runtime wrote (0/1), not the "caller did not ask" -1 that a NULL pointer honestly produces.
    jboolean is_copy = JNI_FALSE;
    // Boolean: seed 1, 0, 1, 0 -> pin, mutate element 0 to 0, copy back
    {
        jbooleanArray a = (*env)->NewBooleanArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jboolean seed[4] = { 1, 0, 1, 0 };
        jboolean back[4] = { 0 };
        (*env)->SetBooleanArrayRegion(env, a, 0, 4, seed);
        jboolean *elems = (*env)->GetBooleanArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 0;
        (*env)->ReleaseBooleanArrayElements(env, a, elems, 0);
        (*env)->GetBooleanArrayRegion(env, a, 0, 4, back);
        const jboolean want[4] = { 0, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 1;
        (*env)->DeleteLocalRef(env, a);
    }
    // Char: seed 65, 68, 72, 33 -> pin, mutate element 0 to 90, copy back
    {
        jcharArray a = (*env)->NewCharArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jchar seed[4] = { 65, 68, 72, 33 };
        jchar back[4] = { 0 };
        (*env)->SetCharArrayRegion(env, a, 0, 4, seed);
        jchar *elems = (*env)->GetCharArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 90;
        (*env)->ReleaseCharArrayElements(env, a, elems, 0);
        (*env)->GetCharArrayRegion(env, a, 0, 4, back);
        const jchar want[4] = { 90, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 2;
        (*env)->DeleteLocalRef(env, a);
    }
    // Short: seed 1000, 2000, 3000, 4000 -> pin, mutate element 0 to 1111, copy back
    {
        jshortArray a = (*env)->NewShortArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jshort seed[4] = { 1000, 2000, 3000, 4000 };
        jshort back[4] = { 0 };
        (*env)->SetShortArrayRegion(env, a, 0, 4, seed);
        jshort *elems = (*env)->GetShortArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 1111;
        (*env)->ReleaseShortArrayElements(env, a, elems, 0);
        (*env)->GetShortArrayRegion(env, a, 0, 4, back);
        const jshort want[4] = { 1111, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 4;
        (*env)->DeleteLocalRef(env, a);
    }
    // Int: seed 100000, 200000, 300000, 400000 -> pin, mutate element 0 to 111111, copy back
    {
        jintArray a = (*env)->NewIntArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jint seed[4] = { 100000, 200000, 300000, 400000 };
        jint back[4] = { 0 };
        (*env)->SetIntArrayRegion(env, a, 0, 4, seed);
        jint *elems = (*env)->GetIntArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 111111;
        (*env)->ReleaseIntArrayElements(env, a, elems, 0);
        (*env)->GetIntArrayRegion(env, a, 0, 4, back);
        const jint want[4] = { 111111, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 8;
        (*env)->DeleteLocalRef(env, a);
    }
    // Long: seed 10000000000LL, 20000000000LL, 30000000000LL, 40000000000LL -> pin, mutate element 0 to 11111111111LL, copy back
    {
        jlongArray a = (*env)->NewLongArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jlong seed[4] = { 10000000000LL, 20000000000LL, 30000000000LL, 40000000000LL };
        jlong back[4] = { 0 };
        (*env)->SetLongArrayRegion(env, a, 0, 4, seed);
        jlong *elems = (*env)->GetLongArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 11111111111LL;
        (*env)->ReleaseLongArrayElements(env, a, elems, 0);
        (*env)->GetLongArrayRegion(env, a, 0, 4, back);
        const jlong want[4] = { 11111111111LL, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 16;
        (*env)->DeleteLocalRef(env, a);
    }
    // Float: seed 1.5f, 2.5f, 3.5f, 4.5f -> pin, mutate element 0 to 9.5f, copy back
    {
        jfloatArray a = (*env)->NewFloatArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jfloat seed[4] = { 1.5f, 2.5f, 3.5f, 4.5f };
        jfloat back[4] = { 0 };
        (*env)->SetFloatArrayRegion(env, a, 0, 4, seed);
        jfloat *elems = (*env)->GetFloatArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 9.5f;
        (*env)->ReleaseFloatArrayElements(env, a, elems, 0);
        (*env)->GetFloatArrayRegion(env, a, 0, 4, back);
        const jfloat want[4] = { 9.5f, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 32;
        (*env)->DeleteLocalRef(env, a);
    }
    // Double: seed 1.25, 2.25, 3.25, 4.25 -> pin, mutate element 0 to 9.75, copy back
    {
        jdoubleArray a = (*env)->NewDoubleArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jdouble seed[4] = { 1.25, 2.25, 3.25, 4.25 };
        jdouble back[4] = { 0 };
        (*env)->SetDoubleArrayRegion(env, a, 0, 4, seed);
        jdouble *elems = (*env)->GetDoubleArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[0] = 9.75;
        (*env)->ReleaseDoubleArrayElements(env, a, elems, 0);
        (*env)->GetDoubleArrayRegion(env, a, 0, 4, back);
        const jdouble want[4] = { 9.75, seed[1], seed[2], seed[3] };
        // The read-back has to show exactly what the pinned buffer was told to become.
        if (memcmp(want, back, sizeof(want)) == 0) bits |= 64;
        (*env)->DeleteLocalRef(env, a);
    }
    // Abort round: the mutation must be DISCARDED by JNI_ABORT, so the array keeps its old values.
    {
        jintArray a = (*env)->NewIntArray(env, 4);
        if (!a) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            return (jint)(0xAD8000 | bits);
        }
        const jint seed[4] = { 100000, 200000, 300000, 400000 };
        jint back[4] = { 0 };
        (*env)->SetIntArrayRegion(env, a, 0, 4, seed);
        jint *elems = (*env)->GetIntArrayElements(env, a, &is_copy);
        if (!elems) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, a);
            return (jint)(0xAD8000 | bits);
        }
        elems[1] = 999999;
        (*env)->ReleaseIntArrayElements(env, a, elems, JNI_ABORT);
        (*env)->GetIntArrayRegion(env, a, 0, 4, back);
        if (back[0] == 100000 && back[1] == 200000 && back[2] == 300000 && back[3] == 400000) bits |= 0x80;
        (*env)->DeleteLocalRef(env, a);
    }
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return (jint)(0xAD8000 | bits); }
    return (jint)(0xAD8000 | bits);
}

// v4.83 fixture: one deterministic walk over the families added after the array work - array
// creation, object arrays, AllocObject, CallNonvirtual dispatch, the reflection bridge, the string
// length/critical entries and ExceptionCheck. Every section asserts a value the target should see,
// so a hook that changes behaviour fails the probe instead of silently "working".
// Returns 0xAD9000 | bits, one bit per section (0xAD91FF when everything held).
static jstring family_find_member(JNIEnv *env, jobjectArray members, jclass member_cls, const char *wanted) {
    if (!members || !member_cls) return NULL;
    jmethodID get_name = (*env)->GetMethodID(env, member_cls, "getName", "()Ljava/lang/String;");
    jsize len = (*env)->GetArrayLength(env, members);
    jstring found = NULL;
    for (jsize i = 0; i < len && !found; i++) {
        jobject member = (*env)->GetObjectArrayElement(env, members, i);
        if (!member) continue;
        jstring name = get_name ? (jstring)(*env)->CallObjectMethod(env, member, get_name) : NULL;
        if (name) {
            const char *chars = (*env)->GetStringUTFChars(env, name, NULL);
            if (chars && strcmp(chars, wanted) == 0) found = (jstring)member;   /* borrowed: caller deletes */
            if (chars) (*env)->ReleaseStringUTFChars(env, name, chars);
            (*env)->DeleteLocalRef(env, name);
        }
        if (!found) (*env)->DeleteLocalRef(env, member);
    }
    return found;
}

// The V form needs a va_list, which only a variadic helper can build.
static jstring family_call_nv_v(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, ...) {
    va_list ap;
    va_start(ap, mid);
    jstring result = (jstring)(*env)->CallNonvirtualObjectMethodV(env, obj, clazz, mid, ap);
    va_end(ap);
    return result;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniFamilyProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jint bits = 0;

    // 1) the eight primitive array constructors plus GetArrayLength
    {
        jsize len = 4;
        jarray arrays[8];
        arrays[0] = (*env)->NewBooleanArray(env, len);
        arrays[1] = (*env)->NewByteArray(env, len);
        arrays[2] = (*env)->NewCharArray(env, len);
        arrays[3] = (*env)->NewShortArray(env, len);
        arrays[4] = (*env)->NewIntArray(env, len);
        arrays[5] = (*env)->NewLongArray(env, len);
        arrays[6] = (*env)->NewFloatArray(env, len);
        arrays[7] = (*env)->NewDoubleArray(env, len);
        int all = 1;
        for (int i = 0; i < 8; i++) if (!arrays[i]) all = 0;
        if (all) bits |= 1;
        if (arrays[4] && (*env)->GetArrayLength(env, arrays[4]) == len) bits |= 4;
        for (int i = 0; i < 8; i++) if (arrays[i]) (*env)->DeleteLocalRef(env, arrays[i]);
    }

    // 2) NewObjectArray + Get/SetObjectArrayElement round trip
    {
        jclass string_cls = (*env)->FindClass(env, "java/lang/String");
        jobjectArray arr = string_cls ? (*env)->NewObjectArray(env, 3, string_cls, NULL) : NULL;
        if (arr) {
            jstring value = (*env)->NewStringUTF(env, "ADH");
            if (value) {
                (*env)->SetObjectArrayElement(env, arr, 1, value);
                jstring back = (jstring)(*env)->GetObjectArrayElement(env, arr, 1);
                if (back) {
                    const char *chars = (*env)->GetStringUTFChars(env, back, NULL);
                    if (chars) {
                        if (strcmp(chars, "ADH") == 0) bits |= 2;
                        (*env)->ReleaseStringUTFChars(env, back, chars);
                    }
                    (*env)->DeleteLocalRef(env, back);
                }
                if ((*env)->GetObjectArrayElement(env, arr, 0) == NULL) bits |= 2;   /* null entry is legal */
                (*env)->DeleteLocalRef(env, value);
            }
            (*env)->DeleteLocalRef(env, arr);
        }
        if (string_cls) (*env)->DeleteLocalRef(env, string_cls);
    }

    // 3) AllocObject: allocate without running a constructor
    {
        jclass target = (*env)->FindClass(env, "com/adh/sandbox/JniCallTarget");
        jobject obj = target ? (*env)->AllocObject(env, target) : NULL;
        if (obj) { bits |= 8; (*env)->DeleteLocalRef(env, obj); }
        if (target) (*env)->DeleteLocalRef(env, target);
    }

    // 4) CallNonvirtual: the BASE implementation must run even though the child overrides it
    {
        jclass child = (*env)->FindClass(env, "com/adh/sandbox/JniNonvirtualChild");
        jclass base = child ? (*env)->GetSuperclass(env, child) : NULL;
        jmethodID ctor = child ? (*env)->GetMethodID(env, child, "<init>", "()V") : NULL;
        jobject obj = (child && ctor) ? (*env)->NewObjectA(env, child, ctor, NULL) : NULL;
        jmethodID describe = base ? (*env)->GetMethodID(env, base, "describe", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
        if (obj && describe) {
            jstring tag = (*env)->NewStringUTF(env, "t");
            // All three JNI forms: a C caller (varargs), the V entry and the A entry. Only the
            // varargs one is what C++ inlines and what C often emits, so each needs its own check.
            jvalue jargs[1];
            jargs[0].l = tag;
            jstring outs[3];
            outs[0] = (jstring)(*env)->CallNonvirtualObjectMethod(env, obj, base, describe, tag);
            outs[1] = family_call_nv_v(env, obj, base, describe, tag);
            outs[2] = (jstring)(*env)->CallNonvirtualObjectMethodA(env, obj, base, describe, jargs);
            int all_base = 1;
            for (int i = 0; i < 3; i++) {
                if (!outs[i]) { all_base = 0; continue; }
                const char *chars = (*env)->GetStringUTFChars(env, outs[i], NULL);
                if (!chars || strcmp(chars, "base:t") != 0) all_base = 0;   /* "child:t" = dispatch broke */
                if (chars) (*env)->ReleaseStringUTFChars(env, outs[i], chars);
                (*env)->DeleteLocalRef(env, outs[i]);
            }
            if (all_base) bits |= 16;
            if (tag) (*env)->DeleteLocalRef(env, tag);
        }
        if (obj) (*env)->DeleteLocalRef(env, obj);
        if (base) (*env)->DeleteLocalRef(env, base);
        if (child) (*env)->DeleteLocalRef(env, child);
    }

    // 5) the reflection bridge: From* must yield the ID the JNI lookup gives, To* must come back named
    {
        jclass target = (*env)->FindClass(env, "com/adh/sandbox/JniCallTarget");
        jclass class_cls = target ? (*env)->GetObjectClass(env, (jobject)target) : NULL;
        jmethodID get_methods = class_cls ? (*env)->GetMethodID(env, class_cls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;") : NULL;
        jmethodID get_fields = class_cls ? (*env)->GetMethodID(env, class_cls, "getDeclaredFields", "()[Ljava/lang/reflect/Field;") : NULL;
        if (target && get_methods && get_fields) {
            jobjectArray methods = (jobjectArray)(*env)->CallObjectMethod(env, target, get_methods);
            jclass method_cls = (*env)->FindClass(env, "java/lang/reflect/Method");
            jobject reflected = family_find_member(env, methods, method_cls, "combine");
            if (reflected) {
                jmethodID mid = (*env)->GetMethodID(env, target, "combine", "(Ljava/lang/String;I)Ljava/lang/String;");
                jmethodID from = (*env)->FromReflectedMethod(env, reflected);
                if (mid && from == mid) bits |= 32;
                jobject back = mid ? (*env)->ToReflectedMethod(env, target, mid, JNI_FALSE) : NULL;
                if (back) {
                    jclass back_cls = (*env)->GetObjectClass(env, back);
                    jmethodID get_name = (*env)->GetMethodID(env, back_cls, "getName", "()Ljava/lang/String;");
                    jstring name = get_name ? (jstring)(*env)->CallObjectMethod(env, back, get_name) : NULL;
                    if (name) {
                        const char *chars = (*env)->GetStringUTFChars(env, name, NULL);
                        if (chars) {
                            if (strcmp(chars, "combine") == 0) bits |= 32;
                            (*env)->ReleaseStringUTFChars(env, name, chars);
                        }
                        (*env)->DeleteLocalRef(env, name);
                    }
                    (*env)->DeleteLocalRef(env, back_cls);
                    (*env)->DeleteLocalRef(env, back);
                }
                (*env)->DeleteLocalRef(env, reflected);
            }
            jobjectArray fields = (jobjectArray)(*env)->CallObjectMethod(env, target, get_fields);
            jclass field_cls = (*env)->FindClass(env, "java/lang/reflect/Field");
            jobject reflected_field = family_find_member(env, fields, field_cls, "counter");
            if (reflected_field) {
                jfieldID fid = (*env)->GetFieldID(env, target, "counter", "I");
                jfieldID from = (*env)->FromReflectedField(env, reflected_field);
                if (fid && from == fid) bits |= 32;
                jobject back = fid ? (*env)->ToReflectedField(env, target, fid, JNI_FALSE) : NULL;
                if (back) {
                    jclass back_cls = (*env)->GetObjectClass(env, back);
                    jmethodID get_name = (*env)->GetMethodID(env, back_cls, "getName", "()Ljava/lang/String;");
                    jstring name = get_name ? (jstring)(*env)->CallObjectMethod(env, back, get_name) : NULL;
                    if (name) {
                        const char *chars = (*env)->GetStringUTFChars(env, name, NULL);
                        if (chars) {
                            if (strcmp(chars, "counter") == 0) bits |= 32;
                            (*env)->ReleaseStringUTFChars(env, name, chars);
                        }
                        (*env)->DeleteLocalRef(env, name);
                    }
                    (*env)->DeleteLocalRef(env, back_cls);
                    (*env)->DeleteLocalRef(env, back);
                }
                (*env)->DeleteLocalRef(env, reflected_field);
            }
            if (method_cls) (*env)->DeleteLocalRef(env, method_cls);
            if (field_cls) (*env)->DeleteLocalRef(env, field_cls);
            if (methods) (*env)->DeleteLocalRef(env, methods);
            if (fields) (*env)->DeleteLocalRef(env, fields);
        }
        if (class_cls) (*env)->DeleteLocalRef(env, class_cls);
        if (target) (*env)->DeleteLocalRef(env, target);
    }

    // 6) strings: NewString, the two length queries, the critical pair and the UTF-8 release
    {
        const jchar text[5] = { 'A', 'D', 'H', '4', '2' };
        jstring s = (*env)->NewString(env, text, 5);
        if (s) {
            if ((*env)->GetStringLength(env, s) == 5 && (*env)->GetStringUTFLength(env, s) == 5) bits |= 64;
            jboolean is_copy = JNI_FALSE;
            const jchar *crit = (*env)->GetStringCritical(env, s, &is_copy);
            if (crit) {
                if (crit[0] == 'A' && crit[4] == '2') bits |= 128;
                (*env)->ReleaseStringCritical(env, s, crit);
            }
            const char *utf = (*env)->GetStringUTFChars(env, s, NULL);
            if (utf) {
                if (strcmp(utf, "ADH42") == 0) bits |= 128;
                (*env)->ReleaseStringUTFChars(env, s, utf);
            }
            (*env)->DeleteLocalRef(env, s);
        }
    }

    // 7) ExceptionCheck with nothing pending must say so (the entry is hooked, the answer must not change)
    if ((*env)->ExceptionCheck(env) == JNI_FALSE) bits |= 256;

    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return (jint)(0xAD9000 | bits); }
    return (jint)(0xAD9000 | bits);
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniFieldProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int calls = 0;
    jclass holder = (*env)->FindClass(env, "com/adh/sandbox/HeapProbe");
    if (!holder) { (*env)->ExceptionClear(env); return 0; }
    jfieldID sConfig = (*env)->GetStaticFieldID(env, holder, "sConfig", "Lcom/adh/sandbox/HeapProbe$Config;");
    if (!sConfig) { (*env)->ExceptionClear(env); return 0; }
    jobject cfg = (*env)->GetStaticObjectField(env, holder, sConfig);
    calls++;
    if (!cfg) { (*env)->ExceptionClear(env); return calls; }
    jclass cfg_cls = (*env)->GetObjectClass(env, cfg);
    jfieldID counter = (*env)->GetFieldID(env, cfg_cls, "counter", "I");
    jfieldID flag = (*env)->GetFieldID(env, cfg_cls, "flag", "Z");
    jfieldID label = (*env)->GetFieldID(env, cfg_cls, "label", "Ljava/lang/String;");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (counter) {
        jint v = (*env)->GetIntField(env, cfg, counter); calls++;
        (*env)->SetIntField(env, cfg, counter, v); calls++;
    }
    if (flag) {
        jboolean b = (*env)->GetBooleanField(env, cfg, flag); calls++;
        (*env)->SetBooleanField(env, cfg, flag, b); calls++;
    }
    if (label) {
        jobject s = (*env)->GetObjectField(env, cfg, label); calls++;
        if (s) { (*env)->SetObjectField(env, cfg, label, s); calls++; }
    }
    jfieldID sCounter = (*env)->GetStaticFieldID(env, holder, "sCounter", "I");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (sCounter) {
        jint v = (*env)->GetStaticIntField(env, holder, sCounter); calls++;
        (*env)->SetStaticIntField(env, holder, sCounter, v); calls++;
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return (jint)calls;
}

// v4.95 fixture for the native_call watchdog: a plain (non-JNI) function that takes its time, so
// the agent has to answer timedOut and stay usable while this is still running.
void adh_slow_leaf(void) {
    sleep(30);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    return JNI_VERSION_1_6;
}
// RegisterNatives probe: the agent's jni_hook intercepts this call and emits a
// JNI_NATIVE event; jniRegisteredProbe is then callable through ordinary JNI reflection.
static jint adh_jni_registered_probe_impl(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return 0xAD11;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniRegisterProbe(JNIEnv *env, jclass clazz) {
    JNINativeMethod method = {
        (char *)"jniRegisteredProbe",
        (char *)"()I",
        (void *)adh_jni_registered_probe_impl,
    };
    return (*env)->RegisterNatives(env, clazz, &method, 1);
}
// JNIEnv function-table probe: one call drives every table entry the agent can hook, so a
// single trigger yields one JNI_ENV event per entry. Returns 0xAD0000 | strlen(marker).
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniEnvProbe(JNIEnv *env, jclass clazz) {
    jclass detection = (*env)->FindClass(env, "com/adh/sandbox/Detection");
    if (!detection) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return -1; }
    jmethodID load = (*env)->GetMethodID(env, detection, "load", "()V");
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); load = NULL; }
    jmethodID value = (*env)->GetStaticMethodID(env, clazz, "jniEnvValue", "()Ljava/lang/String;");
    if (!value) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return -2; }
    jstring made = (*env)->NewStringUTF(env, "ADH_JNI_ENV_MARKER");
    if (!made) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return -3; }
    const char *chars = (*env)->GetStringUTFChars(env, made, NULL);
    jint out = -4;
    if (chars) {
        out = (jint)(0xAD0000u | (unsigned)strlen(chars));
        (*env)->ReleaseStringUTFChars(env, made, chars);
    }
    (*env)->DeleteLocalRef(env, made);
    (void)load;
    return out;
}
// v4.19 fixture for the field-ID / byte-array JNIEnv table hooks: one call performs
// GetFieldID, GetStaticFieldID, SetByteArrayRegion and GetByteArrayElements.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniEnvArrayProbe(JNIEnv *env, jclass clazz) {
    jclass holder = (*env)->FindClass(env, "com/adh/sandbox/JniEnvHolder");
    if (!holder) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return -1; }
    jfieldID instance_field = (*env)->GetFieldID(env, holder, "marker", "I");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    jfieldID static_field = (*env)->GetStaticFieldID(env, clazz, "jniEnvStaticField", "I");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    jbyteArray arr = (*env)->NewByteArray(env, 8);
    if (!arr) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return -2; }
    const jbyte data[8] = { 0x41, 0x44, 0x48, 0x02, 0x03, 0x04, 0x05, 0x06 };
    (*env)->SetByteArrayRegion(env, arr, 0, 8, data);
    jbyte *elems = (*env)->GetByteArrayElements(env, arr, NULL);
    int ok = elems != NULL && elems[0] == 0x41 && elems[3] == 0x02 && elems[7] == 0x06;
    if (elems) (*env)->ReleaseByteArrayElements(env, arr, elems, JNI_ABORT);
    (*env)->DeleteLocalRef(env, arr);
    if (!instance_field || !static_field || !ok) return -3;
    return 0xAD1008;   // = 0xAD1000 + 8 array bytes
}
// v4.20 invariant fixture: the JNIEnv table hooks must not change what the target observes.
// Bit 1: a failed GetMethodID still leaves NoSuchMethodError pending. Bit 4: a failed
// GetStaticFieldID still leaves NoSuchFieldError pending. Both are legal JNI (a *failed*
// lookup returns NULL and throws); calling an arbitrary JNI function while an exception is
// already pending is NOT legal — CheckJNI aborts the process (verified on device) — so the
// fixture deliberately stays inside the legal subset.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniEnvExceptionProbe(JNIEnv *env, jclass clazz) {
    jint bits = 0;
    jmethodID missing = (*env)->GetMethodID(env, clazz, "adhNoSuchMethod", "()V");
    if (missing == NULL && (*env)->ExceptionCheck(env)) bits |= 1;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    jfieldID bad = (*env)->GetStaticFieldID(env, clazz, "adhNoSuchField", "I");
    if (bad == NULL && (*env)->ExceptionCheck(env)) bits |= 4;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return bits;
}
// v4.24 fixture for the JNIEnv Call*Method / NewObject hooks. The probe drives all three JNI
// forms on purpose: A (jvalue array), varargs (C caller) and NewObjectA. Returns a bitmask
// 0xAD3000 | bits so a verifier can assert the calls actually produced the expected values.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniCallProbe(JNIEnv *env, jclass clazz) {
    jint bits = 0;
    jclass target = (*env)->FindClass(env, "com/adh/sandbox/JniCallTarget");
    jclass statics = (*env)->FindClass(env, "com/adh/sandbox/JniCallStatics");
    if (!target || !statics) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0xAD3000; }
    jmethodID ctor = (*env)->GetMethodID(env, target, "<init>", "()V");
    jobject obj = ctor ? (*env)->NewObjectA(env, target, ctor, NULL) : NULL;
    jmethodID combine = (*env)->GetMethodID(env, target, "combine", "(Ljava/lang/String;I)Ljava/lang/String;");
    jmethodID counter = (*env)->GetMethodID(env, target, "counterValue", "()I");
    jmethodID note = (*env)->GetMethodID(env, target, "note", "(Ljava/lang/String;)V");
    jmethodID static_combine = (*env)->GetStaticMethodID(env, statics, "staticCombine", "(Ljava/lang/String;I)Ljava/lang/String;");
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD3000; }
    jstring label = (*env)->NewStringUTF(env, "ADH_CALL");

    // A form: (String, int) -> String
    jvalue args[2];
    args[0].l = label;
    args[1].i = 7;
    jstring combined = (obj && combine) ? (jstring)(*env)->CallObjectMethodA(env, obj, combine, args) : NULL;
    if (combined) {
        const char *chars = (*env)->GetStringUTFChars(env, combined, NULL);
        if (chars) {
            if (strcmp(chars, "ADH_CALL:7") == 0) bits |= 1;
            (*env)->ReleaseStringUTFChars(env, combined, chars);
        }
        (*env)->DeleteLocalRef(env, combined);
    }
    // A form: no-argument int
    jint n = (obj && counter) ? (*env)->CallIntMethodA(env, obj, counter, NULL) : -1;
    if (n == 41) bits |= 2;
    // varargs form: void with one String (C caller hits the varargs table entry)
    if (obj && note) (*env)->CallVoidMethod(env, obj, note, label);
    jint after = (obj && counter) ? (*env)->CallIntMethodA(env, obj, counter, NULL) : -1;
    if (after == 49) bits |= 8;   // 41 + strlen("ADH_CALL")
    // varargs form: static (String, int) -> String
    jstring static_result = static_combine
        ? (jstring)(*env)->CallStaticObjectMethod(env, statics, static_combine, label, 9) : NULL;
    if (static_result) {
        const char *chars = (*env)->GetStringUTFChars(env, static_result, NULL);
        if (chars) {
            if (strcmp(chars, "S:ADH_CALL:9") == 0) bits |= 4;
            (*env)->ReleaseStringUTFChars(env, static_result, chars);
        }
        (*env)->DeleteLocalRef(env, static_result);
    }
    if (label) (*env)->DeleteLocalRef(env, label);
    if (obj) (*env)->DeleteLocalRef(env, obj);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD3000; }
    return (jint)(0xAD3000 | bits);
}
// v4.26 fixture for the byte-array writeback hooks: fill a byte[], rewrite it in place through
// Get/ReleaseByteArrayElements (copy-back mode) and again through the primitive-array critical
// pair, reading the result back with GetByteArrayRegion each time. Returns
// 0xAD4000 | bits so the verifier can prove both writebacks really landed.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniArrayWriteProbe(JNIEnv *env, jclass clazz) {
    jint bits = 0;
    jbyteArray arr = (*env)->NewByteArray(env, 8);
    if (!arr) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0xAD4000; }
    const jbyte seed[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    (*env)->SetByteArrayRegion(env, arr, 0, 8, seed);

    // 1) in-place rewrite through GetByteArrayElements -> ReleaseByteArrayElements(mode 0)
    jbyte *elems = (*env)->GetByteArrayElements(env, arr, NULL);
    if (elems) {
        for (int i = 0; i < 8; i++) elems[i] = (jbyte)(0xA0 + i);
        (*env)->ReleaseByteArrayElements(env, arr, elems, 0);
    }
    jbyte readback[8] = { 0 };
    (*env)->GetByteArrayRegion(env, arr, 0, 8, readback);
    if (readback[0] == (jbyte)0xA0 && readback[7] == (jbyte)0xA7) bits |= 1;

    // 2) in-place rewrite inside a primitive-array critical section
    jbyte *crit = (jbyte *)(*env)->GetPrimitiveArrayCritical(env, arr, NULL);
    if (crit) {
        for (int i = 0; i < 8; i++) crit[i] = (jbyte)(0xB0 + i);
        (*env)->ReleasePrimitiveArrayCritical(env, arr, crit, 0);
    }
    jbyte readback2[8] = { 0 };
    (*env)->GetByteArrayRegion(env, arr, 0, 8, readback2);
    if (readback2[0] == (jbyte)0xB0 && readback2[7] == (jbyte)0xB7) bits |= 2;

    (*env)->DeleteLocalRef(env, arr);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD4000; }
    return (jint)(0xAD4000 | bits);
}
// v4.27 fixture: exercise every remaining Call* return type (instance + static) through the
// A and varargs forms and verify the values. Returns 0xAD5000 | bits.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniCallTypesProbe(JNIEnv *env, jclass clazz) {
    jint bits = 0;
    jclass target = (*env)->FindClass(env, "com/adh/sandbox/JniCallTarget");
    jclass statics = (*env)->FindClass(env, "com/adh/sandbox/JniCallStatics");
    if (!target || !statics) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0xAD5000; }
    jmethodID ctor = (*env)->GetMethodID(env, target, "<init>", "()V");
    jobject obj = ctor ? (*env)->NewObject(env, target, ctor) : NULL;
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD5000; }

    jmethodID m_flag = (*env)->GetMethodID(env, target, "flag", "()Z");
    jmethodID m_byte = (*env)->GetMethodID(env, target, "byteValue", "()B");
    jmethodID m_char = (*env)->GetMethodID(env, target, "charValue", "()C");
    jmethodID m_short = (*env)->GetMethodID(env, target, "shortValue", "()S");
    jmethodID m_long = (*env)->GetMethodID(env, target, "longValue", "()J");
    jmethodID m_float = (*env)->GetMethodID(env, target, "floatValue", "()F");
    jmethodID m_double = (*env)->GetMethodID(env, target, "doubleValue", "()D");
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD5000; }

    if (obj && m_flag && (*env)->CallBooleanMethodA(env, obj, m_flag, NULL) == JNI_TRUE) bits |= 1;
    if (obj && m_byte && (*env)->CallByteMethodA(env, obj, m_byte, NULL) == (jbyte)0x2A) bits |= 2;
    if (obj && m_char && (*env)->CallCharMethodA(env, obj, m_char, NULL) == (jchar)'Z') bits |= 4;
    if (obj && m_short && (*env)->CallShortMethodA(env, obj, m_short, NULL) == (jshort)1234) bits |= 8;
    if (obj && m_long && (*env)->CallLongMethodA(env, obj, m_long, NULL) == 1234567890123LL) bits |= 16;
    if (obj && m_float && (*env)->CallFloatMethodA(env, obj, m_float, NULL) == 2.5f) bits |= 32;
    if (obj && m_double && (*env)->CallDoubleMethodA(env, obj, m_double, NULL) == 1.25) bits |= 64;

    jmethodID s_flag = (*env)->GetStaticMethodID(env, statics, "staticFlag", "()Z");
    jmethodID s_byte = (*env)->GetStaticMethodID(env, statics, "staticByte", "()B");
    jmethodID s_char = (*env)->GetStaticMethodID(env, statics, "staticChar", "()C");
    jmethodID s_short = (*env)->GetStaticMethodID(env, statics, "staticShort", "()S");
    jmethodID s_long = (*env)->GetStaticMethodID(env, statics, "staticLong", "()J");
    jmethodID s_float = (*env)->GetStaticMethodID(env, statics, "staticFloat", "()F");
    jmethodID s_double = (*env)->GetStaticMethodID(env, statics, "staticDouble", "()D");
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD5000 | bits; }
    if (s_flag && (*env)->CallStaticBooleanMethod(env, statics, s_flag) == JNI_TRUE) bits |= 256;
    if (s_byte && (*env)->CallStaticByteMethod(env, statics, s_byte) == (jbyte)0x37) bits |= 512;
    if (s_char && (*env)->CallStaticCharMethod(env, statics, s_char) == (jchar)'Q') bits |= 1024;
    if (s_short && (*env)->CallStaticShortMethod(env, statics, s_short) == (jshort)4321) bits |= 2048;
    if (s_long && (*env)->CallStaticLongMethod(env, statics, s_long) == 9876543210LL) bits |= 4096;
    if (s_float && (*env)->CallStaticFloatMethod(env, statics, s_float) == 3.5f) bits |= 8192;
    if (s_double && (*env)->CallStaticDoubleMethod(env, statics, s_double) == 6.25) bits |= 16384;

    if (obj) (*env)->DeleteLocalRef(env, obj);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD5000 | bits; }
    return (jint)(0xAD5000 | bits);
}
// v4.28 fixture: allocate JniCtorTarget(21) via NewObjectA and read totalValue(). A working
// constructor hook must still let the object exist and keep total = 42 (0xAD6001).
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_jniCtorProbe(JNIEnv *env, jclass clazz) {
    jclass target = (*env)->FindClass(env, "com/adh/sandbox/JniCtorTarget");
    if (!target) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0xAD6000; }
    jmethodID ctor = (*env)->GetMethodID(env, target, "<init>", "(I)V");
    jvalue seed;
    seed.i = 21;
    jobject obj = ctor ? (*env)->NewObjectA(env, target, ctor, &seed) : NULL;
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD6000; }
    if (!obj) return 0xAD6000;
    jmethodID total = (*env)->GetMethodID(env, target, "totalValue", "()I");
    jint value = total ? (*env)->CallIntMethodA(env, obj, total, NULL) : -1;
    (*env)->DeleteLocalRef(env, obj);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return 0xAD6000; }
    return (jint)(0xAD6000 | (value == 42 ? 1 : 0));
}
const volatile struct adh_vt adh_vtable = { adh_add_target, adh_sub_target };

// ---- v4.36 fixture A: object dispatch ---------------------------------------------------
// Same memory shape a C++ virtual call produces: the object holds a vptr, the vtable lives in
// .data.rel.ro (read-only after relocation), and the call is ldr vptr / ldr slot / blr. The probe
// takes the address through the OBJECT (not through a global table), so this covers the real
// "obj->method()" form rather than only a named table.
struct adh_obj;
struct adh_obj_vt {
    long (*add)(struct adh_obj *self, long a, long b);
    long (*sub)(struct adh_obj *self, long a, long b);
};
struct adh_obj { const volatile struct adh_obj_vt *vptr; };

__attribute__((noinline, used, visibility("default")))
long adh_obj_add(struct adh_obj *self, long a, long b) { (void)self; return (a + b) * 2; }
__attribute__((noinline, used, visibility("default")))
long adh_obj_sub(struct adh_obj *self, long a, long b) { (void)self; return a - b; }

const volatile struct adh_obj_vt adh_obj_vtable = { adh_obj_add, adh_obj_sub };
struct adh_obj adh_obj_instance = { &adh_obj_vtable };

__attribute__((noinline, used, visibility("default")))
long adh_obj_call(void) {
    struct adh_obj *o = &adh_obj_instance;
    long (*fn)(struct adh_obj *, long, long) = o->vptr->add;   // vptr load + slot load + blr
    return fn(o, 20, 22);
}

// ---- v4.36 fixture B: writable function pointer ------------------------------------------
// The slot lives in .data (writable), which the backend skips unless slotsWritable:true is passed:
// a writable word that merely equals a target is as likely to be a constant as a call target.
// file-local on purpose: the ONLY reference to this function is the writable slot below, so the
// module gets no read-only GOT/vtable entry for it and the default (read-only-only) scan must find
// nothing - which is what the slotsWritable opt-in is for. The probe hands the address to the Host.
__attribute__((noinline, used))
static long adh_cb_target(long a, long b) { return a * 100 + b; }

long (*volatile adh_cb_slot)(long, long) = adh_cb_target;      // .data, writable

__attribute__((noinline, used, visibility("default")))
long adh_cb_call(void) { return adh_cb_slot(3, 4); }

__attribute__((noinline, used, visibility("default")))
long adh_slot_probe(void) {
    long (*fn)(long, long) = adh_vtable.add;   // indirect: the address comes from the table
    return fn(20, 22);
}

// v4.31 fixture for FP register capture and FP active calls: (float a, double b, int c) -> a*b+c.
// Call it with f:2.5 d:4 1 to get 11.0 back in d0.
__attribute__((noinline, used, visibility("default")))
double adh_fp_target(float a, double b, int c) {
    return (double)a * b + (double)c;
}
// Same shape but returning float, to prove the s0 (32-bit) return path: f:2.5 d:4 1 -> 11.0f.
__attribute__((noinline, used, visibility("default")))
float adh_fp_target_f(float a, double b, int c) {
    return (float)((double)a * b + (double)c);
}
// Bank/order probes that cannot cancel out: both calls must return 291.0, which only holds when
// the FIRST typed argument lands in the first FP register whatever its width (f: then d:, d: then f:).
__attribute__((noinline, used, visibility("default")))
double adh_fp_order_fd(float a, double b, int c) {
    return (double)a * 100.0 + b * 10.0 + (double)c;
}
__attribute__((noinline, used, visibility("default")))
double adh_fp_order_df(double a, float b, int c) {
    return a * 100.0 + (double)b * 10.0 + (double)c;
}
// f:0.1 must be rounded to float32 before it is used: 0.1f*1000+2 = 102.00000149011612, while
// storing the double 0.1 would give 102.00000000000001 - 1.5e-6 apart, far outside the assertion
// epsilon, so this pins the width (not just the register) of an "f:" argument.
__attribute__((noinline, used, visibility("default")))
double adh_fp_mix(float a, double b) {
    return (double)a * 1000.0 + b;
}
// Deterministic NaN return, so the "non-finite result is null, not invalid JSON" path is testable.
__attribute__((noinline, used, visibility("default")))
double adh_fp_nan(double seed) {
    volatile double zero = 0.0;
    return (seed - seed) + zero / zero;
}
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_run(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int flags = 0;

    // 1) anti-debug: ptrace(PTRACE_TRACEME) — classic "only one tracer" defense
    long pr = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (pr == 0) flags |= 1;

    // 2) root: check for su binaries
    if (access("/system/xbin/su", F_OK) == 0) flags |= 2;
    if (access("/system/bin/su", F_OK) == 0) flags |= 4;

    // 3) debugger via /proc/self/status TracerPid
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[4096]; ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = 0; char *t = strstr(buf, "TracerPid:"); if (t && atoi(t + 10) != 0) flags |= 8; }
        close(fd);
    }

    // 4) debuggable property
    char prop[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.debuggable", prop);
    if (prop[0] == '1') flags |= 16;

    // keep the crypto-constant tables + direct-syscall from being stripped
    volatile unsigned int sink = ADH_AES_SBOX[flags & 0xff] ^ (unsigned char)ADH_B64_ALPHABET[flags & 0x3f];
    flags |= (sink & 0);
    if (adh_direct_gettid() < 0) flags |= 0x100;   // reference the svc site

    __android_log_print(ANDROID_LOG_INFO, TAG, "detections ran: ptrace=%ld debuggable=%s flags=0x%x", pr, prop, flags);
    return flags;
}

// ---- v4.32 anti-hook self-audit ---------------------------------------------------------
// What a hardened app can see about an injected hook framework WITHOUT trusting it: this fixture
// inspects its own address space and its own code bytes instead of asking the tool anything.
//   bit0  an executable mapping with no path (what an anonymous trampoline pool looks like)
//   bit1  adh_add_target's prologue differs from the bytes captured when this library loaded
//   bit2  an executable mapping whose path contains "agent" (a module injected by name)
//   bit3  adh_add_target's first instruction branches outside its own module mapping
// The baseline is captured in a constructor, i.e. before anything of ours runs, which is exactly
// how a real app would snapshot its own code.
// 24 bytes = the inline backend's restore window, so "restored" cannot be a 16-byte illusion.
static unsigned char g_anti_prologue[24];
static int g_anti_baseline_ok;

__attribute__((constructor)) static void adh_anti_capture_baseline(void) {
    memcpy(g_anti_prologue, (const void *)(uintptr_t)adh_add_target, sizeof(g_anti_prologue));
    g_anti_baseline_ok = 1;
}

// Path + exec flag of the mapping containing addr, straight from /proc/self/maps.
static int adh_anti_mapping_of(unsigned long long addr, char *path, int path_size, int *is_exec) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long start = 0, end = 0;
        char perms[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
        if (addr < start || addr >= end) continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        // The path is the last whitespace-separated field; offsets/dev/inode may be absent for
        // special mappings, so take everything after the 5th field when it exists.
        char *q = line;
        for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
        if (q) { snprintf(path, (size_t)path_size, "%s", q); }
        else path[0] = 0;
        if (is_exec) *is_exec = perms[2] == 'x';
        found = 1;
        break;
    }
    fclose(m);
    return found;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_objCall(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)adh_obj_call();
}

JNIEXPORT jlong JNICALL Java_com_adh_sandbox_Detection_objVtableAddress(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jlong)(uintptr_t)&adh_obj_vtable;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_cbCall(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)adh_cb_call();
}

JNIEXPORT jlong JNICALL Java_com_adh_sandbox_Detection_cbTargetAddress(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jlong)(uintptr_t)adh_cb_target;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_slotProbe(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)adh_slot_probe();
}

JNIEXPORT jlong JNICALL Java_com_adh_sandbox_Detection_vtableAddress(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jlong)(uintptr_t)&adh_vtable;
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_siteProbe(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)adh_site_probe();
}

JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_siteProbeBl(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return (jint)adh_site_probe_bl();
}

JNIEXPORT jstring JNICALL Java_com_adh_sandbox_Detection_antiHookProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int anon_exec = 0, agent_named_exec = 0, memfd_exec = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    int maps_read_ok = m != NULL;
    if (m) {
        char line[512];
        while (fgets(line, sizeof(line), m)) {
            unsigned long long start = 0, end = 0;
            char perms[8] = "";
            if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
            if (perms[2] != 'x') continue;
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            char *q = line;
            for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
            if (!q || !*q) { anon_exec++; continue; }
            if (strstr(q, "agent")) agent_named_exec++;
            if (strstr(q, "memfd")) memfd_exec++;
        }
        fclose(m);
    }

    unsigned char now[24];
    memcpy(now, (const void *)(uintptr_t)adh_add_target, sizeof(now));
    int prologue_differs = g_anti_baseline_ok && memcmp(now, g_anti_prologue, sizeof(now)) != 0;

    // arm64: is the first instruction an unconditional B, and where does it go?
    unsigned int insn = 0;
    memcpy(&insn, (const void *)(uintptr_t)adh_add_target, sizeof(insn));
    int entry_branches_outside = 0;
    unsigned long long branch_target = 0;
    char branch_path[256] = "";
    char own_path[256] = "";
    int own_exec = 0;
    adh_anti_mapping_of((unsigned long long)(uintptr_t)adh_add_target, own_path, sizeof(own_path), &own_exec);
    if ((insn & 0xFC000000u) == 0x14000000u) {
        int imm26 = (int)(insn & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 -= 0x04000000;
        branch_target = (unsigned long long)(uintptr_t)adh_add_target + (unsigned long long)(long long)imm26 * 4ull;
        int bexec = 0;
        if (!adh_anti_mapping_of(branch_target, branch_path, sizeof(branch_path), &bexec)) {
            entry_branches_outside = 1;              // branches somewhere unmapped/anon
        } else if (!bexec || strcmp(branch_path, own_path) != 0) {
            entry_branches_outside = 1;              // branches into another (or non-exec) mapping
        }
    }

    int bits = 0;
    if (anon_exec > 0) bits |= 1;
    if (prologue_differs) bits |= 2;
    if (agent_named_exec > 0) bits |= 4;
    if (entry_branches_outside) bits |= 8;

    char out[1024];
    snprintf(out, sizeof(out),
             "{\"bits\":%d,\"anonExec\":%d,\"memfdExec\":%d,\"agentNamedExec\":%d,"
             "\"prologueDiffers\":%s,\"entryBranchesOutside\":%s,\"firstInsn\":\"0x%08x\","
             "\"branchTarget\":\"0x%llx\",\"branchTargetPath\":\"%s\",\"ownPath\":\"%s\","
             "\"mapsReadOk\":%s,\"prologueBytes\":%d,\"baselineCaptured\":%s}",
             bits, anon_exec, memfd_exec, agent_named_exec,
             prologue_differs ? "true" : "false", entry_branches_outside ? "true" : "false",
             insn, branch_target, branch_path, own_path,
             maps_read_ok ? "true" : "false", (int)sizeof(now),
             g_anti_baseline_ok ? "true" : "false");
    return (*env)->NewStringUTF(env, out);
}

// libadhdetect.so — a mock "anti-analysis" native lib for the sandbox.
// Mimics what evasive/gray-market apps do in native code (to dodge Java hooks):
// debugger detection (ptrace TRACEME + /proc TracerPid), root detection (su paths),
// and property checks (ro.debuggable). The IDH agent GOT-hooks these libc calls to
// OBSERVE (module V) — and can neutralize (module S). Deterministic for verify.

#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
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

// Deterministic active-call target: (a + b) * 2, exported for native_call acceptance.
__attribute__((noinline, used, visibility("default")))
long adh_add_target(long a, long b) {
    return (a + b) * 2;
}
// Deterministic trigger for the generic native-hook manager: an explicit JNI call into
// adh_trace_target() lets the acceptance script install an inline/GOT hook and observe it.
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_nativeHookProbe(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return adh_trace_target();
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

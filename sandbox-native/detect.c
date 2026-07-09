// libidhdetect.so — a mock "anti-analysis" native lib for the sandbox.
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

#define TAG "IDH_DETECT"

JNIEXPORT jint JNICALL Java_com_idh_sandbox_Detection_run(JNIEnv *env, jclass clazz) {
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

    __android_log_print(ANDROID_LOG_INFO, TAG, "detections ran: ptrace=%ld debuggable=%s flags=0x%x", pr, prop, flags);
    return flags;
}

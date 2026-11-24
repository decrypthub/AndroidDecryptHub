// ---- native hooks (split from native_hooks.cpp) -------------------------
#include "native_hooks_internal.h"

#define ADH_NATIVE_STUB(N, OFF) \
extern "C" void adh_native_stub_##N(void) __attribute__((naked)); \
extern "C" void adh_native_stub_##N(void) { \
    __asm__ volatile( \
        "sub sp, sp, #352\n" \
        "stp x0, x1, [sp, #0]\n" \
        "stp x2, x3, [sp, #16]\n" \
        "stp x4, x5, [sp, #32]\n" \
        "stp x6, x7, [sp, #48]\n" \
        "stp x8, x9, [sp, #64]\n" \
        "stp x29, x30, [sp, #80]\n" \
        "str x18, [sp, #96]\n" \
        "stp q0, q1, [sp, #128]\n" \
        "stp q2, q3, [sp, #160]\n" \
        "stp q4, q5, [sp, #192]\n" \
        "stp q6, q7, [sp, #224]\n" \
        "add x9, sp, #352\n" \
        "str x9, [sp, #256]\n" \
        "stp x19, x20, [sp, #264]\n" \
        "stp x21, x22, [sp, #280]\n" \
        "stp x23, x24, [sp, #296]\n" \
        "stp x25, x26, [sp, #312]\n" \
        "stp x27, x28, [sp, #328]\n" \
        "mov x2, xzr\n" \
        "mov x0, sp\n" \
        "mov x1, #" #N "\n" \
        "bl adh_native_hook_record\n" \
        "mov x16, x0\n" \
        "ldp x0, x1, [sp, #0]\n" \
        "ldp x2, x3, [sp, #16]\n" \
        "ldp x4, x5, [sp, #32]\n" \
        "ldp x6, x7, [sp, #48]\n" \
        "ldp x8, x9, [sp, #64]\n" \
        "ldp x29, x30, [sp, #80]\n" \
        "ldr x18, [sp, #96]\n" \
        "ldp q0, q1, [sp, #128]\n" \
        "ldp q2, q3, [sp, #160]\n" \
        "ldp q4, q5, [sp, #192]\n" \
        "ldp q6, q7, [sp, #224]\n" \
        "ldp x19, x20, [sp, #264]\n" \
        "ldp x21, x22, [sp, #280]\n" \
        "ldp x23, x24, [sp, #296]\n" \
        "ldp x25, x26, [sp, #312]\n" \
        "ldp x27, x28, [sp, #328]\n" \
        "add sp, sp, #352\n" \
        "cbnz x16, 1f\n" \
        "adrp x17, g_native_hook_originals+" #OFF "\n" \
        "add x17, x17, :lo12:g_native_hook_originals+" #OFF "\n" \
        "ldr x17, [x17]\n" \
        "br x17\n" \
        "1:\n" \
        "ret\n" \
    ); \
}

ADH_NATIVE_STUB(0, 0)
ADH_NATIVE_STUB(1, 8)
ADH_NATIVE_STUB(2, 16)
ADH_NATIVE_STUB(3, 24)
ADH_NATIVE_STUB(4, 32)
ADH_NATIVE_STUB(5, 40)
ADH_NATIVE_STUB(6, 48)
ADH_NATIVE_STUB(7, 56)
ADH_NATIVE_STUB(8, 64)
ADH_NATIVE_STUB(9, 72)
ADH_NATIVE_STUB(10, 80)
ADH_NATIVE_STUB(11, 88)
ADH_NATIVE_STUB(12, 96)
ADH_NATIVE_STUB(13, 104)
ADH_NATIVE_STUB(14, 112)
ADH_NATIVE_STUB(15, 120)

// ---- post-call stubs -----------------------------------------------------------------------
// The ordinary stub TAIL-JUMPS to the original, so nothing of ours can run after it returns. A hook
// that asked for `memAfter` needs the opposite shape: call the original, copy the window it wrote,
// then hand its return value back. Only those hooks pay for this; every other hook keeps the tail
// jump, which also leaves the float/vector return registers untouched.
extern "C" uint64_t adh_native_hook_after(uint64_t retval, uint64_t *regs, int hook_id, uint64_t seq, uint64_t expected_id);

#define ADH_NATIVE_STUB_AFTER(N, OFF) \
extern "C" void adh_native_stub_after_##N(void) __attribute__((naked)); \
extern "C" void adh_native_stub_after_##N(void) { \
    __asm__ volatile( \
        "sub sp, sp, #288\n" \
        "stp x0, x1, [sp, #0]\n" \
        "stp x2, x3, [sp, #16]\n" \
        "stp x4, x5, [sp, #32]\n" \
        "stp x6, x7, [sp, #48]\n" \
        "stp x8, x9, [sp, #64]\n" \
        "stp x29, x30, [sp, #80]\n" \
        "str x18, [sp, #96]\n" \
        "stp q0, q1, [sp, #128]\n" \
        "stp q2, q3, [sp, #160]\n" \
        "stp q4, q5, [sp, #192]\n" \
        "stp q6, q7, [sp, #224]\n" \
        "add x2, sp, #256\n" \
        "mov x0, sp\n" \
        "mov x1, #" #N "\n" \
        "bl adh_native_hook_record\n" \
        "mov x16, x0\n" \
        "ldp x0, x1, [sp, #0]\n" \
        "ldp x2, x3, [sp, #16]\n" \
        "ldp x4, x5, [sp, #32]\n" \
        "ldp x6, x7, [sp, #48]\n" \
        "ldp x8, x9, [sp, #64]\n" \
        "ldp x29, x30, [sp, #80]\n" \
        "ldr x18, [sp, #96]\n" \
        "ldp q0, q1, [sp, #128]\n" \
        "ldp q2, q3, [sp, #160]\n" \
        "ldp q4, q5, [sp, #192]\n" \
        "ldp q6, q7, [sp, #224]\n" \
        "cbnz x16, 2f\n" \
        "adrp x17, g_native_hook_originals+" #OFF "\n" \
        "add x17, x17, :lo12:g_native_hook_originals+" #OFF "\n" \
        "ldr x17, [x17]\n" \
        "blr x17\n" \
        "stp q0, q1, [sp, #128]\n" \
        "stp q2, q3, [sp, #160]\n" \
        "str x1, [sp, #272]\n" \
        "ldr x3, [sp, #256]\n" \
        "ldr x4, [sp, #264]\n" \
        "mov x1, sp\n" \
        "mov x2, #" #N "\n" \
        "bl adh_native_hook_after\n" \
        "ldr x1, [sp, #272]\n" \
        "ldp q0, q1, [sp, #128]\n" \
        "ldp q2, q3, [sp, #160]\n" \
        "ldp x29, x30, [sp, #80]\n" \
        "ldr x18, [sp, #96]\n" \
        "add sp, sp, #288\n" \
        "ret\n" \
        "2:\n" \
        "add sp, sp, #288\n" \
        "ret\n" \
    ); \
}

ADH_NATIVE_STUB_AFTER(0, 0)
ADH_NATIVE_STUB_AFTER(1, 8)
ADH_NATIVE_STUB_AFTER(2, 16)
ADH_NATIVE_STUB_AFTER(3, 24)
ADH_NATIVE_STUB_AFTER(4, 32)
ADH_NATIVE_STUB_AFTER(5, 40)
ADH_NATIVE_STUB_AFTER(6, 48)
ADH_NATIVE_STUB_AFTER(7, 56)
ADH_NATIVE_STUB_AFTER(8, 64)
ADH_NATIVE_STUB_AFTER(9, 72)
ADH_NATIVE_STUB_AFTER(10, 80)
ADH_NATIVE_STUB_AFTER(11, 88)
ADH_NATIVE_STUB_AFTER(12, 96)
ADH_NATIVE_STUB_AFTER(13, 104)
ADH_NATIVE_STUB_AFTER(14, 112)
ADH_NATIVE_STUB_AFTER(15, 120)

 void *after_stub_for_id(int id) {
    switch (id) {
        case 0: return (void *)adh_native_stub_after_0;
        case 1: return (void *)adh_native_stub_after_1;
        case 2: return (void *)adh_native_stub_after_2;
        case 3: return (void *)adh_native_stub_after_3;
        case 4: return (void *)adh_native_stub_after_4;
        case 5: return (void *)adh_native_stub_after_5;
        case 6: return (void *)adh_native_stub_after_6;
        case 7: return (void *)adh_native_stub_after_7;
        case 8: return (void *)adh_native_stub_after_8;
        case 9: return (void *)adh_native_stub_after_9;
        case 10: return (void *)adh_native_stub_after_10;
        case 11: return (void *)adh_native_stub_after_11;
        case 12: return (void *)adh_native_stub_after_12;
        case 13: return (void *)adh_native_stub_after_13;
        case 14: return (void *)adh_native_stub_after_14;
        case 15: return (void *)adh_native_stub_after_15;
        default: return nullptr;
    }
}

 void *stub_for_id(int id) {
    switch (id) {
        case 0: return (void *)adh_native_stub_0;
        case 1: return (void *)adh_native_stub_1;
        case 2: return (void *)adh_native_stub_2;
        case 3: return (void *)adh_native_stub_3;
        case 4: return (void *)adh_native_stub_4;
        case 5: return (void *)adh_native_stub_5;
        case 6: return (void *)adh_native_stub_6;
        case 7: return (void *)adh_native_stub_7;
        case 8: return (void *)adh_native_stub_8;
        case 9: return (void *)adh_native_stub_9;
        case 10: return (void *)adh_native_stub_10;
        case 11: return (void *)adh_native_stub_11;
        case 12: return (void *)adh_native_stub_12;
        case 13: return (void *)adh_native_stub_13;
        case 14: return (void *)adh_native_stub_14;
        case 15: return (void *)adh_native_stub_15;
        default: return nullptr;
    }
}


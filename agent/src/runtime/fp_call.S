// adh_fp_call — active-call trampoline with FP arguments (AAPCS64).
//
// Called from C as:  uint64_t adh_fp_call(void *target, const uint64_t ints[8], const uint64_t fps[8],
//                                         uint64_t *fp_result_out)
//   x0 = target
//   x1 = ints   (8 x 64-bit integer/pointer arguments -> x0-x7)
//   x2 = fps    (16-byte aligned; fps[0..7] -> d0-d7 (8 bytes each))
//   x3 = fp_result_out (receives d0, the FP return register)
// x0 still carries the target's integer return; the FP return goes through the caller's pointer
// rather than a shared global, so two concurrent calls cannot read each other's result.
//
// AAPCS64 assigns integer and floating-point arguments to independent banks, which is exactly what
// this lays out: the i-th integer argument goes to x(i), the i-th FP argument to d(i). x29/x30 are
// saved because this is NOT a leaf function (the blr below overwrites x30 with the target's return
// address - without saving it the final ret would jump back into this trampoline). Written in
// assembly rather than a naked C function because a naked C version let -O3 clobber the argument
// registers on device.

    .text
    .p2align 2
    .global adh_fp_call
    .type adh_fp_call, %function
adh_fp_call:
    stp x29, x30, [sp, #-32]!       // frame: [sp]=x29, [sp+8]=x30, [sp+16]=fp-result out-pointer
    mov x29, sp
    mov x11, x0                     // target
    mov x9, x1                      // ints
    mov x10, x2                     // fps
    str x3, [sp, #16]               // park the out-pointer: x3 is caller-saved and the target may clobber it
    ldp d0, d1, [x10]
    ldp d2, d3, [x10, #16]
    ldp d4, d5, [x10, #32]
    ldp d6, d7, [x10, #48]
    ldp x0, x1, [x9]
    ldp x2, x3, [x9, #16]
    ldp x4, x5, [x9, #32]
    ldp x6, x7, [x9, #48]
    blr x11
    ldr x3, [sp, #16]
    str d0, [x3]                    // d0 -> *fp_result_out (64-bit store; s0 for float-returning targets)
    ldp x29, x30, [sp], #32
    ret
    .size adh_fp_call, .-adh_fp_call
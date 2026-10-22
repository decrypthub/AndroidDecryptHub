#ifndef ADH_AGENT_HOOK_HW_WATCH_H
#define ADH_AGENT_HOOK_HW_WATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Hardware watchpoints, set from inside the target with perf_event_open(PERF_TYPE_BREAKPOINT).
//
// Why this exists: "who wrote this buffer" is not answerable by hooking known functions (the writer
// is usually a non-exported VM handler) and not by an instruction trace of a 0x11000-byte flattened
// function (millions of instructions, and the interesting one is a single store). A watchpoint is
// the surgical instrument: arm it on the address, trigger the target once, and the kernel reports
// the faulting instruction + call chain.
//
// Requirements: perf events must be permitted (kernel.perf_event_paranoid <= 0 for an app), which
// is NOT the default on Android — the command fails loud with the errno instead of pretending.
#define ADH_HW_WATCH_MAX 4

// action: "set" (addr, len 1|2|4|8, mode "w"|"rw"|"x") / "clear" (slot) / "status".
// out receives a JSON object. Returns 0 on success, -1 on failure with a reason in out.
int adh_hw_watch_cmd(const char *action, const char *addr_hex, int len, const char *mode,
                     int slot, char *out, size_t outsz);

// Arm one watchpoint at an address computed inside a hook's after-stub (regs = saved x0..x8).
// Configured with adh_hw_watch_config_after(hook uid, "x0:8"). Returns the slot, or -1.
int adh_hw_watch_arm_for_hook(int hook_uid, const uint64_t *regs);
int adh_hw_watch_config_after(int hook_uid, const char *spec, char *out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif

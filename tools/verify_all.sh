#!/usr/bin/env bash
# Master regression runner — runs every version acceptance script and reports a summary.
# Ensures ADH Daemon + adb reverse are up first. Device-only scripts are skipped (not failed)
# when no device is attached. Exit 0 only if all RUN scripts passed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash tools/dev_up.sh >/dev/null 2>&1
STATE="$(adb get-state 2>/dev/null | tr -d '\r')"
# Right after a reboot the Manager accessibility service (and with it the automation bridge) needs a
# moment to come back; v36/v38/v39/v40/v41 drive the UI and otherwise fail or skip confusingly. Wait
# once here, bounded, instead of teaching every script to poll.
if [ "$STATE" = "device" ]; then
  for _ in $(seq 1 20); do
    if curl -s -m 2 "http://127.0.0.1:${ADH_HTTP_PORT:-8088}/api/automation/status" 2>/dev/null | grep -Eq '"connected"[[:space:]]*:[[:space:]]*true'; then
      break
    fi
    sleep 3
  done
fi

# name:needs_device
SCRIPTS=(
  "verify_v01.sh:device"
  "verify_v02.sh:device"
  # Optional phone automation first, before device scripts that may stop Manager.
  "verify_v36_automation.sh:device"
  # Agent reconnect: the injected agent must survive a Host ADH Daemon restart (kills + restarts
  # the daemon inside the script; SKIPs when it cannot find the process to restart).
  "verify_v37_agent_reconnect.sh:device"
  # Watchdog: a stuck device command must answer command_timeout and leave the channel usable.
  "verify_v38_automation_watchdog.sh:device"
  # Notifications: the opt-in listener (borrows the grant for the run, releases it afterwards).
  "verify_v39_notifications.sh:device"
  # Root Device Daemon surface (v6-v8): root open, screen control, ensure loop. SKIPs when the
  # resident daemon is still the old payload.
  "verify_v40_device_daemon.sh:device"
  # Post-flash boot path: waits for the boot-started daemon and exercises volume/clipboard/root
  # input. Meaningful right after a flash; also runs (and passes) while the daemon is already up.
  "verify_v41_postflash.sh:device"
  # LSPlant Java hooks + Java enum/call + native/GOT hook runtime (v4.2-v4.7). Each script
  # SKIPs cleanly on an older deployed payload; on the current agent they are deterministic.
  "verify_v42_lsplant.sh:device"
  "verify_v43_javahook.sh:device"
  "verify_v44_java_enum.sh:device"
  "verify_v45_java_call.sh:device"
  "verify_v46_native_hook.sh:device"
  "verify_v47_got_enum.sh:device"
  "verify_v48_memory_disasm.sh:device"
  "verify_v49_native_call.sh:device"
  "verify_v50_syscall_watch.sh:device"
  "verify_v51_qbdi_args.sh:device"
  "verify_v52_java_override.sh:device"
  "verify_v53_java_arg_rewrite.sh:device"
  "verify_v54_jni_register_hook.sh:device"
  "verify_v55_native_rewrite.sh:device"
  "verify_v56_hook_stress.sh:device"
  "verify_v57_jni_onload.sh:device"
  "verify_v58_jni_env_hook.sh:device"
  "verify_v59_jni_env_arrays.sh:device"
  "verify_v60_jni_env_preserve.sh:device"
  "verify_v61_got_by_name.sh:device"
  "verify_v62_jni_call_hooks.sh:device"
  "verify_v63_jni_array_writeback.sh:device"
  "verify_v64_jni_call_types.sh:device"
  "verify_v65_java_ctor_inherited.sh:device"
  "verify_v66_native_hard_unhook.sh:device"
  "verify_v67_jni_onload_watch.sh:device"
  "verify_v68_native_fp_args.sh:device"
  "verify_v71_mcp_registry.sh:host"
  "verify_v69_stealth_pool.sh:device"
  "verify_v70_site_hooks.sh:device"
  "verify_v72_site_hooks_cross.sh:device"
  "verify_v73_vtable_hook.sh:device"
  "verify_v74_slot_object_callback.sh:device"
  # Memfd loader (v4.37): the injected agent must be alive AND loaded from an unnamed memfd. Checks
  # the decision log, the target's maps (outside), the agent's own maps + ELF header (inside), and
  # restores the Zygisk scope afterwards.
  "verify_v75_zygisk_memfd.sh:device"
  # Syscall attribution (v4.38): the static decoder is unit-tested on the host; the device script
  # proves a libc-mediated syscall (uname) can be selected by name and really fires with x8=0xa0.
  "verify_v76_syscall_attribution.sh:host"
  "verify_v77_syscall_watch_libc.sh:device"
  # Trace digest (v4.41): pure digest of a QBDI stream + the MCP tool shape. Host-only.
  "verify_v80_trace_digest.sh:host"
  # Syscall digest (v4.43): groups watched syscall hits by (nr, issuing caller frame) and compares
  # runtime x8 with the attributed number. Host-only.
  "verify_v81_syscall_digest.sh:host"
  # Hook-hit caller backtrace (v4.39): the event must carry the at-hit chain and every frame must be
  # resolved to module + symbol; a bogus frame pointer must stop the walk, not invent frames.
  "verify_v78_hook_backtrace.sh:device"
  # Java caller chain (v4.40): the LSPlant callback must report the app frames that led to the hooked
  # method when stack:true is set - and nothing when it is not.
  "verify_v79_java_stack.sh:device"
  "verify_v02_dump.sh:device"
  "verify_v02_so.sh:device"
  "verify_v02_dexrepair.sh:host"
  "verify_v03.sh:device"
  "verify_v04_dexparse.sh:host"
  "verify_v04_gothook.sh:device"
  "verify_v04_crypto.sh:device"
  "verify_v05_detect.sh:device"
  "verify_v06.sh:device"
  "verify_v07.sh:device"
  "verify_v07_flow.sh:device"
  "verify_v08_dexsearch.sh:host"
  "verify_v08_disasm.sh:host"
  "verify_v08_analyze.sh:host"
  "verify_v08_xref.sh:host"
  "verify_v09_cryptoconst.sh:host"
  "verify_v09_syscall.sh:host"
  "verify_v09_methodcode.sh:host"
  "verify_v10_mcp.sh:host"
  "verify_v10_webui.sh:host"
  "verify_v33_backends.sh:host"
  "verify_v35_sessions.sh:host"
  "verify_v10_trace.sh:device"
  "verify_v10_export.sh:host"
  "verify_v10_events.sh:device"
  "verify_v10_qbdi.sh:device"
  "verify_v11_capture.sh:device"
  "verify_v12_rebuild.sh:host"
  "verify_v13_recover.sh:host"
  "verify_v14_trigger.sh:device"
  "verify_v15_dumpall.sh:device"
  "verify_v16_identify.sh:device"
  "verify_v17_dumpall_mcp.sh:device"
  "verify_v18_loadso.sh:device"
  "verify_v19_settings.sh:host"
  "verify_v20_file.sh:device"
  "verify_v21_frame.sh:device"
  "verify_v22_capture.sh:device"
  "verify_v24_javacap.sh:device"
  "verify_v25_fsbrowser.sh:device"
  "verify_v26_cryptocoverage.sh:device"
  "verify_v26_footprint.sh:host"
  "verify_v27_zygisk.sh:device"
  "verify_v28_inlinehook.sh:device"
  "verify_v29_dexindex.sh:host"
  # Optional Frida Gadget backend (module W): official gadget → dlopen → bundled Java hook.
  # SKIPs (exit 0) when the gadget asset / bundler deps are absent — both are gitignored caches.
  "verify_v30_fridagadget.sh:device"
  # Optional LSPosed/Xposed backend (module W): framework → thin module → agent. Restores the
  # pre-test scope/module state; SKIPs when no framework CLI or the module cannot be built.
  "verify_v31_xposed.sh:device"
  # Optional backend CONTROL path (module W): Device Daemon drives the framework scope/module
  # state; restores the pre-test state. SKIPs when there is no framework/module.
  "verify_v32_backend_control.sh:device"
  # Optional eCapture backend (module W): eBPF TLS plaintext capture. Needs root + eBPF kernel;
  # SKIPs with an explicit reason when the kernel cannot load eBPF programs.
  "verify_v34_ecapture.sh:device"
)

pass=0; fail=0; skip=0; FAILED=""
for entry in "${SCRIPTS[@]}"; do
  name="${entry%%:*}"; needs="${entry##*:}"
  [ -f "tools/$name" ] || continue
  if [ "$needs" = "device" ] && [ "$STATE" != "device" ]; then
    echo "SKIP  $name (no device)"; skip=$((skip+1)); continue
  fi
  # device scripts need the sandbox running + agent connected; (re)launch first
  if [ "$needs" = "device" ]; then
    adb shell am force-stop com.adh.sandbox >/dev/null 2>&1
    adb shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1; sleep 4
  fi
  if bash "tools/$name" >/tmp/vr.log 2>&1; then
    # A capability script whose precondition is missing exits 0 WITHOUT the RESULT:PASS sentinel: it
    # prints either a top-level "SKIP ..." line (verify_v75) or "RESULT:SKIP" (verify_v30/31/32/34).
    # Counting those as passes would report an acceptance that never ran; counting RESULT:SKIP as a
    # failure (the old behaviour) was equally wrong. Both are counted - and printed - as skips.
    # A skip must be the script's FINAL result: the last non-empty line starts with SKIP (v75 style)
    # or the script ends with the RESULT:SKIP sentinel (v30/31/32/34 style). Matching any line in the
    # log would turn a script that merely mentions an internal skip into a skip itself.
    last_line="$(grep -v '^[[:space:]]*$' /tmp/vr.log | tail -1)"
    if [[ "$last_line" == SKIP* ]] || grep -q '^RESULT:SKIP' /tmp/vr.log; then
      reason="$(grep -m1 'SKIP (' /tmp/vr.log | sed -e 's/^[[:space:]]*//' -e 's/^[^A-Za-z0-9]*//')"
      [ -n "$reason" ] || reason="$(grep -m1E '^(SKIP|RESULT:SKIP)' /tmp/vr.log | sed -e 's/^RESULT:SKIP[[:space:]]*//' -e 's/^SKIP[[:space:]]*//')"
      echo "SKIP  $name ($reason)"; skip=$((skip+1))
    else
      echo "PASS  $name"; pass=$((pass+1))
    fi
  else
    echo "FAIL  $name"; fail=$((fail+1)); FAILED="$FAILED $name"
    tail -6 /tmp/vr.log | sed 's/^/        /'
  fi
done
echo "----"
echo "pass=$pass fail=$fail skip=$skip${FAILED:+  failed:$FAILED}"
[ "$fail" -eq 0 ] && exit 0 || exit 1

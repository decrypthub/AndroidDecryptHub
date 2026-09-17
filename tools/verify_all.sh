#!/usr/bin/env bash
# Master regression runner — runs every version acceptance script and reports a summary.
# Ensures ADH Daemon + adb reverse are up first. Device-only scripts are skipped (not failed)
# when no device is attached. Exit 0 only if all RUN scripts passed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash tools/dev_up.sh >/dev/null 2>&1
STATE="$(adb get-state 2>/dev/null | tr -d '\r')"

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
    echo "PASS  $name"; pass=$((pass+1))
  else
    echo "FAIL  $name"; fail=$((fail+1)); FAILED="$FAILED $name"
    tail -6 /tmp/vr.log | sed 's/^/        /'
  fi
done
echo "----"
echo "pass=$pass fail=$fail skip=$skip${FAILED:+  failed:$FAILED}"
[ "$fail" -eq 0 ] && exit 0 || exit 1

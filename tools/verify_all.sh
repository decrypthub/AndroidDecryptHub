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
  # Agent reconnect: the injected agent must survive a Host ADH Daemon restart (kills + restarts
  # the daemon inside the script; SKIPs when it cannot find the process to restart).
  "verify_v37_agent_reconnect.sh:device"
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
  # Device half of the same feature: QBDI-trace a real fixture and digest THAT stream.
  "verify_v80_device_trace_digest.sh:device"
  # Syscall digest (v4.43): groups watched syscall hits by (nr, issuing caller frame) and compares
  # runtime x8 with the attributed number. Host-only.
  "verify_v81_syscall_digest.sh:host"
  # Device half: the digest must name the fixture that issued the libc uname(2) call.
  "verify_v81_device_syscall_digest.sh:device"
  # Java class-level trace digest (v4.45): hook_all + capture ring + per-method/timeline digest.
  "verify_v83_java_trace.sh:host"
  # Device half: start -> trigger the call chain -> digest methods/callers -> stop.
  "verify_v83_device_java_trace.sh:device"
  # Native batch hooking by export pattern (v4.46): symbol selection + MCP shape. Host-only.
  "verify_v84_native_hook_all.sh:host"
  # One-shot syscall tracing (v4.47): watch->digest->stop assembly with the attribution threaded.
  "verify_v85_syscall_trace.sh:host"
  # Device half: the threaded attribution must survive start -> trigger -> digest -> stop.
  "verify_v85_device_syscall_trace.sh:device"
  # Per-hook native event throttle (v4.48): payload shaping + agent wiring + MCP/REST shape. Host-only.
  "verify_v86_native_throttle.sh:host"
  # ...and its device half: hits = emitted + throttled on a real hook, with the return rewrite still
  # applied to every throttled hit.
  "verify_v86_device_throttle.sh:device"
  # MCP operability (v4.49): every agent op must be reachable through the MCP import graph (or be
  # declared internal with a reason); probe/filesystem tools share their logic with the REST routes.
  "verify_v87_mcp_operability.sh:host"
  # Device half of the MCP operability tools: ping / engine self-test / protocol self-test / fs.
  "verify_v87_device_probe_fs.sh:device"
  # Signature scrub (v4.50): the release agent must not carry our own identity strings (stage 1)
  # and the remaining third-party/contract strings are budgeted. SKIPs when the .so is not built.
  "verify_v88_agent_signatures.sh:host"
  # Device half: scan the LOADED agent image for the tokens stage 1 removed (with a positive control).
  "verify_v88_device_memory_signature.sh:device"
  # Hook-hit caller backtrace (v4.39): the event must carry the at-hit chain and every frame must be
  # resolved to module + symbol; a bogus frame pointer must stop the walk, not invent frames.
  "verify_v78_hook_backtrace.sh:device"
  # Java caller chain (v4.40): the LSPlant callback must report the app frames that led to the hooked
  # method when stack:true is set - and nothing when it is not.
  "verify_v79_java_stack.sh:device"
  # Batch Java hooks (v4.44): hookAll must install every matching overload in one call and report a
  # larger matched count when the slot limit truncates the batch.
  "verify_v82_java_hook_all.sh:device"
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
  # Live-object field WRITE (v4.53): read -> patch -> read back, and a final field must refuse.
  "verify_v89_object_set.sh:device"
  # JNIEnv table ABI (v4.54): every hand-written slot index is checked against the SDK jni.h, so
  # adding a slot (e.g. the field accessors) is machine-verified before it ever runs in a target.
  "verify_v90_jni_table_abi.sh:host"
  # JNIEnv FIELD accessor slots (v4.55): the native probe drives them; events must carry field+value.
  "verify_v91_jni_env_fields.sh:device"
  # JNIEnv field digest (v4.56): join access events with the IDs they were handed out with.
  "verify_v92_jni_field_digest.sh:host"
  # Device-script routes (v4.87): every /api/... an acceptance script calls must exist in the
  # daemon route table. The device scripts only run when a phone is attached, so a renamed route
  # would otherwise stay invisible until then.
  "verify_v94_device_script_routes.sh:host"
  # WS-E slice 1 (v2.4): try/catch code_items are read in full and rebuilt byte-identically;
  # a method whose item cannot be walked is reported unresolvable, not silently "present".
  "verify_v95_dex_trycatch.sh:host"
  # WS-E slice 2 (v5.01): the rebuilt dex's map_list names the relocated code_item/class_data
  # regions, every class_def/code_off is patched to them, and the layout check has teeth.
  "verify_v96_dex_map.sh:host"
  # v9.7: the agent's memory reads stopped depending on /proc/self/mem. A target that refuses that
  # fd (protectors that make the process non-dumpable) keeps read/search/scan/dump/art_dexfiles.
  "verify_v97_memread_direct.sh:device"
  # v9.8: the injected path (memfd-loaded agent, no JNI_OnLoad) must still reach Java and ART.
  # The JavaVM defect this guards left every Java/ART command dead on real targets while the gate
  # stayed green, because every other device check runs against the self-loading sandbox.
  "verify_v98_injected_java_surface.sh:device"
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
  # verify_v34_ecapture.sh:device — REMOVED from the gate on 2026-10-01. eCapture was downgraded to
  # an experimental script: it needs kernel eBPF, overlaps the built-in
  # TLS/syscall observation, and does not ship. The script is kept runnable by hand
  # (bash tools/verify_v34_ecapture.sh) but is no longer a release gate.
  # v9.9 artifact store: the eviction policy is unit-tested, and artifacts that are on disk must be
  # listed again after a daemon restart. Registered last because it restarts the daemon itself.
  "verify_v99_artifact_store.sh:host"
  # v10.0 `adh` CLI (daemon/): doctor/target/unpack, and — the interesting half — every declared flag
  # asserted by its EFFECT rather than by its presence in --help (a flag accepted but ignored is how
  # a diagnostic CLI lies to its operator). Registered as device because target/unpack need a live
  # agent; the daemon-side half still runs standalone and the agent half SKIPs cleanly when absent.
  "verify_v100_adh_cli.sh:device"
  # v10.1 mutated-algorithm identification (host): identifies crypto by STRUCTURE and names the
  # mutation, and asserts the standard-constant scan is blind to it (it returns the same algorithm
  # names for the textbook and the mutated fixture, and claims MD5 on the mutated one). The fixtures
  # are compiled by tools/build_crypto_variants.sh; no daemon-no-clang SKIPs cleanly.
  "verify_v101_crypto_variants.sh:host"
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

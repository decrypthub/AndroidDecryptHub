#!/usr/bin/env bash
# Master regression runner — runs every version acceptance script and reports a summary.
# Full mode can bootstrap ADH Daemon + adb reverse. Host mode never bootstraps or discovers ADB.
# ADH_VERIFY_BOOTSTRAP=skip uses an already prepared, owned environment for full verification.
# Device-only scripts are skipped (not failed)
# when no device is attached. Exit 0 only if all RUN scripts passed.
#
# ADH_VERIFY_MODE=host  — only :host scripts (daily / no phone). Prefer: tools/verify_host.sh
# ADH_VERIFY_MODE=full  — host + device (default when unset)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODE="${ADH_VERIFY_MODE:-full}"
case "$MODE" in host|full) ;; *) echo 'invalid ADH_VERIFY_MODE (host/full required)' >&2; exit 2 ;; esac
BOOTSTRAP="${ADH_VERIFY_BOOTSTRAP:-auto}"
case "$BOOTSTRAP" in auto|skip) ;; *) echo 'invalid ADH_VERIFY_BOOTSTRAP (auto/skip required)' >&2; exit 2 ;; esac
source "$ROOT/tools/lib/verify_common.sh"
STATE=offline
if [ "$MODE" = full ]; then
  SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-}}"
  if [ -z "$SERIAL" ]; then
    DEVICES="$(adb devices 2>/dev/null | tr -d '\r' | awk 'NR>1 && $2=="device" {print $1}')"
    COUNT="$(printf '%s\n' "$DEVICES" | awk 'NF{n++} END{print n+0}')"
    [ "$COUNT" -le 1 ] || { echo 'multiple devices: set ANDROID_SERIAL explicitly' >&2; exit 2; }
    SERIAL="$DEVICES"
  fi
  [ "$SERIAL" != a22fecdd ] || { echo 'daily device a22fecdd refused before bootstrap' >&2; exit 2; }
  if [ -n "$SERIAL" ]; then
    export ANDROID_SERIAL="$SERIAL"
    STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
  fi
  if [ "$BOOTSTRAP" = auto ]; then
    [ -n "${ADH_VERIFY_OWNED_ROOT:-}" ] && [ -n "${ADH_DATA_DIR:-}" ] || { echo 'full bootstrap requires ADH_VERIFY_OWNED_ROOT and isolated ADH_DATA_DIR' >&2; exit 2; }
    existing="$(daemon_pid_on_port "${ADH_HTTP_PORT:-8088}")"
    if [ -n "$existing" ] && ! verify_pid_owned "$existing"; then echo 'refuse bootstrap over an unowned Host' >&2; exit 2; fi
    bash tools/dev_up.sh >/dev/null 2>&1
  fi
fi
if [ -n "${ADH_VERIFY_LOG_DIR:-}" ]; then
  [ ! -e "$ADH_VERIFY_LOG_DIR" ] || { echo 'ADH_VERIFY_LOG_DIR must be new' >&2; exit 2; }
  mkdir -p "$ADH_VERIFY_LOG_DIR" || exit 2
  LOG_DIR="$ADH_VERIFY_LOG_DIR"
else
  LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/adh-verify.XXXXXX")" || exit 2
fi
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
  # Frida Gadget retired from product surface (2026-10-20); verify_v30_fridagadget.sh kept as archive-only.
  # Optional eCapture backend (module W): eBPF TLS plaintext capture. Needs root + eBPF kernel;
  # SKIPs with an explicit reason when the kernel cannot load eBPF programs.
  # verify_v34_ecapture.sh:device — REMOVED from the gate on 2026-10-01. eCapture was downgraded to
  # an experimental script (DEVELOPMENT_PLAN §6.10): it needs kernel eBPF, overlaps the built-in
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
  # v10.2 per-package hook policy (module W): the scope file's per-app policy decides which crypto
  # hook families are INSTALLED in that app — not merely which records are reported afterwards.
  # Writes a trimmed policy for one target, cold-starts it, asserts the agent's own hello reports the
  # switched-off families as skipped (-1) and the rest installed (1), then restores the scope file.
  # Needs the adh Zygisk module AND the target package; SKIPs cleanly otherwise. Set ADH_POLICY_TARGET
  # to a package that is actually installed (defaults to the sandbox).
  "verify_v102_policy.sh:device"
  # v10.3 Zygisk Next integration: Zygisk Next 1.5+ validates how a module uses the companion API and
  # publishes the verdict in its own status line. Our log-relay socket used to be cached and never
  # closed, which is exactly "improper use of the Companion API" — every injected process carried a
  # dead fd for its lifetime. Needs a device with BOTH our module and Zygisk Next; SKIPs otherwise.
  "verify_v103_zygisk_companion.sh:device"
  # v10.4 Java crypto hooks: the sandbox probe runs AES-CBC, AES-GCM, HMAC, SHA-256, RSA and
  # SHA256withRSA on a platform provider (not the sandbox's own reporter). java-source captures
  # of the fixed markers are the plugin hooks, and the probe return value shows the originals ran.
  "verify_v104_java_hook.sh:device"
  # v10.5 detection checklist: system-capture lines become debug/root/signature/emulator/integrity
  # counts, app-owned modules are selected, and the Java plan does not install without confirm.
  "verify_v105_detect_summary.sh:host"
  # Hit-time memory windows: the host grammar (caps, canonical spec, typo refuses the
  # install) and the wiring into MCP/REST/agent. The device half is v107.
  "verify_v106_native_mem_window.sh:host"
  # Device half: the companion record matches the buffer from BEFORE the hooked function
  # flips it, and a small integer register is reported unreadable without killing the process.
  "verify_v107_native_mem_window.sh:device"
  # One readable native observation: the host joins the hook hit and its memory
  # copy into a single sentence. Host-only; the device bytes stay on v107.
  "verify_v108_native_look.sh:host"
  # Trace safety: a target that still carries one of our inline patches (active OR
  # soft-unhooked - the soft state keeps the Dobby branch in the prologue on purpose) must be
  # refused with the hook id, and the same address must trace to completion again after a hard
  # unhook. Before this the tracer followed the branch into its trampoline and the target died
  # (SIGBUS at pc=0x2a, tombstone_10) with nothing in the message naming the hook.
  "verify_v110_trace_guard.sh:device"
  # v112: indirect (pointer-of-pointer) memory windows. `mem "@x2+32:512"` must resolve the pointer at
  # hit time and copy the bytes it names, report deref:true + the resolved ptr, and leave the plain
  # window showing the pointer VALUE. Without this, a VM frame's instruction record, a dispatch slot's
  # target or a list head's node is unreadable exactly when it is live.
  "verify_v112_indirect_window.sh:device"
  # v113: a post-call (memAfter) record must carry the SAME seq as its pre-call twin. It used to carry
  # none, so the documented (hookId, seq) join silently dropped every "what did it WRITE" record - and
  # the shape differed too (flat vs mem[]), which left the host preview blank.
  "verify_v113_memafter_seq.sh:device"
  # v114: window-chained dereference ("@x0:8,@#1+0:8"): the second hop follows a pointer that an earlier
  # window already copied, which is the shape of a formatter descriptor -> argument vector -> value.
  "verify_v114_window_chain.sh:device"
  # v115: the tracer must bound TIME, not only instruction count. A synchronous interpreter was measured
  # holding the command channel for the full 60 s client timeout with the instruction budget never
  # reached, which the caller can only read as "timed out".
  "verify_v115_trace_time_budget.sh:device"
  # v117: in-hook trace. "Capture the arguments, then trace afterwards" runs into released memory on a
  # request-scoped target, so the trace has to run AT THE HIT on the target thread. The gate asserts
  # the trace sub-object travels in the SAME event (first[0] == the hooked entry), that traceInsns:0
  # adds no key at all, and that the target survives both.
  "verify_v117_inhook_trace.sh:device"
  # v118: a hit-time window may read BEFORE the register's address (`x0-8:16`). A template interpreter's
  # instruction records are one contiguous array, so "what produced the value I am about to render" lives
  # at pc-10 - unreachable with a forward-only grammar.
  "verify_v118_negative_window.sh:device"
  # v119: a write watch inside the in-hook trace (`traceWatch`). Hardware watchpoints are denied to app
  # domains (perf_event_open: errno 13), so "which store wrote this buffer" had no answer; the gate makes
  # a fixture flip a known byte and requires the event to name that store (address/size/value/insn), then
  # requires the key to be absent when the watch is not requested.
  "verify_v119_trace_watch.sh:device"
  # v120: the oracle + differential harness. Record one call of a facade, replay it with ONE field changed,
  # and get the dependency matrix back - the primitive that turns "unknown parameter" into a small search
  # space without any target knowledge. Fixture: a static facade whose return value is a function of its
  # two arguments, so a patch to either must move the output and a patch to an unused position must not.
  "verify_v120_oracle_diff.sh:device"
  # Root-side perf collection (optional helper): actual GPR/stack records, bounded scope and accounting.
  "verify_v121_root_watch.sh:device"
  "verify_v122_native_controls.sh:device"
  "verify_v123_trace_session.sh:device"
  "verify_v124_crypto_evidence.sh:host"
  "verify_v125_native_abi.sh:device"
  "verify_v126_root_watch_native.sh:device"
  # v127: one module's dynamic symbol table (name/offset/size/kind), paged, with archive-mapped
  # libraries reported as symbol-less instead of guessed. Host-only: the device half of this path is
  # already covered by v84 (native_hook_all resolves exports through the same maps+dump+parse chain);
  # what is new is the paging/filter/archive contract and the refusal to add an agent op for it.
  "verify_v127_symbols.sh:host"
  # v129: the QBDI payload on a REAL target (not the sandbox APK): default refuses with an actionable
  # error and delivers no fd; opt-in delivers the fd, traces, and releases the library afterwards.
  "verify_v129_qbdi_delivery.sh:device"
  # v130: scope merge rules + the analyze_app/scope_* MCP tool contract (host only, no device write).
  "verify_v130_scope_analyze.sh:host"
  "verify_v132_p5_stdio.sh:host"
)

pass=0; fail=0; skip=0; FAILED=""
SERVICE_READY=''
service_ready() {
  [ -n "${ADH_VERIFY_OWNED_ROOT:-}" ] || return 1
  if [ -z "$SERVICE_READY" ]; then
    local listener; listener="$(daemon_pid_on_port "${ADH_HTTP_PORT:-8088}")"
    if [ -n "$listener" ] && verify_pid_owned "$listener" && curl --fail --silent --max-time 2 "http://127.0.0.1:${ADH_HTTP_PORT:-8088}/health" >/dev/null 2>&1; then SERVICE_READY=yes; else SERVICE_READY=no; fi
  fi
  [ "$SERVICE_READY" = yes ]
}
echo "verify_all mode=$MODE (host=daily subset, full=host+device)"
echo "logs=$LOG_DIR"
if [ -n "${ADH_VERIFY_OWNED_ROOT:-}" ]; then
  SHIM_URL="$(node --input-type=module -e "import {pathToFileURL} from 'node:url';process.stdout.write(pathToFileURL(process.argv[1]).href)" "$ROOT/tools/lib/verify_fetch.mjs")" || exit 2
  export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--import=$SHIM_URL"
  export ADH_VERIFY_FETCH_COORDINATED=1
  export ADH_VERIFY_FETCH_BASE="http://127.0.0.1:${ADH_HTTP_PORT:-8088}"
fi
for entry in "${SCRIPTS[@]}"; do
  name="${entry%%:*}"; needs="${entry##*:}"
  [ -f "tools/$name" ] || continue
  if [ "$MODE" = "host" ] && [ "$needs" = "device" ]; then
    continue
  fi
  # A host-only gate may still need a prepared local HTTP service or build fixture.
  # Missing external prerequisites are SKIP, while a failing assertion remains FAIL.
  case "$name" in
    verify_v02_dexrepair.sh|verify_v04_dexparse.sh|verify_v08_dexsearch.sh|verify_v08_xref.sh|verify_v09_methodcode.sh|verify_v95_dex_trycatch.sh|verify_v96_dex_map.sh|verify_v12_rebuild.sh|verify_v13_recover.sh|verify_v29_dexindex.sh)
      if [ ! -f "$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk" ]; then echo "SKIP  $name (sandbox APK not built)"; skip=$((skip+1)); continue; fi ;;
  esac
  case "$name" in
    verify_v02_dexrepair.sh|verify_v04_dexparse.sh|verify_v08_dexsearch.sh|verify_v08_disasm.sh|verify_v08_analyze.sh|verify_v08_xref.sh|verify_v09_cryptoconst.sh|verify_v09_syscall.sh|verify_v09_methodcode.sh|verify_v10_mcp.sh|verify_v10_webui.sh|verify_v33_backends.sh|verify_v35_sessions.sh|verify_v10_export.sh|verify_v12_rebuild.sh|verify_v13_recover.sh|verify_v19_settings.sh|verify_v29_dexindex.sh)
      if ! service_ready; then echo "SKIP  $name (prepare an owned Host on ADH_HTTP_PORT with ADH_VERIFY_OWNED_ROOT; host mode never starts it)"; skip=$((skip+1)); continue; fi ;;
  esac
  if [ "$needs" = "device" ] && [ "$STATE" != "device" ]; then
    echo "SKIP  $name (no device)"; skip=$((skip+1)); continue
  fi
  if [ "$needs" = "device" ] && ! service_ready; then echo "SKIP  $name (prepared Host unavailable)"; skip=$((skip+1)); continue; fi
  case "$name" in
    verify_v27_zygisk.sh|verify_v75_zygisk_memfd.sh|verify_v98_injected_java_surface.sh|verify_v103_zygisk_companion.sh|verify_v129_qbdi_delivery.sh)
      source_version="$(awk -F= '$1=="version"{gsub(/\r/,"",$2);print $2}' "$ROOT/injector/zygisk/module/module.prop")"
      deployed_version="$(adb -s "$SERIAL" exec-out su -c 'cat /data/adb/modules/adh/module.prop' 2>/dev/null | tr -d '\r' | awk -F= '$1=="version"{print $2}')"
      if [ "$source_version" != "$deployed_version" ]; then echo "SKIP  $name (source $source_version is not the deployed module $deployed_version; rerun after upgrade)"; skip=$((skip+1)); continue; fi ;;
  esac
  # device scripts need the sandbox running + agent connected; (re)launch first
  if [ "$needs" = "device" ]; then
    adb -s "$SERIAL" shell am force-stop com.adh.sandbox >/dev/null 2>&1
    adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1; sleep 4
  fi
  LOG="$LOG_DIR/$name.log"
  if bash "tools/$name" >"$LOG" 2>&1 && ! grep -qE '^RESULT:FAIL([[:space:]]|$)' "$LOG"; then
    # A capability script whose precondition is missing exits 0 WITHOUT the RESULT:PASS sentinel: it
    # prints either a top-level "SKIP ..." line (verify_v75) or "RESULT:SKIP" (verify_v30/34).
    # Counting those as passes would report an acceptance that never ran; counting RESULT:SKIP as a
    # failure (the old behaviour) was equally wrong. Both are counted - and printed - as skips.
    # A skip must be the script's FINAL result: the last non-empty line starts with SKIP (v75 style)
    # or the script ends with the RESULT:SKIP sentinel (v30/34 style). Matching any line in the
    # log would turn a script that merely mentions an internal skip into a skip itself.
    last_line="$(grep -v '^[[:space:]]*$' "$LOG" | tail -1)"
    if { [[ "$last_line" == SKIP* ]] || grep -qE '^RESULT:SKIP([[:space:]]|$)' "$LOG"; } &&
       ! grep -qE '^RESULT:PASS([[:space:]]|$)' "$LOG"; then
      reason="$(grep -m1 'SKIP (' "$LOG" | sed -e 's/^[[:space:]]*//' -e 's/^[^A-Za-z0-9]*//')"
      [ -n "$reason" ] || reason="$(grep -m1 -E '^(SKIP|RESULT:SKIP)' "$LOG" | sed -e 's/^RESULT:SKIP[[:space:]]*//' -e 's/^SKIP[[:space:]]*//')"
      echo "SKIP  $name ($reason)"; skip=$((skip+1))
    else
      echo "PASS  $name"; pass=$((pass+1))
    fi
  else
    echo "FAIL  $name"; fail=$((fail+1)); FAILED="$FAILED $name"
    tail -6 "$LOG" | cut -c1-360 | sed 's/^/        /'
    echo "        full details: $LOG"
    case "$name" in verify_v01.sh|verify_v02.sh) echo 'ABORT full verification: sandbox bootstrap prerequisite failed'; break ;; esac
    if grep -q CONTROL_REQUIRED "$LOG"; then echo 'ABORT full verification: acceptance client violated the required control-version contract'; break; fi
  fi
done
echo "----"
echo "pass=$pass fail=$fail skip=$skip${FAILED:+  failed:$FAILED}"
[ "$fail" -eq 0 ] && exit 0 || exit 1

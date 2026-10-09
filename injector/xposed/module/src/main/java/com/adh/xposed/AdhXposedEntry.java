package com.adh.xposed;

import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * ADH optional LSPosed/Xposed backend — a <b>thin loader</b>, nothing else.
 *
 * <p>Contract: with the
 * framework already loaded into a scoped target process, this module hands that process
 * over to the ADH agent ({@code libadh_agent.so}). Every analysis feature stays in the
 * Host ADH Daemon; the target process only gets the same minimal agent the Zygisk path
 * injects.
 *
 * <p>Slice 1 deliberately keeps the policy small and explicit:
 * <ul>
 *   <li>only the <b>main</b> process of a scoped package</li>
 *   <li>never framework/system packages, never the module's own package</li>
 *   <li>no files are written into third-party targets — the acceptance marker is only
 *       written for ADH's own test hosts (sandbox / Manager)</li>
 * </ul>
 */
public class AdhXposedEntry implements IXposedHookLoadPackage {

    private static final String TAG = "ADH_XPOSED";
    /** Shipped agent library name. */
    private static final String AGENT_LIB = "adh_agent";
    private static final String SELF_PKG = "com.adh.xposed";

    private static final Set<String> NEVER = new HashSet<>(Arrays.asList(
            "android",
            "com.android.systemui",
            "com.android.phone",
            "com.android.settings",
            "com.google.android.gms"));

    /** ADH test hosts that may receive the acceptance marker (never third-party targets). */
    private static final Set<String> MARKER_HOSTS = new HashSet<>(Arrays.asList(
            "com.adh.sandbox",
            "com.adh.manager"));

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            handle(lpparam);
        } catch (Throwable t) {
            // A module must never take the target down with it.
            log("unexpected error: " + t);
        }
    }

    private void handle(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam == null) return;

        final String pkg = lpparam.packageName;
        if (pkg == null || pkg.isEmpty()) return;
        final String proc = lpparam.processName != null ? lpparam.processName : pkg;

        if (SELF_PKG.equals(pkg)) return;
        if (NEVER.contains(pkg)) return;
        if (pkg.startsWith("com.android.")) return;
        if (!pkg.equals(proc)) return;   // main process only in slice 1

        final boolean agentOk = loadAgent();
        log("pkg=" + pkg + " proc=" + proc + " sdk=" + Build.VERSION.SDK_INT
                + " agent=" + (agentOk ? "loaded" : "FAILED"));

        if (MARKER_HOSTS.contains(pkg)) {
            writeMarker(pkg, proc, agentOk);
        }
    }

    /**
     * Bring the agent into this process. The framework puts the module's own
     * {@code lib/<abi>} directory on the module classloader's native search path,
     * so {@link System#loadLibrary} resolves the bundled {@code libadh_agent.so}.
     */
    private boolean loadAgent() {
        try {
            System.loadLibrary(AGENT_LIB);
            return true;
        } catch (Throwable t) {
            log("System.loadLibrary(" + AGENT_LIB + ") failed: " + t);
            return false;
        }
    }

    /**
     * Acceptance marker for ADH's own test hosts only. It gives the verify script an
     * end-to-end signal (the framework reached this process and the loader ran) without
     * leaving artifacts inside real targets.
     */
    private void writeMarker(String pkg, String proc, boolean agentOk) {
        File dir = new File("/data/data/" + pkg + "/files");
        if (!dir.isDirectory()) {
            dir.mkdirs();
        }
        File out = new File(dir, "adh_xposed_ok");
        FileWriter w = null;
        try {
            w = new FileWriter(out, false);
            w.write("ADH_XPOSED_OK pkg=" + pkg + " proc=" + proc
                    + " agent=" + (agentOk ? "1" : "0")
                    + " sdk=" + Build.VERSION.SDK_INT);
        } catch (Throwable t) {
            log("marker write failed: " + t);
        } finally {
            if (w != null) {
                try {
                    w.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /** Framework log (LSPosed/Vector log + logcat) — the operator's view inside a target. */
    private static void log(String msg) {
        Log.i(TAG, msg);
        try {
            XposedBridge.log("[" + TAG + "] " + msg);
        } catch (Throwable ignored) {
        }
    }
}

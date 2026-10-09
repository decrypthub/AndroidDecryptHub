package de.robv.android.xposed;

/**
 * Compile-only ABI declaration — see {@link IXposedHookLoadPackage}.
 *
 * <p>{@code log()} writes into the framework log (LSPosed/Vector log + logcat), which is
 * how an on-device operator sees what the optional backend did inside a target process.
 */
public final class XposedBridge {
    private XposedBridge() {}

    public static void log(String text) {}

    public static void log(Throwable throwable) {}
}
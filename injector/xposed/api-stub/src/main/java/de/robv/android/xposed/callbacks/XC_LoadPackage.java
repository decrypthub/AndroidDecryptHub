package de.robv.android.xposed.callbacks;

/**
 * Compile-only ABI declaration — see {@link de.robv.android.xposed.IXposedHookLoadPackage}.
 *
 * <p>Only the members the ADH loader actually reads are declared. The field names/types
 * must stay identical to the framework's {@code LoadPackageParam}, because the module
 * bytecode resolves them at runtime against the real class.
 */
public abstract class XC_LoadPackage {
    public static class LoadPackageParam {
        public String packageName;
        public String processName;
        public boolean isFirstApplication;
        public ClassLoader classLoader;
    }
}
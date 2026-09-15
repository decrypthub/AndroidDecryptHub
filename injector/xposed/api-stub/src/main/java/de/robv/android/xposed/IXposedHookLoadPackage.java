package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Compile-only ABI declaration for the classic Xposed entry point (API 82/93).
 *
 * <p>ADH does not vendor the upstream Xposed API. This project declares exactly the
 * signatures we link against, and the module depends on it with {@code compileOnly}:
 * at runtime the framework (LSPosed / Vector) supplies the real classes from its own
 * classloader, which is the parent of the module classloader. Nothing from this stub
 * ends up inside the module APK.
 */
public interface IXposedHookLoadPackage {
    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}
package com.adh.daemon;

interface IAdhScopeService {
    int getProtocolVersion();
    String getScopeJson();
    boolean setScopeJson(String json);
    boolean isModulePresent();
    boolean isLoaderActive();
    String getModuleVersion();
    /** Compact JSON catalog: [{"p":"pkg","l":"label","s":false}]. Protocol v2. */
    String listApplications();
    /** PNG bytes for one package icon. Empty if missing. Protocol v3. */
    byte[] getApplicationIconPng(String packageName);
    /**
     * Stop or restart a third-party app. Protocol v4.
     * action is "stop" or "restart".
     * Returns "ok", "denied", "no_launcher", or "failed".
     */
    String controlPackage(String packageName, String action);
    /**
     * Optional Xposed/LSPosed backend (module W). Protocol v5.
     * Compact JSON: {"present":bool,"installed":bool,"enabled":bool,"scope":["pkg",...]}.
     */
    String getXposedStatus();
    /** Enable/disable the ADH Xposed module through the framework CLI. */
    boolean setXposedEnabled(boolean enabled);
    /** Replace the ADH Xposed module's framework scope with these packages (user 0). */
    boolean setXposedScope(in List<String> packages);
    /** Protocol v7: read whether ADH's optional automation AccessibilityService is enabled. */
    boolean isAutomationEnabled();
    /** Protocol v7: enable/disable ADH's automation AccessibilityService after an explicit user action. */
    boolean setAutomationEnabled(boolean enabled);
    /** Protocol v8: compact JSON state: interactive, locked. */
    String getDevicePowerStatus();
    /** Protocol v8: wake the display if it is off. */
    boolean wakeScreen();
    /** Protocol v8: dismiss a non-secure keyguard; secure credentials are never bypassed. */
    boolean dismissKeyguard();
    /**
     * Protocol v9: inject one raw tap at absolute display pixels through the system input binary.
     * Used when the AccessibilityService gesture silently does nothing on some Compose UIs.
     */
    boolean injectInputTap(int x, int y);
    /** Protocol v9: inject one raw swipe (absolute display pixels). */
    boolean injectInputSwipe(int x1, int y1, int x2, int y2, int durationMs);
}
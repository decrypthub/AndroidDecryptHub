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
}

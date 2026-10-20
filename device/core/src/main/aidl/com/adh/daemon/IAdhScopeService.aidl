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
    /** "ipv4:port", or empty when none is stored. Protocol v17. */
    String getHostEndpoint();
    /** Persist the computer an injected process should dial. Protocol v17. */
    boolean setHostEndpoint(String endpoint);
    /** Compact JSON: [{"f","s","b","e","a"}]. Protocol v18. */
    String listCaCerts();
    /**
     * Store CA certificates from PEM or DER. Returns how many were stored,
     * 0 when the bytes contain no CA, or -1 on reject. Protocol v18.
     */
    int putCaCert(in byte[] encoded);
    /** Delete one `hhhhhhhh.N` file. Protocol v18. */
    boolean deleteCaCert(String fileName);
    /** Reboot. The caller must already have confirmed with the user. Protocol v18. */
    boolean rebootDevice();
}

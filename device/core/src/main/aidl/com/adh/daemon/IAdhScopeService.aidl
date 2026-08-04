package com.adh.daemon;

interface IAdhScopeService {
    int getProtocolVersion();
    String getScopeJson();
    boolean setScopeJson(String json);
    boolean isModulePresent();
    boolean isLoaderActive();
    String getModuleVersion();
}

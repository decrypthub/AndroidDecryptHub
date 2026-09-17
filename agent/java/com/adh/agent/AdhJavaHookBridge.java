package com.adh.agent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Fixed LSPlant hooker class bundled with libadh_agent.so.
 *
 * It contains no target knowledge. The native side installs the target method, hook id and
 * backup Method into one instance before calling LSPlant.Hook(). LSPlant routes the target
 * invocation into callback(Object[]); this class invokes the original through the backup and
 * reports one bounded event per hit to the native capture ring.
 */
public final class AdhJavaHookBridge {
    public Method backup;
    public boolean isStatic;
    public int hookId;
    public int hits;
    public String lastArg;
    public String lastReturn;
    public String lastError;
    public String target;

    private static native void nativeReport(int hookId, String target, String arg, String ret, String error);

    public Object callback(Object[] args) throws Throwable {
        hits++;
        int first = isStatic ? 0 : 1;
        if (args != null && args.length > first) {
            Object value = args[first];
            lastArg = value == null ? "null" : String.valueOf(value);
        } else {
            lastArg = "";
        }
        if (backup == null) {
            lastError = "hook backup not ready";
            nativeReport(hookId, target, lastArg, "", lastError);
            throw new IllegalStateException(lastError);
        }
        try {
            Object result = backup.invoke(null, args);
            lastReturn = result == null ? "null" : String.valueOf(result);
            lastError = "";
            nativeReport(hookId, target, lastArg, lastReturn, lastError);
            return result;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            lastError = String.valueOf(cause);
            nativeReport(hookId, target, lastArg, "", lastError);
            throw cause;
        } catch (Throwable t) {
            lastError = String.valueOf(t);
            nativeReport(hookId, target, lastArg, "", lastError);
            throw t;
        }
    }

    public void reset() {
        hits = 0;
        lastArg = "";
        lastReturn = "";
        lastError = "";
    }
}
package com.adh.agent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * Fixed LSPlant hooker class bundled with libadh_agent.so.
 *
 * It contains no target knowledge. The native side installs the target method, hook id and
 * backup Method into one instance before calling LSPlant.Hook(). LSPlant routes the target
 * invocation into callback(Object[]); this class invokes the original through the backup and
 * reports one bounded event per hit to the native capture ring.
 *
 * IMPORTANT: nativeReport's signature is part of the ABI with libadh_agent.so. Changing it here
 * REQUIRES regenerating the dex with tools/build_java_hook_bridge.sh AND updating the RegisterNatives
 * descriptor in agent/src/hook/java_lsplant.cpp in the same change - otherwise the dex fails to
 * verify (loudly) instead of silently dropping events.
 */
public final class AdhJavaHookBridge {
    public Method backup;
    public boolean isStatic;
    // Constructor hooks: args[0] is the object being constructed, the original runs on that
    // same receiver, and the invocation result must stay thisObject (the ctor "returns" the
    // new instance). skipOriginal/overrideReturn are rejected at install time for these.
    public boolean isConstructor;
    public int hookId;
    public int hits;
    public String lastArg;
    public String lastReturn;
    public String lastError;
    public String target;
    public volatile boolean ready;
    public volatile boolean active;
    public boolean skipOriginal;
    public String overrideReturn;
    public int argIndex = -1;
    public String argValue;
    // Opt-in per hook: capture a bounded caller chain at the hit (the Java analogue of
    // Thread.backtrace()). Off by default - it costs a stack walk on every hit.
    public boolean captureStack;
    public String lastStack;

    private static native void nativeReport(int hookId, String target, String arg, String ret, String error, String stack);

    public Object callback(Object[] args) throws Throwable {
        hits++;
        if (captureStack) {
            try {
                lastStack = stackTrace();
            } catch (Throwable t) {
                lastStack = "<stack capture failed: " + t + ">";
            }
        } else {
            lastStack = "";
        }
        int first = isStatic ? 0 : 1;
        try {
            if (args != null && args.length > first) {
                Object value = args[first];
                lastArg = bounded(value);
            } else {
                lastArg = "";
            }
        } catch (Throwable t) {
            lastArg = "<toString failed>";
        }
        if (!ready) {
            long deadline = System.nanoTime() + 50_000_000L;
            while (!ready && System.nanoTime() < deadline) Thread.yield();
        }
        if (!ready || backup == null) {
            lastError = "hook backup not ready";
            nativeReport(hookId, target, lastArg, "", lastError, lastStack);
            throw new IllegalStateException(lastError);
        }
        Object receiver = isStatic ? null : (args != null && args.length > 0 ? args[0] : null);
        Object[] params = isStatic
            ? (args != null ? args : new Object[0])
            : (args != null && args.length > 1 ? Arrays.copyOfRange(args, 1, args.length) : new Object[0]);
        if (active && argIndex >= 0 && argIndex < params.length) {
            try {
                Class<?>[] types = backup.getParameterTypes();
                Object rewritten = convertReturn(argValue, types[argIndex]);
                params[argIndex] = rewritten;
                lastArg = rewritten == null ? "null" : String.valueOf(rewritten);
            } catch (Throwable t) {
                lastError = "argument rewrite failed: " + t;
                nativeReport(hookId, target, lastArg, "", lastError, lastStack);
                throw t;
            }
        }
        if (isConstructor) {
            try {
                backup.invoke(receiver, params);
                lastReturn = bounded(receiver);
                lastError = "";
                nativeReport(hookId, target, lastArg, lastReturn, lastError, lastStack);
                return receiver;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                lastError = String.valueOf(cause);
                nativeReport(hookId, target, lastArg, "", lastError, lastStack);
                throw cause;
            } catch (Throwable t) {
                lastError = String.valueOf(t);
                nativeReport(hookId, target, lastArg, "", lastError, lastStack);
                throw t;
            }
        }
        if (active && skipOriginal) {
            try {
                Object replaced = convertReturn(overrideReturn, backup.getReturnType());
                lastReturn = bounded(replaced);
                lastError = "";
                nativeReport(hookId, target, lastArg, lastReturn, lastError, lastStack);
                return replaced;
            } catch (Throwable t) {
                lastError = "return override failed: " + t;
                nativeReport(hookId, target, lastArg, "", lastError, lastStack);
                throw t;
            }
        }
        try {
            Object result = backup.invoke(receiver, params);
            lastReturn = bounded(result);
            lastError = "";
            nativeReport(hookId, target, lastArg, lastReturn, lastError, lastStack);
            return result;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            lastError = String.valueOf(cause);
            nativeReport(hookId, target, lastArg, "", lastError, lastStack);
            throw cause;
        } catch (Throwable t) {
            lastError = String.valueOf(t);
            nativeReport(hookId, target, lastArg, "", lastError, lastStack);
            throw t;
        }
    }

    private static final int MAX_VALUE_CHARS = 512;
    private static final int MAX_STACK_FRAMES = 12;
    private static final int MAX_STACK_CHARS = 512;

    /**
     * Bounded caller chain captured at the hit: "pkg.Class#method:line <- ..." (innermost first).
     * Frames that belong to the hook plumbing itself are skipped - they tell the operator nothing
     * about who really called the target.
     */
    private static String stackTrace() {
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
        StringBuilder sb = new StringBuilder();
        int written = 0;
        for (StackTraceElement frame : frames) {
            String cls = frame.getClassName();
            // Skip the capture plumbing itself (Thread/VMStack), our own bridge, the ART reflection
            // frame used by java_call, and LSPlant's synthetic subclass for the hooked method - the
            // operator wants the app frames, not our machinery.
            if (cls.equals("java.lang.Thread") || cls.equals("dalvik.system.VMStack") ||
                cls.equals("java.lang.reflect.Method") || cls.startsWith("com.adh.agent.AdhJavaHookBridge") ||
                cls.startsWith("com.android.internal.util.NativeBridge_")) continue;
            if (written++ >= MAX_STACK_FRAMES) break;
            if (sb.length() > 0) sb.append(" <- ");
            sb.append(cls).append('#').append(frame.getMethodName());
            if (frame.getFileName() != null) sb.append(':').append(frame.getLineNumber());
            if (sb.length() >= MAX_STACK_CHARS) break;
        }
        return sb.length() <= MAX_STACK_CHARS ? sb.toString() : sb.substring(0, MAX_STACK_CHARS) + "...";
    }

    private static String bounded(Object value) {
        if (value == null) return "null";
        if (value instanceof String) {
            String text = (String) value;
            return text.length() <= MAX_VALUE_CHARS ? text : text.substring(0, MAX_VALUE_CHARS) + "...";
        }
        if (value instanceof Number || value instanceof Boolean || value instanceof Character) {
            String text = String.valueOf(value);
            return text.length() <= MAX_VALUE_CHARS ? text : text.substring(0, MAX_VALUE_CHARS) + "...";
        }
        return value.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(value));
    }
    private static long parseLongValue(String value) {
        String v = value == null ? "" : value.trim();
        return (v.startsWith("0x") || v.startsWith("0X"))
            ? Long.parseLong(v.substring(2), 16)
            : Long.parseLong(v);
    }

    private static Object convertReturn(String value, Class<?> type) {
        boolean nullish = value == null || value.length() == 0 || value.equalsIgnoreCase("null");
        if (type == void.class || type == Void.class) return null;
        if (type == String.class) return nullish ? null : value;
        if (type == boolean.class || type == Boolean.class) {
            return nullish ? Boolean.FALSE : (Boolean.parseBoolean(value) || "1".equals(value));
        }
        if (type == byte.class || type == Byte.class) return nullish ? (byte) 0 : (byte) parseLongValue(value);
        if (type == char.class || type == Character.class) return nullish ? (char) 0 : (value.isEmpty() ? (char) 0 : value.charAt(0));
        if (type == short.class || type == Short.class) return nullish ? (short) 0 : (short) parseLongValue(value);
        if (type == int.class || type == Integer.class) return nullish ? 0 : (int) parseLongValue(value);
        if (type == long.class || type == Long.class) return nullish ? 0L : parseLongValue(value);
        if (type == float.class || type == Float.class) return nullish ? 0f : Float.parseFloat(value);
        if (type == double.class || type == Double.class) return nullish ? 0d : Double.parseDouble(value);
        if (type == Object.class) return nullish ? null : value;
        if (nullish) return null;
        throw new IllegalArgumentException("unsupported return override type " + type.getName());
    }

    public void reset() {
        hits = 0;
        lastArg = "";
        lastReturn = "";
        lastError = "";
        lastStack = "";
    }
}
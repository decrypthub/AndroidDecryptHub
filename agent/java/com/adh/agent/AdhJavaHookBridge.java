package com.adh.agent;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Key;
import java.util.HashMap;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

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
public final class AdhJavaHookBridge extends X509ExtendedTrustManager implements HostnameVerifier {
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
    // Bypass hooks fire on every handshake. They still count hits, but they do not emit an event.
    public boolean silent;
    // 0 = not an algorithm hook. 1 Cipher.init, 2 Cipher.doFinal, 3 Mac.init, 4 Mac.doFinal,
    // 5 MessageDigest.digest, 7 Signature.initSign/initVerify, 8 Signature.sign/verify.
    public int cryptoMode;

    private static AdhJavaHookBridge trustAll;
    private static final Object MEM = new Object();
    private static final HashMap<Integer, String> OPS = new HashMap<Integer, String>();
    private static final HashMap<Integer, byte[]> KEYS = new HashMap<Integer, byte[]>();
    private static final HashMap<Integer, byte[]> IVS = new HashMap<Integer, byte[]>();

    private static native void nativeReport(int hookId, String target, String arg, String ret, String error, String stack);
    private static native void nativeCrypto(String algo, String op, byte[] key, byte[] iv, byte[] in, byte[] out);

    private void noteHit() {
        try {
            Class<?> log = Class.forName("android.util.Log");
            java.lang.reflect.Method info = log.getMethod("i", String.class, String.class);
            info.invoke(null, "rt.java", "bypass hit " + target);
        } catch (Throwable ignored) {
        }
    }

    private void report(String arg, String ret, String error) {
        if (silent) return;
        nativeReport(hookId, target, arg, ret, error, lastStack);
    }

    /** One trust-all manager. Conscrypt and TrustManagerFactory both accept this instance. */
    public static TrustManager[] trustManagers() {
        if (trustAll == null) {
            AdhJavaHookBridge tm = new AdhJavaHookBridge();
            tm.ready = true;
            tm.active = false;
            trustAll = tm;
        }
        return new TrustManager[] { trustAll };
    }

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
    @Override public boolean verify(String hostname, SSLSession session) { return true; }

    public Object callback(Object[] args) throws Throwable {
        hits++;
        if (silent && cryptoMode == 0 && hits == 1) noteHit();
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
            report(lastArg, "", lastError);
            throw new IllegalStateException(lastError);
        }
        Object receiver = isStatic ? null : (args != null && args.length > 0 ? args[0] : null);
        Object[] params = isStatic
            ? (args != null ? args : new Object[0])
            : (args != null && args.length > 1 ? Arrays.copyOfRange(args, 1, args.length) : new Object[0]);
        if (active && argIndex >= 0 && argIndex < params.length) {
            try {
                Object rewritten;
                if ("@trust".equals(argValue)) {
                    rewritten = trustManagers();
                    lastArg = "trust-all";
                } else {
                    Class<?>[] types = backup.getParameterTypes();
                    rewritten = convertReturn(argValue, types[argIndex]);
                    lastArg = rewritten == null ? "null" : String.valueOf(rewritten);
                }
                params[argIndex] = rewritten;
            } catch (Throwable t) {
                lastError = "argument rewrite failed: " + t;
                report(lastArg, "", lastError);
                throw t;
            }
        }
        if (isConstructor) {
            try {
                backup.invoke(receiver, params);
                lastReturn = bounded(receiver);
                lastError = "";
                report(lastArg, lastReturn, lastError);
                return receiver;
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                lastError = String.valueOf(cause);
                report(lastArg, "", lastError);
                throw cause;
            } catch (Throwable t) {
                lastError = String.valueOf(t);
                report(lastArg, "", lastError);
                throw t;
            }
        }
        if (active && skipOriginal) {
            try {
                Object replaced = skippedReturn(params);
                lastReturn = bounded(replaced);
                lastError = "";
                report(lastArg, lastReturn, lastError);
                return replaced;
            } catch (Throwable t) {
                lastError = "return override failed: " + t;
                report(lastArg, "", lastError);
                throw t;
            }
        }
        try {
            Object result = backup.invoke(receiver, params);
            lastReturn = bounded(result);
            lastError = "";
            report(lastArg, lastReturn, lastError);
            if (cryptoMode != 0) recordCrypto(receiver, params, result);
            return result;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            lastError = String.valueOf(cause);
            report(lastArg, "", lastError);
            throw cause;
        } catch (Throwable t) {
            lastError = String.valueOf(t);
            report(lastArg, "", lastError);
            throw t;
        }
    }

    /** What a skipped call returns. @chain hands the peer certificates back. @trust hands the trust-all array. */
    private Object skippedReturn(Object[] params) {
        if ("@chain".equals(overrideReturn)) return chainReturn(params, backup.getReturnType());
        if ("@trust".equals(overrideReturn)) return trustManagers();
        return convertReturn(overrideReturn, backup.getReturnType());
    }

    private static Object chainReturn(Object[] params, Class<?> type) {
        Object chain = null;
        if (params != null) {
            for (Object param : params) {
                if (param instanceof X509Certificate[] || param instanceof List || param instanceof java.security.cert.Certificate[]) {
                    chain = param;
                    break;
                }
            }
        }
        if (chain == null) {
            if (List.class.isAssignableFrom(type)) return java.util.Collections.emptyList();
            return null;
        }
        if (type == void.class || type == Void.class) return null;
        if (List.class.isAssignableFrom(type)) {
            if (chain instanceof List) return chain;
            if (chain instanceof Object[]) return Arrays.asList((Object[]) chain);
        }
        return chain;
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

    /**
     * Convert a substitution string to a value of the declared type.
     */
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

    private void recordCrypto(Object receiver, Object[] params, Object result) {
        try {
            int id = receiver == null ? 0 : System.identityHashCode(receiver);
            String algo = algorithm(receiver);
            if (cryptoMode == 1 || cryptoMode == 3 || cryptoMode == 7) {
                String op = cryptoMode == 1 ? opMode(params) : (cryptoMode == 3 ? "mac" : sigOp());
                byte[] key = encodedKey(params);
                byte[] iv = parameterIv(params);
                remember(id, op, key, iv);
                nativeCrypto(algo, op, key, iv, null, null);
                return;
            }
            String op;
            byte[] key;
            byte[] iv;
            synchronized (MEM) {
                op = OPS.containsKey(id) ? OPS.get(id) : defaultOp();
                key = KEYS.get(id);
                iv = IVS.get(id);
            }
            byte[] in = inputBytes(params);
            byte[] out = result instanceof byte[] ? (byte[]) result : null;
            nativeCrypto(algo, op, key, iv, in, out);
        } catch (Throwable ignored) {
        }
    }

    private String defaultOp() {
        if (cryptoMode == 4) return "mac";
        if (cryptoMode == 5) return "digest";
        if (cryptoMode == 8) return sigOp();
        return "doFinal";
    }

    private String sigOp() {
        // Method names are initVerify / verify. Match the lowercase form so initVerify is not
        // stored as "sign" and then copied onto the later verify() call.
        String name = target == null ? "" : target.toLowerCase();
        return name.indexOf("verify") >= 0 ? "verify" : "sign";
    }

    private static String opMode(Object[] params) {
        if (params != null && params.length > 0 && params[0] instanceof Integer) {
            int mode = ((Integer) params[0]).intValue();
            if (mode == 1) return "encrypt";
            if (mode == 2) return "decrypt";
            if (mode == 3) return "wrap";
            if (mode == 4) return "unwrap";
        }
        return "init";
    }

    private static String algorithm(Object receiver) {
        if (receiver == null) return "";
        try {
            Method method = receiver.getClass().getMethod("getAlgorithm");
            Object value = method.invoke(receiver);
            return value instanceof String ? (String) value : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static byte[] encodedKey(Object[] params) {
        if (params == null) return null;
        for (Object param : params) {
            if (param instanceof Key) {
                try { return ((Key) param).getEncoded(); } catch (Throwable ignored) { return null; }
            }
        }
        return null;
    }

    private static byte[] parameterIv(Object[] params) {
        if (params == null) return null;
        for (Object param : params) {
            if (param instanceof javax.crypto.spec.IvParameterSpec) {
                return ((javax.crypto.spec.IvParameterSpec) param).getIV();
            }
            if (param instanceof javax.crypto.spec.GCMParameterSpec) {
                return ((javax.crypto.spec.GCMParameterSpec) param).getIV();
            }
        }
        return null;
    }

    private static byte[] inputBytes(Object[] params) {
        if (params == null) return null;
        for (int i = 0; i < params.length; i++) {
            if (!(params[i] instanceof byte[])) continue;
            byte[] raw = (byte[]) params[i];
            if (i + 2 < params.length && params[i + 1] instanceof Integer && params[i + 2] instanceof Integer) {
                int off = ((Integer) params[i + 1]).intValue();
                int len = ((Integer) params[i + 2]).intValue();
                if (off >= 0 && len >= 0 && off <= raw.length && len <= raw.length - off) {
                    return Arrays.copyOfRange(raw, off, off + len);
                }
            }
            return raw;
        }
        return null;
    }

    private static void remember(int id, String op, byte[] key, byte[] iv) {
        synchronized (MEM) {
            if (OPS.size() > 256) {
                OPS.clear();
                KEYS.clear();
                IVS.clear();
            }
            if (op != null) OPS.put(id, op);
            if (key != null) KEYS.put(id, key);
            if (iv != null) IVS.put(id, iv);
        }
    }

    public void reset() {
        hits = 0;
        lastArg = "";
        lastReturn = "";
        lastError = "";
        lastStack = "";
    }
}
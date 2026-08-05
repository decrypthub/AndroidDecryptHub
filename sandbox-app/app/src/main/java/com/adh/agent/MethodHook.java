package com.adh.agent;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * LSPlant callback holder (WS-A). LSPlant swaps the target ArtMethod to route into a
 * generated dex stub that calls this instance's {@code callback(Object[])}; the native side
 * stores the original into {@link #backup}. For an instance method args[0] is the receiver;
 * for a static method args are the real args directly. This class carries no target
 * knowledge — the native side picks what to hook. (For the sandbox self-test it lives in the
 * app; a real target would get a tiny injected dex defining the same class.)
 */
public class MethodHook {
    public Method backup;
    public boolean isStatic;

    // Self-test observation points (read back by the agent to assert the hook fired).
    public static volatile int hits = 0;
    public static volatile String lastArg = "";

    public Object callback(Object[] args) throws Throwable {
        hits++;
        Object receiver = isStatic ? null : (args.length > 0 ? args[0] : null);
        Object[] real = isStatic ? args
                                 : (args.length > 1 ? Arrays.copyOfRange(args, 1, args.length) : new Object[0]);
        if (real.length > 0 && real[0] != null) lastArg = String.valueOf(real[0]);
        return backup.invoke(receiver, real);   // run the original
    }
}

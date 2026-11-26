import com.adh.agent.AdhJavaHookBridge;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/** Compiles the actual shipping bridge, without Android/native stubs replacing its callback. */
public final class HookBridgeLifecycleFixture {
    static final RuntimeException MARKER = new RuntimeException("original-marker");
    static AdhJavaHookBridge current;
    static int calls;
    public static int plus(int value) { calls++; return value + 41; }
    public static String zero() { calls++; return "zero"; }
    public static void voidTarget() { calls++; }
    public static Object fail() { throw MARKER; }
    public static int disableThenReturn(int value) { current.active = false; return value + 41; }
    public static int disableThenThrow() { current.active = false; throw MARKER; }
    public static int acceptMap(SpyMap value) { return 42; }
    public static SpyMap returnMap() { return spy; }
    static SpyMap spy = new SpyMap();
    public static final class SpyMap extends HashMap<String, String> {
        int rendered;
        @Override public String toString() { rendered++; return "private-fixture"; }
    }
    public static final class Box {
        int value = 40;
        String name;
        public int add(int n) { value += n; return value; }
        public void construct(String n) { name = n; }
    }
    static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    static Map<?, ?> memo(String name) throws Exception {
        Field field = AdhJavaHookBridge.class.getDeclaredField(name);
        field.setAccessible(true);
        return (Map<?, ?>) field.get(null);
    }
    static void clearMemo() throws Exception { for (String name : new String[] {"OPS", "KEYS", "IVS"}) memo(name).clear(); }
    static void emptyMemo() throws Exception { for (String name : new String[] {"OPS", "KEYS", "IVS"}) require(memo(name).isEmpty(), name + " changed"); }
    static AdhJavaHookBridge bridge(Method method, boolean isStatic) {
        AdhJavaHookBridge b = new AdhJavaHookBridge();
        b.backup = method; b.isStatic = isStatic; b.ready = true; b.active = false;
        b.silent = true; b.captureStack = true; b.target = "fixture.target";
        b.lastArg = "arg-before"; b.lastReturn = "return-before";
        b.lastError = "error-before"; b.lastStack = "stack-before";
        current = b;
        return b;
    }
    static void untouched(AdhJavaHookBridge b) throws Exception {
        require(b.hits == 0, "inactive hits=" + b.hits);
        require("arg-before".equals(b.lastArg), "inactive argument observed");
        require("return-before".equals(b.lastReturn), "inactive return observed");
        require("error-before".equals(b.lastError), "inactive exception observed");
        require("stack-before".equals(b.lastStack), "inactive stack observed");
        emptyMemo();
    }
    static Method method(String name, Class<?>... types) throws Exception { return HookBridgeLifecycleFixture.class.getMethod(name, types); }
    public static void main(String[] args) throws Throwable {
        clearMemo(); calls = 0;
        String test = args[0];
        if (test.equals("inactive-static")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true);
            b.argIndex = 0; b.argValue = "99"; b.skipOriginal = true; b.overrideReturn = "999";
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "disabled hook rewrote original");
            require(calls == 1, "original did not run exactly once"); untouched(b);
        } else if (test.equals("inactive-crypto")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.cryptoMode = 1;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "original result changed"); untouched(b);
        } else if (test.equals("inactive-nonsilent")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.silent = false;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "disabled report changed call"); untouched(b);
        } else if (test.equals("inactive-instance")) {
            Box box = new Box(); AdhJavaHookBridge b = bridge(Box.class.getMethod("add", int.class), false);
            b.argIndex = 0; b.argValue = "99";
            require(Integer.valueOf(42).equals(b.callback(new Object[] {box, 2})), "instance args/receiver changed");
            require(box.value == 42, "instance side effect changed"); untouched(b);
        } else if (test.equals("inactive-constructor")) {
            Box box = new Box(); AdhJavaHookBridge b = bridge(Box.class.getMethod("construct", String.class), false); b.isConstructor = true;
            require(b.callback(new Object[] {box, "created"}) == box, "constructor did not return receiver");
            require("created".equals(box.name), "constructor body did not run"); untouched(b);
        } else if (test.equals("inactive-exception")) {
            AdhJavaHookBridge b = bridge(method("fail"), true);
            try { b.callback(null); throw new AssertionError("exception swallowed"); } catch (RuntimeException e) { require(e == MARKER, "exception identity changed"); }
            untouched(b);
        } else if (test.equals("inactive-void")) {
            AdhJavaHookBridge b = bridge(method("voidTarget"), true); b.skipOriginal = true;
            require(b.callback(null) == null && calls == 1, "void original changed"); untouched(b);
        } else if (test.equals("inactive-null-args")) {
            AdhJavaHookBridge b = bridge(method("zero"), true);
            require("zero".equals(b.callback(null)), "zero-argument call changed"); untouched(b);
        } else if (test.equals("inactive-not-ready")) {
            AdhJavaHookBridge b = bridge(null, true); b.ready = false; b.silent = false;
            try { b.callback(null); throw new AssertionError("missing backup accepted"); } catch (IllegalStateException e) { require("hook backup not ready".equals(e.getMessage()), "readiness error changed"); }
            untouched(b);
        } else if (test.equals("inactive-argument-observation")) {
            spy = new SpyMap(); AdhJavaHookBridge b = bridge(method("acceptMap", SpyMap.class), true);
            require(Integer.valueOf(42).equals(b.callback(new Object[] {spy})), "original result changed");
            require(spy.rendered == 0, "disabled hook invoked argument toString"); untouched(b);
        } else if (test.equals("inactive-return-observation")) {
            spy = new SpyMap(); AdhJavaHookBridge b = bridge(method("returnMap"), true);
            require(b.callback(null) == spy, "return identity changed");
            require(spy.rendered == 0, "disabled hook invoked return toString"); untouched(b);
        } else if (test.equals("deactivate-during-return")) {
            AdhJavaHookBridge b = bridge(method("disableThenReturn", int.class), true); b.active = true; b.cryptoMode = 1;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "in-flight original result changed");
            require(b.hits == 1 && "return-before".equals(b.lastReturn), "post-disable return observed"); emptyMemo();
        } else if (test.equals("deactivate-during-exception")) {
            AdhJavaHookBridge b = bridge(method("disableThenThrow"), true); b.active = true;
            try { b.callback(null); throw new AssertionError("exception swallowed"); } catch (RuntimeException e) { require(e == MARKER, "exception identity changed"); }
            require("error-before".equals(b.lastError), "post-disable exception observed"); emptyMemo();
        } else if (test.equals("active-positive-control")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.active = true;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "active original changed");
            require(b.hits == 1 && "42".equals(b.lastReturn), "active observation was removed");
        } else if (test.equals("active-crypto-positive-control")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.active = true; b.cryptoMode = 1;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "active crypto original changed");
            require(memo("OPS").size() == 1, "active crypto bookkeeping was removed");
        } else if (test.equals("active-argument-rewrite")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.active = true; b.argIndex = 0; b.argValue = "2";
            require(Integer.valueOf(43).equals(b.callback(new Object[] {1})) && calls == 1, "active rewrite was removed");
        } else if (test.equals("active-return-override")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true); b.active = true; b.skipOriginal = true; b.overrideReturn = "999";
            require(Integer.valueOf(999).equals(b.callback(new Object[] {1})) && calls == 0, "active override was removed");
        } else if (test.equals("reactivate-positive-control")) {
            AdhJavaHookBridge b = bridge(method("plus", int.class), true);
            b.callback(new Object[] {1}); b.active = true;
            require(Integer.valueOf(42).equals(b.callback(new Object[] {1})), "reactivated original changed");
            require(b.hits == 1 && calls == 2, "reactivation lost original or counted disabled call");
        } else throw new AssertionError("unknown fixture case " + test);
        System.out.println("PASS " + test);
    }
}

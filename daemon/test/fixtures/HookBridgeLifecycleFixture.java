import com.adh.agent.AdhJavaHookBridge;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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
    static void enable(AdhJavaHookBridge b, boolean on) {
        try { b.getClass().getMethod("setEnabled", boolean.class).invoke(b, on); }
        catch (NoSuchMethodException e) { b.active = on; } // Exercise the old ABI for the baseline.
        catch (Exception e) { throw new RuntimeException(e); }
    }
    static void cycle() { enable(current,false); enable(current,true); }
    public static int cycleThenReturn(int value) { cycle(); return value + 41; }
    public static int cycleThenThrow() { cycle(); throw MARKER; }
    static CountDownLatch entered, release;
    public static int blockedPlus(int value) throws Exception {
        calls++; entered.countDown(); require(release.await(5,TimeUnit.SECONDS),"release timed out");return value+41;
    }
    public static int interleavedPlus(int value) throws Exception {
        if(value==1){entered.countDown();require(release.await(5,TimeUnit.SECONDS),"release timed out");}return value+41;
    }
    public static int acceptMap(SpyMap value) { return 42; }
    public static SpyMap returnMap() { return spy; }
    static SpyMap spy = new SpyMap();
    public static final class SpyMap extends HashMap<String, String> {
        int rendered;
        boolean cycleOnRender;
        @Override public String toString() { rendered++; if(cycleOnRender)cycle(); return "private-fixture"; }
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
        if(test.equals("concurrent-call-provenance")) {
            entered=new CountDownLatch(1);release=new CountDownLatch(1);final AdhJavaHookBridge b=bridge(method("interleavedPlus",int.class),true);b.active=true;
            AtomicReference<Throwable> failure=new AtomicReference<Throwable>();Thread first=new Thread(new Runnable(){public void run(){try{require(Integer.valueOf(42).equals(b.callback(new Object[]{1})),"first original changed");}catch(Throwable t){failure.set(t);}}});first.start();
            require(entered.await(2,TimeUnit.SECONDS),"first never entered");require(Integer.valueOf(43).equals(b.callback(new Object[]{2})),"second original changed");
            release.countDown();first.join(2000);require(!first.isAlive()&&failure.get()==null,"first failed");
            require(b.lastArg.contains("1")&&!b.lastArg.contains("2")&&"42".equals(b.lastReturn),"event combined another invocation's arguments with this return");
        } else if (test.equals("epoch-return")) {
            AdhJavaHookBridge b=bridge(method("cycleThenReturn",int.class),true);b.active=true;b.cryptoMode=1;
            require(Integer.valueOf(42).equals(b.callback(new Object[]{1})),"original result changed");
            require("return-before".equals(b.lastReturn),"old generation returned into new generation");emptyMemo();
        } else if(test.equals("epoch-exception")) {
            AdhJavaHookBridge b=bridge(method("cycleThenThrow"),true);b.active=true;
            try{b.callback(null);throw new AssertionError("exception swallowed");}catch(RuntimeException e){require(e==MARKER,"original exception identity changed");}
            require("error-before".equals(b.lastError),"old exception entered new generation");
        } else if(test.equals("epoch-argument-render")) {
            spy=new SpyMap();spy.cycleOnRender=true;AdhJavaHookBridge b=bridge(method("acceptMap",SpyMap.class),true);b.active=true;b.argIndex=0;b.argValue="2";
            require(Integer.valueOf(42).equals(b.callback(new Object[]{spy})),"old generation rewrote original");
            require("arg-before".equals(b.lastArg)&&"return-before".equals(b.lastReturn),"reentrant argument render committed stale data");emptyMemo();
        } else if(test.equals("epoch-return-render")) {
            spy=new SpyMap();spy.cycleOnRender=true;AdhJavaHookBridge b=bridge(method("returnMap"),true);b.active=true;
            require(b.callback(null)==spy,"return identity changed");require(spy.rendered==1,"return not rendered once");
            require("return-before".equals(b.lastReturn),"reentrant return render committed stale data");
        } else if(test.equals("epoch-original-unlocked")) {
            entered=new CountDownLatch(1);release=new CountDownLatch(1);final AdhJavaHookBridge b=bridge(method("blockedPlus",int.class),true);b.active=true;
            AtomicReference<Object> result=new AtomicReference<Object>();AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
            Thread call=new Thread(new Runnable(){public void run(){try{result.set(b.callback(new Object[]{1}));}catch(Throwable t){failure.set(t);}}});call.start();
            require(entered.await(2,TimeUnit.SECONDS),"original never entered");
            Thread control=new Thread(new Runnable(){public void run(){enable(b,false);enable(b,true);}});control.start();control.join(1000);boolean unlocked=!control.isAlive();
            release.countDown();call.join(2000);control.join(2000);require(unlocked,"controller blocked behind original method");
            require(failure.get()==null&&Integer.valueOf(42).equals(result.get()),"in-flight original changed");
            require("return-before".equals(b.lastReturn),"old concurrent invocation committed stale result");
            require(Integer.valueOf(42).equals(b.callback(new Object[]{1})),"new generation failed");require(b.hits==2&&"42".equals(b.lastReturn),"new generation did not observe");
        } else if(test.equals("clear-crypto-memo")) {
            AdhJavaHookBridge b=bridge(method("plus",int.class),true);b.active=true;b.cryptoMode=1;b.callback(new Object[]{1});
            require(memo("OPS").size()==1,"positive memo absent");b.getClass().getMethod("clearCryptoMemo").invoke(null);emptyMemo();
        } else if(test.equals("epoch-exhaustion")) {
            AdhJavaHookBridge b=bridge(method("plus",int.class),true);Field f=b.getClass().getField("observationEpoch");f.setLong(b,Long.MAX_VALUE);b.active=true;
            try{b.getClass().getMethod("setEnabled",boolean.class).invoke(b,true);throw new AssertionError("epoch wrapped");}
            catch(java.lang.reflect.InvocationTargetException e){require(e.getCause() instanceof IllegalStateException,"wrong exhaustion error");}
            require(!b.active&&f.getLong(b)==Long.MAX_VALUE,"epoch exhausted but active");require(Integer.valueOf(42).equals(b.callback(new Object[]{1})),"original stopped after exhaustion");untouched(b);
        } else if (test.equals("inactive-static")) {
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

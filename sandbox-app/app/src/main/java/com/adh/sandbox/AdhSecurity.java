package com.adh.sandbox;

import android.util.Log;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.io.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.Mac;
import javax.crypto.MacSpi;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Java-layer crypto interception. An interposing JCE {@link Provider} inserted at the
 * highest priority wraps Cipher / Mac / MessageDigest: it delegates the real computation
 * to the platform provider (so results are byte-identical) while capturing the full
 * context at the Java API boundary — algorithm string, operation, key, IV, input, output —
 * which is far richer than the native EVP hook (that only sees raw update buffers).
 *
 * This catches pure-Java crypto too, and binds algorithm+key+IV that the native layer
 * can't easily recover. Apps that pin an explicit provider bypass this; the native EVP
 * GOT hook remains the bypass-proof backstop. Designed to be relocatable into an
 * agent-injected dex for arbitrary targets (here it lives in the sandbox for verification).
 */
public final class AdhSecurity {
    private static final String TAG = "ADH_SANDBOX";
    private static final String NAME = "ADH-Intercept";

    // transforms/algorithms we interpose (the common surface; extendable)
    private static final String[] CIPHERS = {
        "AES/CBC/PKCS5Padding", "AES/CTR/NoPadding", "AES/GCM/NoPadding",
        "AES/ECB/PKCS5Padding", "DESede/CBC/PKCS5Padding", "DES/CBC/PKCS5Padding",
        "RSA/ECB/PKCS1Padding",   // 非对称：也走 Cipher，包住即可拿到公钥/明文/密文
    };
    private static final String[] DIGESTS = { "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512" };
    private static final String[] MACS = { "HmacSHA1", "HmacSHA256", "HmacSHA512", "HmacMD5" };

    private static volatile boolean installed = false;

    public static synchronized void install() {
        if (installed) return;
        try {
            Provider p = new AdhProvider();
            Security.insertProviderAt(p, 1);   // priority 1 → default getInstance picks us
            installed = true;
            Log.i(TAG, "AdhSecurity installed (Java-layer crypto interception)");
        } catch (Throwable t) {
            Log.w(TAG, "AdhSecurity install failed: " + t);
        }
    }

    // Find a real provider (not ours) that offers type.algorithm, to delegate to.
    static Provider delegateProvider(String type, String algorithm) {
        for (Provider p : Security.getProviders()) {
            if (NAME.equals(p.getName())) continue;
            if (p.getService(type, algorithm) != null) return p;
        }
        return null;
    }

    static byte[] keyBytes(Key k) { try { return k == null ? null : k.getEncoded(); } catch (Throwable t) { return null; } }
    static byte[] ivOf(AlgorithmParameterSpec s) {
        try {
            if (s instanceof IvParameterSpec) return ((IvParameterSpec) s).getIV();
            if (s instanceof GCMParameterSpec) return ((GCMParameterSpec) s).getIV();
        } catch (Throwable t) {}
        return null;
    }

    // ------------------------------------------------------------------ provider
    static final class AdhProvider extends Provider {
        AdhProvider() {
            super(NAME, 1.0, "ADH Java-layer crypto interceptor");
            for (String t : CIPHERS) putService(new Svc(this, "Cipher", t));
            for (String d : DIGESTS) putService(new Svc(this, "MessageDigest", d));
            for (String m : MACS)    putService(new Svc(this, "Mac", m));
        }
    }

    // Custom Service so the SPI knows the exact transform it was requested for.
    static final class Svc extends Provider.Service {
        Svc(Provider p, String type, String algo) { super(p, type, algo, "com.adh.sandbox.AdhSecurity$Spi", null, null); }
        @Override public Object newInstance(Object ctorParam) {
            String type = getType();
            String algo = getAlgorithm();
            if ("Cipher".equals(type)) return new WrapCipher(algo);
            if ("Mac".equals(type)) return new WrapMac(algo);
            return new WrapDigest(algo);
        }
    }
    // marker (referenced by class name in Svc; concrete SPIs are the Wrap* below)
    public static final class Spi {}

    // ------------------------------------------------------------------ Cipher
    static final class WrapCipher extends CipherSpi {
        private final String transform;
        private Cipher delegate;
        private int opmode;
        private byte[] key, iv;
        private final ByteArrayOutputStream acc = new ByteArrayOutputStream();
        WrapCipher(String t) { this.transform = t; }

        private void ensure() throws Exception {
            if (delegate == null) {
                Provider p = delegateProvider("Cipher", transform);
                delegate = (p != null) ? Cipher.getInstance(transform, p) : Cipher.getInstance(transform);
            }
        }
        @Override protected void engineSetMode(String mode) {}
        @Override protected void engineSetPadding(String padding) {}
        @Override protected int engineGetBlockSize() { return delegate != null ? delegate.getBlockSize() : 16; }
        @Override protected int engineGetOutputSize(int inputLen) { return delegate != null ? delegate.getOutputSize(inputLen) : inputLen + 16; }
        @Override protected byte[] engineGetIV() { return delegate != null ? delegate.getIV() : iv; }
        @Override protected AlgorithmParameters engineGetParameters() { return delegate != null ? delegate.getParameters() : null; }

        @Override protected void engineInit(int opmode, Key key, SecureRandom random) {
            try { ensure(); this.opmode = opmode; this.key = keyBytes(key); acc.reset(); delegate.init(opmode, key, random); }
            catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
            try { ensure(); this.opmode = opmode; this.key = keyBytes(key); this.iv = ivOf(params); acc.reset(); delegate.init(opmode, key, params, random); }
            catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {
            try { ensure(); this.opmode = opmode; this.key = keyBytes(key); acc.reset(); delegate.init(opmode, key, params, random);
                  try { this.iv = delegate.getIV(); } catch (Throwable t) {} }
            catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected byte[] engineUpdate(byte[] input, int off, int len) {
            if (input != null && len > 0) acc.write(input, off, len);
            return delegate.update(input, off, len);
        }
        @Override protected int engineUpdate(byte[] input, int off, int len, byte[] output, int outOff) {
            try { if (input != null && len > 0) acc.write(input, off, len); return delegate.update(input, off, len, output, outOff); }
            catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected byte[] engineDoFinal(byte[] input, int off, int len) {
            try {
                if (input != null && len > 0) acc.write(input, off, len);
                byte[] out = delegate.doFinal(input, off, len);
                emit(out);
                return out;
            } catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected int engineDoFinal(byte[] input, int off, int len, byte[] output, int outOff) {
            try {
                if (input != null && len > 0) acc.write(input, off, len);
                int n = delegate.doFinal(input, off, len, output, outOff);
                byte[] out = new byte[n]; System.arraycopy(output, outOff, out, 0, n);
                emit(out);
                return n;
            } catch (Exception e) { throw new RuntimeException(e); }
        }
        private void emit(byte[] out) {
            String op = (opmode == Cipher.ENCRYPT_MODE) ? "encrypt" : (opmode == Cipher.DECRYPT_MODE) ? "decrypt" : "cipher";
            AdhReport.report(transform, op, key, iv, acc.toByteArray(), out);
            acc.reset();
        }
    }

    // ------------------------------------------------------------------ MessageDigest
    static final class WrapDigest extends MessageDigestSpi {
        private final String algo;
        private MessageDigest delegate;
        private final ByteArrayOutputStream acc = new ByteArrayOutputStream();
        WrapDigest(String a) { this.algo = a; ensure(); }
        private void ensure() {
            if (delegate == null) try { Provider p = delegateProvider("MessageDigest", algo);
                delegate = (p != null) ? MessageDigest.getInstance(algo, p) : MessageDigest.getInstance(algo); } catch (Exception e) {}
        }
        @Override protected void engineUpdate(byte input) { acc.write(input); delegate.update(input); }
        @Override protected void engineUpdate(byte[] input, int off, int len) { if (len > 0) acc.write(input, off, len); delegate.update(input, off, len); }
        @Override protected byte[] engineDigest() {
            byte[] out = delegate.digest();
            AdhReport.report(algo, "digest", null, null, acc.toByteArray(), out);
            acc.reset();
            return out;
        }
        @Override protected void engineReset() { acc.reset(); delegate.reset(); }
        @Override protected int engineGetDigestLength() { return delegate != null ? delegate.getDigestLength() : 0; }
    }

    // ------------------------------------------------------------------ Mac
    static final class WrapMac extends MacSpi {
        private final String algo;
        private Mac delegate;
        private byte[] key;
        private final ByteArrayOutputStream acc = new ByteArrayOutputStream();
        WrapMac(String a) { this.algo = a; }
        private void ensure() { if (delegate == null) try { Provider p = delegateProvider("Mac", algo);
            delegate = (p != null) ? Mac.getInstance(algo, p) : Mac.getInstance(algo); } catch (Exception e) {} }
        @Override protected int engineGetMacLength() { ensure(); return delegate != null ? delegate.getMacLength() : 0; }
        @Override protected void engineInit(Key k, AlgorithmParameterSpec params) {
            try { ensure(); this.key = keyBytes(k); acc.reset(); delegate.init(k, params); } catch (Exception e) { throw new RuntimeException(e); }
        }
        @Override protected void engineUpdate(byte input) { acc.write(input); delegate.update(input); }
        @Override protected void engineUpdate(byte[] input, int off, int len) { if (len > 0) acc.write(input, off, len); delegate.update(input, off, len); }
        @Override protected byte[] engineDoFinal() {
            byte[] out = delegate.doFinal();
            AdhReport.report(algo, "hmac", key, null, acc.toByteArray(), out);
            acc.reset();
            return out;
        }
        @Override protected void engineReset() { acc.reset(); if (delegate != null) delegate.reset(); }
    }

    private AdhSecurity() {}
}

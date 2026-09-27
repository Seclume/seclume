package space.seclume.crypto;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.internal.Platform;

/**
 * A private key for signing - RSA or EC - held by OpenSSL and never by the JVM.
 *
 * <p>The key arrives as PEM or DER in native memory, read there by a secret
 * provider, and is decoded by OpenSSL's own decoder ({@code OSSL_DECODER}):
 * PKCS#8, PKCS#1 ({@code RSA PRIVATE KEY}) and SEC 1 ({@code EC PRIVATE KEY})
 * alike. From then on it is an {@code EVP_PKEY} in OpenSSL's memory, and what
 * this class hands out is a signature - which is public - over a message,
 * which is the caller's.
 *
 * <p>For JWS: {@code RS256}/{@code RS384}/{@code RS512} (PKCS#1 v1.5),
 * {@code PS256}/{@code PS384}/{@code PS512} (PSS, salt as long as the digest)
 * and {@code ES256}/{@code ES384}/{@code ES512} - the ECDSA signature comes
 * back as OpenSSL writes it, DER; JWS wants {@code r || s}, which
 * {@link #rawEcdsa} makes of it.
 *
 * <p>OpenSSL 3 on 64-bit Linux, where libcrypto is found; elsewhere
 * {@link #available()} says no.
 */
public final class OpenSslSigningKey implements AutoCloseable {

    /** The largest signature this makes: RSA-8192. */
    public static final int MAX_SIGNATURE = 1024;

    private static final int PARAM_SIZE = 40;
    private static final int PRIVATE_KEY_SELECTION = 0x87;   // keypair and parameters

    private MemorySegment key;

    private OpenSslSigningKey(MemorySegment key) {
        this.key = key;
    }

    /** Whether OpenSSL 3's libcrypto can be used here. */
    public static boolean available() {
        if (!Platform.isLinux() || ValueLayout.ADDRESS.byteSize() != 8) {
            return false;
        }
        try {
            return Native.LIB != null;
        } catch (LinkageError | RuntimeException e) {
            return false;
        }
    }

    /**
     * Decodes a private key from {@code length} bytes of PEM or DER at the start
     * of {@code encoded}, which stays the caller's to wipe.
     */
    public static OpenSslSigningKey decode(MemorySegment encoded, int length) {
        if (!available()) {
            throw new IllegalStateException("signing with a private key needs OpenSSL 3 on "
                    + "64-bit Linux, which is not there");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment result = arena.allocate(ADDRESS);
            result.set(ADDRESS, 0, NULL);
            MemorySegment decoder = Native.pointer(Native.DECODER_NEW, result, NULL, NULL, NULL,
                    PRIVATE_KEY_SELECTION, NULL, NULL);
            try {
                MemorySegment data = arena.allocate(ADDRESS);
                data.set(ADDRESS, 0, encoded);
                MemorySegment left = arena.allocate(JAVA_LONG);
                left.set(JAVA_LONG, 0, length);
                if ((int) Native.invoke(Native.DECODE, decoder, data, left) != 1) {
                    throw new IllegalArgumentException("the private key could not be read - "
                            + "PEM or DER, PKCS#8, PKCS#1 or SEC 1, without a passphrase "
                            + "(for a key encrypted at rest, use provider=encrypted)");
                }
            } finally {
                Native.invoke(Native.DECODER_FREE, decoder);
            }
            MemorySegment decoded = result.get(ADDRESS, 0);
            if (decoded.equals(NULL)) {
                throw new IllegalArgumentException("no private key in what was given");
            }
            return new OpenSslSigningKey(decoded);
        }
    }

    /** {@code RSA}, {@code EC}, {@code RSA-PSS} ... - whether this key is of that type. */
    public boolean is(String type) {
        checkOpen();
        try (Arena arena = Arena.ofConfined()) {
            return (int) Native.invoke(Native.IS_A, key, arena.allocateFrom(type)) == 1;
        }
    }

    /**
     * The public half, as a DER {@code SubjectPublicKeyInfo} - what a
     * certificate carries and {@code X509EncodedKeySpec} reads. Public, and so
     * a {@code byte[]}.
     */
    public byte[] publicKey() {
        checkOpen();
        int length = (int) Native.invoke(Native.PUBLIC_KEY, key, NULL);
        if (length <= 0) {
            throw new IllegalStateException("OpenSSL could not encode the public key");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            MemorySegment cursor = arena.allocate(ADDRESS);
            cursor.set(ADDRESS, 0, out);
            if ((int) Native.invoke(Native.PUBLIC_KEY, key, cursor) != length) {
                throw new IllegalStateException("OpenSSL encoded the public key twice "
                        + "differently");
            }
            return out.toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * Signs {@code length} bytes of {@code message}, hashing them with
     * {@code digest} ({@code SHA256}, {@code SHA384}, {@code SHA512}); with
     * {@code pss}, RSA-PSS with a salt as long as the digest.
     *
     * @return how many bytes of {@code signature} were written
     */
    public int sign(String digest, boolean pss, MemorySegment message, long length,
                    MemorySegment signature) {
        checkOpen();
        if (pss && !is("RSA") && !is("RSA-PSS")) {
            // OpenSSL takes the padding parameter for an EC key and signs anyway;
            // PSS on a key that cannot do it is a configuration mistake, said here
            throw new IllegalStateException("PSS needs an RSA key, and this one is not");
        }
        MemorySegment context = Native.pointer(Native.MD_NEW);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment params = NULL;
            if (pss) {
                params = arena.allocate(3L * PARAM_SIZE, 8);
                utf8(arena, params, 0, "pad-mode", "pss");
                utf8(arena, params, 1, "saltlen", "digest");
            }
            Native.ok(Native.SIGN_INIT, context, NULL, arena.allocateFrom(digest), NULL, NULL,
                    key, params);
            MemorySegment written = arena.allocate(JAVA_LONG);
            written.set(JAVA_LONG, 0, signature.byteSize());
            Native.ok(Native.SIGN, context, signature, written, message, length);
            long size = written.get(JAVA_LONG, 0);
            if (size <= 0 || size > signature.byteSize()) {
                throw new IllegalStateException("unexpected OpenSSL signature length");
            }
            return (int) size;
        } finally {
            Native.invoke(Native.MD_FREE, context);
        }
    }

    /**
     * An ECDSA signature in DER ({@code SEQUENCE { r, s }}) as JWS wants it:
     * {@code r || s}, each padded to {@code field} bytes. The signature is
     * public; this is only its other spelling.
     */
    public static byte[] rawEcdsa(byte[] der, int field) {
        int at = 2;
        if ((der[1] & 0x80) != 0) {
            at = 2 + (der[1] & 0x7f);
        }
        byte[] raw = new byte[2 * field];
        for (int part = 0; part < 2; part++) {
            if (der[at] != 0x02) {
                throw new IllegalArgumentException("not a DER ECDSA signature");
            }
            int length = der[at + 1] & 0xff;
            int start = at + 2;
            while (length > field && der[start] == 0) {
                start++;
                length--;
            }
            if (length > field) {
                throw new IllegalArgumentException("an ECDSA integer longer than the field");
            }
            System.arraycopy(der, start, raw, part * field + field - length, length);
            at = start + length;
        }
        return raw;
    }

    @Override
    public void close() {
        MemorySegment old = key;
        key = NULL;
        if (!old.equals(NULL)) {
            Native.invoke(Native.KEY_FREE, old);
        }
    }

    private void checkOpen() {
        if (key.equals(NULL)) {
            throw new IllegalStateException("this signing key is closed");
        }
    }

    private static void utf8(Arena arena, MemorySegment params, int index, String name,
                             String value) {
        long at = (long) index * PARAM_SIZE;
        MemorySegment text = arena.allocateFrom(value);
        params.set(ADDRESS, at, arena.allocateFrom(name));
        params.set(JAVA_INT, at + 8, 4);                     // OSSL_PARAM_UTF8_STRING
        params.set(ADDRESS, at + 16, text);
        params.set(JAVA_LONG, at + 24, value.length());
        params.set(JAVA_LONG, at + 32, -1L);
    }

    /** The downcalls, bound on first use - so that {@link #available()} can say no. */
    private static final class Native {

        static final SymbolLookup LIB =
                SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());

        static final MethodHandle DECODER_NEW = bind("OSSL_DECODER_CTX_new_for_pkey",
                ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS);
        static final MethodHandle DECODE = bind("OSSL_DECODER_from_data",
                JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
        static final MethodHandle DECODER_FREE = bind("OSSL_DECODER_CTX_free", null, ADDRESS);
        static final MethodHandle IS_A = bind("EVP_PKEY_is_a", JAVA_INT, ADDRESS, ADDRESS);
        static final MethodHandle MD_NEW = bind("EVP_MD_CTX_new", ADDRESS);
        static final MethodHandle MD_FREE = bind("EVP_MD_CTX_free", null, ADDRESS);
        static final MethodHandle SIGN_INIT = bind("EVP_DigestSignInit_ex",
                JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
        static final MethodHandle SIGN = bind("EVP_DigestSign",
                JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
        static final MethodHandle KEY_FREE = bind("EVP_PKEY_free", null, ADDRESS);
        static final MethodHandle PUBLIC_KEY = bind("i2d_PUBKEY", JAVA_INT, ADDRESS, ADDRESS);

        private static MethodHandle bind(String name, ValueLayout result,
                                         ValueLayout... arguments) {
            FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(arguments)
                    : FunctionDescriptor.of(result, arguments);
            return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                    descriptor);
        }

        static Object invoke(MethodHandle function, Object... arguments) {
            try {
                return function.invokeWithArguments(arguments);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException("OpenSSL signing downcall failed", e);
            }
        }

        static void ok(MethodHandle function, Object... arguments) {
            if ((int) invoke(function, arguments) != 1) {
                throw new IllegalStateException("OpenSSL signing failed - does the algorithm "
                        + "fit the key (RS/PS for RSA, ES for EC)?");
            }
        }

        static MemorySegment pointer(MethodHandle function, Object... arguments) {
            MemorySegment result = (MemorySegment) invoke(function, arguments);
            if (result.equals(NULL)) {
                throw new IllegalStateException("OpenSSL allocation failure");
            }
            return result;
        }
    }
}

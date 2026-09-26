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
 * The hybrid post-quantum key exchange TLS calls {@code X25519MLKEM768}
 * (group 0x11EC): ML-KEM-768 and X25519 together, so that the session keys
 * hold as long as either of the two does - against "harvest now, decrypt
 * later", where recorded traffic waits for a quantum computer.
 *
 * <p>Through OpenSSL 3.5 or later, like P-256: the private keys belong to
 * OpenSSL and never become Java objects, and the shared secret is written into
 * the caller's native memory. Where OpenSSL 3.5 is not there - Windows, an
 * older Linux - {@link #available()} says so, and the client offers P-256
 * alone as before.
 *
 * <p>The layout follows the IETF definition: the client's share is the ML-KEM
 * encapsulation key (1184 bytes) followed by the X25519 public key (32); the
 * server's is the ML-KEM ciphertext (1088) followed by its X25519 key (32);
 * the shared secret is the ML-KEM secret followed by the X25519 one, 64 bytes.
 */
public final class HybridMlKem implements AutoCloseable {

    /** The TLS group number. */
    public static final int GROUP = 0x11EC;
    public static final int CLIENT_SHARE = 1184 + 32;
    public static final int SERVER_SHARE = 1088 + 32;
    public static final int SECRET = 64;

    private static final int ML_KEM_KEY = 1184;
    private static final int ML_KEM_CIPHERTEXT = 1088;
    private static final int X25519 = 32;

    private MemorySegment mlKem;
    private MemorySegment x25519;

    private HybridMlKem(MemorySegment mlKem, MemorySegment x25519) {
        this.mlKem = mlKem;
        this.x25519 = x25519;
    }

    /** Whether this platform has what it takes: 64-bit Linux with OpenSSL 3.5 or later. */
    public static boolean available() {
        return Native.AVAILABLE;
    }

    /** A fresh pair of both keys. */
    public static HybridMlKem generate() {
        if (!available()) {
            throw new IllegalStateException("X25519MLKEM768 needs OpenSSL 3.5 on 64-bit Linux");
        }
        MemorySegment kem = Native.generate("ML-KEM-768");
        try {
            return new HybridMlKem(kem, Native.generate("X25519"));
        } catch (RuntimeException | Error e) {
            Native.free(kem);
            throw e;
        }
    }

    /** The client's key share, {@link #CLIENT_SHARE} bytes. */
    public void publicShare(MemorySegment out) {
        Native.rawPublic(mlKem, out.asSlice(0, ML_KEM_KEY), ML_KEM_KEY);
        Native.rawPublic(x25519, out.asSlice(ML_KEM_KEY, X25519), X25519);
    }

    /**
     * The shared secret from the server's share: {@link #SECRET} bytes into
     * {@code out}, which should be a SecretScope's native memory.
     */
    public void derive(MemorySegment serverShare, MemorySegment out) {
        if (serverShare.byteSize() != SERVER_SHARE) {
            throw new IllegalArgumentException("an X25519MLKEM768 server share is "
                    + SERVER_SHARE + " bytes, not " + serverShare.byteSize());
        }
        Native.decapsulate(mlKem, serverShare.asSlice(0, ML_KEM_CIPHERTEXT), out.asSlice(0, 32));
        Native.x25519(x25519, serverShare.asSlice(ML_KEM_CIPHERTEXT, X25519), out.asSlice(32, 32));
    }

    @Override
    public void close() {
        MemorySegment kem = mlKem;
        MemorySegment ecdh = x25519;
        mlKem = NULL;
        x25519 = NULL;
        Native.free(kem);
        Native.free(ecdh);
    }

    /** OpenSSL 3.5 downcalls, loaded only where they can be. */
    private static final class Native {

        static final boolean AVAILABLE;
        private static final MethodHandle NEW;
        private static final MethodHandle NEW_KEY;
        private static final MethodHandle KEYGEN_INIT;
        private static final MethodHandle GENERATE;
        private static final MethodHandle RAW_PUBLIC;
        private static final MethodHandle NEW_RAW_PUBLIC;
        private static final MethodHandle DECAPSULATE_INIT;
        private static final MethodHandle DECAPSULATE;
        private static final MethodHandle DERIVE_INIT;
        private static final MethodHandle SET_PEER;
        private static final MethodHandle DERIVE;
        private static final MethodHandle FREE_CTX;
        private static final MethodHandle FREE_KEY;

        static {
            MethodHandle[] handles = new MethodHandle[13];
            boolean available = false;
            if (Platform.isLinux() && ValueLayout.ADDRESS.byteSize() == 8) {
                try {
                    lookup = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
                    handles[0] = bind("EVP_PKEY_CTX_new_from_name", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[1] = bind("EVP_PKEY_CTX_new_from_pkey", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
                    handles[2] = bind("EVP_PKEY_keygen_init", JAVA_INT, ADDRESS);
                    handles[3] = bind("EVP_PKEY_generate", JAVA_INT, ADDRESS, ADDRESS);
                    handles[4] = bind("EVP_PKEY_get_raw_public_key", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
                    handles[5] = bind("EVP_PKEY_new_raw_public_key_ex", ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
                    handles[6] = bind("EVP_PKEY_decapsulate_init", JAVA_INT, ADDRESS, ADDRESS);
                    handles[7] = bind("EVP_PKEY_decapsulate", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
                    handles[8] = bind("EVP_PKEY_derive_init", JAVA_INT, ADDRESS);
                    handles[9] = bind("EVP_PKEY_derive_set_peer", JAVA_INT, ADDRESS, ADDRESS);
                    handles[10] = bind("EVP_PKEY_derive", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
                    handles[11] = bind("EVP_PKEY_CTX_free", null, ADDRESS);
                    handles[12] = bind("EVP_PKEY_free", null, ADDRESS);
                    // OpenSSL 3.0 to 3.4 have every symbol above but no ML-KEM:
                    // the context for it is what tells the versions apart.
                    MemorySegment probe;
                    try (Arena arena = Arena.ofConfined()) {
                        probe = (MemorySegment) handles[0].invokeExact(NULL,
                                arena.allocateFrom("ML-KEM-768"), NULL);
                    }
                    if (!probe.equals(NULL)) {
                        handles[11].invokeExact(probe);
                        available = true;
                    }
                } catch (Throwable absent) {
                    available = false;
                }
            }
            AVAILABLE = available;
            NEW = handles[0];
            NEW_KEY = handles[1];
            KEYGEN_INIT = handles[2];
            GENERATE = handles[3];
            RAW_PUBLIC = handles[4];
            NEW_RAW_PUBLIC = handles[5];
            DECAPSULATE_INIT = handles[6];
            DECAPSULATE = handles[7];
            DERIVE_INIT = handles[8];
            SET_PEER = handles[9];
            DERIVE = handles[10];
            FREE_CTX = handles[11];
            FREE_KEY = handles[12];
        }

        static MemorySegment generate(String algorithm) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment context = pointer(NEW, NULL, arena.allocateFrom(algorithm), NULL);
                MemorySegment result = arena.allocate(ADDRESS);
                try {
                    ok(KEYGEN_INIT, context);
                    ok(GENERATE, context, result);
                    return result.get(ADDRESS, 0);
                } finally {
                    invoke(FREE_CTX, context);
                }
            }
        }

        static void rawPublic(MemorySegment key, MemorySegment out, int expected) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment length = arena.allocate(JAVA_LONG);
                length.set(JAVA_LONG, 0, expected);
                ok(RAW_PUBLIC, key, out, length);
                if (length.get(JAVA_LONG, 0) != expected) {
                    throw new IllegalStateException("OpenSSL returned a public key of "
                            + length.get(JAVA_LONG, 0) + " bytes, " + expected + " expected");
                }
            }
        }

        static void decapsulate(MemorySegment key, MemorySegment ciphertext, MemorySegment out) {
            MemorySegment context = pointer(NEW_KEY, NULL, key, NULL);
            try (Arena arena = Arena.ofConfined()) {
                ok(DECAPSULATE_INIT, context, NULL);
                MemorySegment length = arena.allocate(JAVA_LONG);
                length.set(JAVA_LONG, 0, 32L);
                ok(DECAPSULATE, context, out, length, ciphertext, ciphertext.byteSize());
                if (length.get(JAVA_LONG, 0) != 32) {
                    throw new IllegalStateException("unexpected ML-KEM secret length");
                }
            } finally {
                invoke(FREE_CTX, context);
            }
        }

        static void x25519(MemorySegment key, MemorySegment peerPublic, MemorySegment out) {
            MemorySegment peer;
            try (Arena arena = Arena.ofConfined()) {
                peer = pointer(NEW_RAW_PUBLIC, NULL, arena.allocateFrom("X25519"), NULL,
                        peerPublic, (long) X25519);
            }
            MemorySegment context = NULL;
            try (Arena arena = Arena.ofConfined()) {
                context = pointer(NEW_KEY, NULL, key, NULL);
                ok(DERIVE_INIT, context);
                ok(SET_PEER, context, peer);
                MemorySegment length = arena.allocate(JAVA_LONG);
                length.set(JAVA_LONG, 0, 32L);
                ok(DERIVE, context, out, length);
                if (length.get(JAVA_LONG, 0) != 32) {
                    throw new IllegalStateException("unexpected X25519 secret length");
                }
            } finally {
                invoke(FREE_CTX, context);
                invoke(FREE_KEY, peer);
            }
        }

        static void free(MemorySegment key) {
            if (key != null && !key.equals(NULL)) {
                invoke(FREE_KEY, key);
            }
        }

        /** Set in the static initialiser before the first bind, where libcrypto can be found. */
        private static SymbolLookup lookup;

        private static MethodHandle bind(String name, ValueLayout result, ValueLayout... arguments) {
            FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(arguments)
                    : FunctionDescriptor.of(result, arguments);
            return Linker.nativeLinker().downcallHandle(lookup.find(name).orElseThrow(), descriptor);
        }

        private static Object invoke(MethodHandle function, Object... arguments) {
            try {
                return function.invokeWithArguments(arguments);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException("OpenSSL X25519MLKEM768 downcall failed", e);
            }
        }

        private static void ok(MethodHandle function, Object... arguments) {
            if ((int) invoke(function, arguments) != 1) {
                throw new IllegalStateException("OpenSSL X25519MLKEM768 operation failed");
            }
        }

        private static MemorySegment pointer(MethodHandle function, Object... arguments) {
            MemorySegment result = (MemorySegment) invoke(function, arguments);
            if (result.equals(NULL)) {
                throw new IllegalStateException("OpenSSL X25519MLKEM768 allocation failure");
            }
            return result;
        }
    }
}

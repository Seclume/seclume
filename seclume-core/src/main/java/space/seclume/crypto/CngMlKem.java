package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.internal.Platform;
import space.seclume.secret.SecretScope;

/**
 * The two halves of X25519MLKEM768 through CNG: ML-KEM-768 (Windows 11 with
 * the post-quantum update; tested on build 26200.9457) and ECDH on
 * curve25519 (Windows 10 onwards). The private keys stay CNG handles.
 *
 * <p>Byte order, found against the JDK's X25519 and ML-KEM
 * ({@code HybridMlKemTest}): CNG's curve25519 public blob holds the RFC 7748
 * little-endian u as it is, but its raw secret comes reversed, the same way
 * P-256's does - so only the secret is turned around here.
 */
final class CngMlKem implements HybridMlKem.Keys {

    static final boolean AVAILABLE;

    private static final MethodHandle OPEN;
    private static final MethodHandle GENERATE;
    private static final MethodHandle SET_PROPERTY;
    private static final MethodHandle FINALIZE;
    private static final MethodHandle IMPORT;
    private static final MethodHandle EXPORT;
    private static final MethodHandle DECAPSULATE;
    private static final MethodHandle AGREE;
    private static final MethodHandle DERIVE;
    private static final MethodHandle DESTROY_SECRET;
    private static final MethodHandle DESTROY_KEY;
    private static final MethodHandle CLOSE;

    private static final int ML_KEM_PUBLIC_MAGIC = 0x504b4c4d;   // BCRYPT_MLKEM_PUBLIC_MAGIC
    private static final int ECDH_PUBLIC_MAGIC = 0x504b4345;     // BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
    private static final String PARAMETER_SET = "768";
    /** BCRYPT_MLKEM_KEY_BLOB: magic, cbParameterSet, cbKey, "768\0" in UTF-16, the key. */
    private static final int ML_KEM_BLOB = 12 + (PARAMETER_SET.length() + 1) * 2 + 1184;
    /** BCRYPT_ECCKEY_BLOB for curve25519: magic, cbKey, X, and a Y of zeros. */
    private static final int ECDH_BLOB = 8 + 64;

    static {
        MethodHandle[] handles = new MethodHandle[12];
        boolean available = false;
        if (Platform.isWindows()) {
            try {
                lookup = SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
                handles[0] = bind("BCryptOpenAlgorithmProvider", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
                handles[1] = bind("BCryptGenerateKeyPair", ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
                handles[2] = bind("BCryptSetProperty", ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
                handles[3] = bind("BCryptFinalizeKeyPair", ADDRESS, JAVA_INT);
                handles[4] = bind("BCryptImportKeyPair", ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
                handles[5] = bind("BCryptExportKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
                // Absent before the post-quantum update: the lookup fails and
                // the hybrid is simply not offered.
                handles[6] = bind("BCryptDecapsulate", ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
                handles[7] = bind("BCryptSecretAgreement", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
                handles[8] = bind("BCryptDeriveKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
                handles[9] = bind("BCryptDestroySecret", ADDRESS);
                handles[10] = bind("BCryptDestroyKey", ADDRESS);
                handles[11] = bind("BCryptCloseAlgorithmProvider", ADDRESS, JAVA_INT);
                available = true;
            } catch (RuntimeException | Error absent) {
                available = false;
            }
        }
        OPEN = handles[0];
        GENERATE = handles[1];
        SET_PROPERTY = handles[2];
        FINALIZE = handles[3];
        IMPORT = handles[4];
        EXPORT = handles[5];
        DECAPSULATE = handles[6];
        AGREE = handles[7];
        DERIVE = handles[8];
        DESTROY_SECRET = handles[9];
        DESTROY_KEY = handles[10];
        CLOSE = handles[11];
        if (available) {
            // The symbols can be there while the algorithm is not (a build in
            // between): one real key pair is the only reliable answer.
            try {
                new CngMlKem().close();
            } catch (RuntimeException | Error absent) {
                available = false;
            }
        }
        AVAILABLE = available;
    }

    private MemorySegment kemAlgorithm = MemorySegment.NULL;
    private MemorySegment kemKey = MemorySegment.NULL;
    private MemorySegment ecdhAlgorithm = MemorySegment.NULL;
    private MemorySegment ecdhKey = MemorySegment.NULL;

    CngMlKem() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment handle = arena.allocate(ADDRESS);
            call(OPEN, handle, wide(arena, "ML-KEM"), MemorySegment.NULL, 0);
            kemAlgorithm = handle.get(ADDRESS, 0);
            call(GENERATE, kemAlgorithm, handle, 0, 0);
            kemKey = handle.get(ADDRESS, 0);
            MemorySegment set = wide(arena, PARAMETER_SET);
            call(SET_PROPERTY, kemKey, wide(arena, "ParameterSetName"), set, (int) set.byteSize(), 0);
            call(FINALIZE, kemKey, 0);

            call(OPEN, handle, wide(arena, "ECDH"), MemorySegment.NULL, 0);
            ecdhAlgorithm = handle.get(ADDRESS, 0);
            MemorySegment curve = wide(arena, "curve25519");
            call(SET_PROPERTY, ecdhAlgorithm, wide(arena, "ECCCurveName"), curve, (int) curve.byteSize(), 0);
            call(GENERATE, ecdhAlgorithm, handle, 255, 0);
            ecdhKey = handle.get(ADDRESS, 0);
            call(FINALIZE, ecdhKey, 0);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    @Override
    public void publicShare(MemorySegment out) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment count = arena.allocate(JAVA_INT);
            MemorySegment kem = arena.allocate(ML_KEM_BLOB, 4);
            call(EXPORT, kemKey, MemorySegment.NULL, wide(arena, "MLKEMPUBLICBLOB"), kem, ML_KEM_BLOB, count, 0);
            int keyAt = 12 + kem.get(JAVA_INT, 4);
            if (count.get(JAVA_INT, 0) != ML_KEM_BLOB || kem.get(JAVA_INT, 0) != ML_KEM_PUBLIC_MAGIC
                    || kem.get(JAVA_INT, 8) != HybridMlKem.ML_KEM_KEY || keyAt + HybridMlKem.ML_KEM_KEY != ML_KEM_BLOB) {
                throw new IllegalStateException("unexpected CNG ML-KEM public blob");
            }
            MemorySegment.copy(kem, keyAt, out, 0, HybridMlKem.ML_KEM_KEY);

            MemorySegment ecdh = arena.allocate(ECDH_BLOB, 4);
            call(EXPORT, ecdhKey, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"), ecdh, ECDH_BLOB, count, 0);
            if (count.get(JAVA_INT, 0) != ECDH_BLOB || ecdh.get(JAVA_INT, 0) != ECDH_PUBLIC_MAGIC
                    || ecdh.get(JAVA_INT, 4) != 32) {
                throw new IllegalStateException("unexpected CNG curve25519 public blob");
            }
            MemorySegment.copy(ecdh, 8, out, HybridMlKem.ML_KEM_KEY, 32);
        }
    }

    @Override
    public void derive(MemorySegment serverShare, MemorySegment out) {
        decapsulate(serverShare.asSlice(0, HybridMlKem.ML_KEM_CIPHERTEXT), out.asSlice(0, 32));
        x25519(serverShare.asSlice(HybridMlKem.ML_KEM_CIPHERTEXT, 32), out.asSlice(32, 32));
    }

    private void decapsulate(MemorySegment ciphertext, MemorySegment out) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment count = arena.allocate(JAVA_INT);
            call(DECAPSULATE, kemKey, ciphertext, (int) ciphertext.byteSize(), out, 32, count, 0);
            if (count.get(JAVA_INT, 0) != 32) {
                throw new IllegalStateException("unexpected ML-KEM secret length");
            }
        }
    }

    private void x25519(MemorySegment peerPublic, MemorySegment out) {
        MemorySegment peer = MemorySegment.NULL;
        MemorySegment secret = MemorySegment.NULL;
        try (Arena arena = Arena.ofConfined(); SecretScope raw = SecretScope.allocate(32)) {
            MemorySegment blob = arena.allocate(ECDH_BLOB, 4);
            blob.set(JAVA_INT, 0, ECDH_PUBLIC_MAGIC);
            blob.set(JAVA_INT, 4, 32);
            MemorySegment.copy(peerPublic, 0, blob, 8, 32);
            MemorySegment handle = arena.allocate(ADDRESS);
            call(IMPORT, ecdhAlgorithm, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"),
                    handle, blob, ECDH_BLOB, 0);
            peer = handle.get(ADDRESS, 0);
            call(AGREE, ecdhKey, peer, handle, 0);
            secret = handle.get(ADDRESS, 0);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(DERIVE, secret, wide(arena, "TRUNCATE"), MemorySegment.NULL, raw.segment(), 32, count, 0);
            if (count.get(JAVA_INT, 0) != 32) {
                throw new IllegalStateException("unexpected CNG X25519 length");
            }
            reverse(raw.segment(), out);
            // RFC 8446 7.4.2: an all-zero X25519 result means a low-order
            // point from the server - OpenSSL refuses it itself, CNG does not say.
            int any = 0;
            for (int i = 0; i < 32; i++) any |= out.get(JAVA_BYTE, i);
            if (any == 0) {
                throw new IllegalStateException("the server's X25519 share is a low-order point");
            }
        } finally {
            try {
                if (!secret.equals(MemorySegment.NULL)) call(DESTROY_SECRET, secret);
            } finally {
                if (!peer.equals(MemorySegment.NULL)) call(DESTROY_KEY, peer);
            }
        }
    }

    @Override
    public void close() {
        MemorySegment[] keys = {kemKey, ecdhKey};
        MemorySegment[] algorithms = {kemAlgorithm, ecdhAlgorithm};
        kemKey = ecdhKey = kemAlgorithm = ecdhAlgorithm = MemorySegment.NULL;
        RuntimeException first = null;
        for (MemorySegment key : keys) {
            try {
                if (!key.equals(MemorySegment.NULL)) call(DESTROY_KEY, key);
            } catch (RuntimeException e) {
                if (first == null) first = e;
            }
        }
        for (MemorySegment algorithm : algorithms) {
            try {
                if (!algorithm.equals(MemorySegment.NULL)) call(CLOSE, algorithm, 0);
            } catch (RuntimeException e) {
                if (first == null) first = e;
            }
        }
        if (first != null) throw first;
    }

    private static void reverse(MemorySegment in, MemorySegment out) {
        for (int i = 0; i < 32; i++) {
            out.set(JAVA_BYTE, i, in.get(JAVA_BYTE, 31 - i));
        }
    }

    private static MemorySegment wide(Arena arena, String text) {
        MemorySegment out = arena.allocate((text.length() + 1L) * 2, 2);
        for (int i = 0; i < text.length(); i++) out.set(ValueLayout.JAVA_CHAR, 2L * i, text.charAt(i));
        return out;
    }

    /** Set in the static initialiser before the first bind, on Windows only. */
    private static SymbolLookup lookup;

    private static MethodHandle bind(String name, ValueLayout... arguments) {
        return Linker.nativeLinker().downcallHandle(lookup.find(name).orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, arguments));
    }

    private static void call(MethodHandle function, Object... args) {
        try {
            int status = (int) function.invokeWithArguments(args);
            if (status != 0) throw new IllegalStateException("CNG X25519MLKEM768 failed: NTSTATUS 0x" + Integer.toHexString(status));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("CNG X25519MLKEM768 downcall failed", e);
        }
    }
}

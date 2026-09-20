package space.seclume.crypto;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

import space.seclume.secret.SecretScope;

/**
 * ECDSA over P-256 through CNG.
 *
 * <p>Separate from {@link CngP256} because CNG itself separates them: a key
 * imported under {@code ECDH_P256} cannot sign, and one imported under
 * {@code ECDSA_P256} cannot agree. The blob layout is the same but the magic
 * number is not - {@code ECS2} rather than {@code ECK2} - and using the wrong
 * one fails at import, which is the right place for it to fail.
 *
 * <p>{@code BCryptSignHash} returns the raw pair {@code r || s}; the DER that
 * TLS wants is made in {@link P256Signer}.
 */
final class CngP256Signer implements P256Signer.Backend {

    private static final SymbolLookup LIB =
            SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
    private static final MethodHandle OPEN =
            bind("BCryptOpenAlgorithmProvider", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle IMPORT = bind("BCryptImportKeyPair",
            ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle SIGN = bind("BCryptSignHash",
            ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle VERIFY = bind("BCryptVerifySignature",
            ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle DESTROY_KEY = bind("BCryptDestroyKey", ADDRESS);
    private static final MethodHandle CLOSE = bind("BCryptCloseAlgorithmProvider", ADDRESS, JAVA_INT);

    /** BCRYPT_ECDSA_PRIVATE_P256_MAGIC - 'ECS2', not the 'ECK2' of key agreement. */
    private static final int PRIVATE_MAGIC = 0x32534345;
    /** BCRYPT_ECDSA_PUBLIC_P256_MAGIC - 'ECS1'. */
    private static final int PUBLIC_MAGIC = 0x31534345;
    /** Magic, key length, x, y, d. */
    private static final int BLOB_SIZE = 8 + 32 + 32 + 32;
    /** The same without d. */
    private static final int PUBLIC_BLOB_SIZE = 8 + 32 + 32;

    private MemorySegment algorithm = MemorySegment.NULL;
    private MemorySegment key = MemorySegment.NULL;

    CngP256Signer(MemorySegment point, MemorySegment scalar) {
        try (Arena arena = Arena.ofConfined(); SecretScope blob = SecretScope.allocate(BLOB_SIZE)) {
            MemorySegment handle = arena.allocate(ADDRESS);
            call(OPEN, handle, wide(arena, "ECDSA_P256"), MemorySegment.NULL, 0);
            algorithm = handle.get(ADDRESS, 0);

            blob.segment().set(JAVA_INT, 0, PRIVATE_MAGIC);
            blob.segment().set(JAVA_INT, 4, 32);
            MemorySegment.copy(point, 1, blob.segment(), 8, 64);   // x and y, without the 0x04
            MemorySegment.copy(scalar, 0, blob.segment(), 72, 32);

            call(IMPORT, algorithm, MemorySegment.NULL, wide(arena, "ECCPRIVATEBLOB"),
                    handle, blob.segment(), BLOB_SIZE, 0);
            key = handle.get(ADDRESS, 0);
            checkPair(arena, point);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    /**
     * That the private key really belongs to this public point.
     *
     * <p>CNG does not check. It takes {@code x}, {@code y} and {@code d} as
     * three independent numbers and imports them happily even when they have
     * nothing to do with each other, and the mismatch only surfaces later as a
     * server rejecting {@code CertificateVerify} - an alert that says nothing
     * about the cause. OpenSSL refuses such a pair outright
     * ({@code EVP_PKEY_pairwise_check}), so the same is done here rather than
     * having the two platforms disagree about which keys are acceptable.
     *
     * <p>The check is a signature over a fixed digest, verified against a
     * public key built from the point alone: it can only succeed if the two
     * halves belong together. One signature at construction, and the caller
     * finds out now instead of during a handshake.
     */
    private void checkPair(Arena arena, MemorySegment point) {
        MemorySegment publicBlob = arena.allocate(PUBLIC_BLOB_SIZE, 4);
        publicBlob.set(JAVA_INT, 0, PUBLIC_MAGIC);
        publicBlob.set(JAVA_INT, 4, 32);
        MemorySegment.copy(point, 1, publicBlob, 8, 64);

        MemorySegment handle = arena.allocate(ADDRESS);
        call(IMPORT, algorithm, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"),
                handle, publicBlob, PUBLIC_BLOB_SIZE, 0);
        MemorySegment publicKey = handle.get(ADDRESS, 0);
        try {
            MemorySegment digest = arena.allocate(P256Signer.FIELD);   // all zeroes will do
            MemorySegment raw = arena.allocate(2L * P256Signer.FIELD);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(SIGN, key, MemorySegment.NULL, digest, P256Signer.FIELD,
                    raw, 2 * P256Signer.FIELD, count, 0);
            call(VERIFY, publicKey, MemorySegment.NULL, digest, P256Signer.FIELD,
                    raw, 2 * P256Signer.FIELD, 0);
        } catch (IllegalStateException mismatch) {
            throw new IllegalStateException("this private key does not belong to the public key "
                    + "it was given with - check that the certificate and the key file are a "
                    + "pair", mismatch);
        } finally {
            call(DESTROY_KEY, publicKey);
        }
    }

    @Override
    public int sign(MemorySegment digest, MemorySegment der) {
        try (Arena arena = Arena.ofConfined();
             SecretScope raw = SecretScope.allocate(2 * P256Signer.FIELD)) {
            MemorySegment count = arena.allocate(JAVA_INT);
            call(SIGN, key, MemorySegment.NULL, digest, (int) digest.byteSize(),
                    raw.segment(), 2 * P256Signer.FIELD, count, 0);
            if (count.get(JAVA_INT, 0) != 2 * P256Signer.FIELD) {
                throw new IllegalStateException("unexpected CNG ECDSA signature length");
            }
            return P256Signer.der(raw.segment(), der);
        }
    }

    @Override
    public void close() {
        try {
            if (!key.equals(MemorySegment.NULL)) {
                MemorySegment old = key;
                key = MemorySegment.NULL;
                call(DESTROY_KEY, old);
            }
        } finally {
            if (!algorithm.equals(MemorySegment.NULL)) {
                MemorySegment old = algorithm;
                algorithm = MemorySegment.NULL;
                call(CLOSE, old, 0);
            }
        }
    }

    private static MemorySegment wide(Arena arena, String text) {
        MemorySegment out = arena.allocate((text.length() + 1L) * 2, 2);
        for (int i = 0; i < text.length(); i++) {
            out.set(ValueLayout.JAVA_CHAR, 2L * i, text.charAt(i));
        }
        return out;
    }

    private static MethodHandle bind(String name, ValueLayout... arguments) {
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, arguments));
    }

    private static void call(MethodHandle function, Object... args) {
        try {
            int status = (int) function.invokeWithArguments(args);
            if (status != 0) {
                throw new IllegalStateException(
                        "CNG ECDSA P-256 failed: NTSTATUS 0x" + Integer.toHexString(status));
            }
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("CNG ECDSA P-256 downcall failed", e);
        }
    }
}

package space.seclume.crypto;

import static java.lang.foreign.MemorySegment.NULL;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteOrder;

import space.seclume.secret.SecretScope;

/**
 * ECDSA over P-256 through OpenSSL 3, using the provider API only.
 *
 * <p>The same import route as {@link OpenSslP256} - {@code EVP_PKEY_fromdata}
 * with the group, the public point and the private scalar - because the key
 * material has to come out of a {@code MemorySegment} and none of the
 * convenience functions accept one. The signing itself is
 * {@code EVP_PKEY_sign} over a digest that has already been computed, which
 * for EC keys produces exactly the DER that TLS wants, so nothing is
 * re-encoded here.
 *
 * <p>{@code EVP_PKEY_pairwise_check} runs on import: a private key that does
 * not belong to the certificate's public point is refused now rather than
 * during a handshake.
 */
final class OpenSslP256Signer implements P256Signer.Backend {

    private static final SymbolLookup LIB =
            SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
    private static final MethodHandle NEW =
            bind("EVP_PKEY_CTX_new_from_name", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle NEW_KEY =
            bind("EVP_PKEY_CTX_new_from_pkey", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle IMPORT_INIT = bind("EVP_PKEY_fromdata_init", JAVA_INT, ADDRESS);
    private static final MethodHandle IMPORT =
            bind("EVP_PKEY_fromdata", JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS);
    private static final MethodHandle PAIR_CHECK = bind("EVP_PKEY_pairwise_check", JAVA_INT, ADDRESS);
    private static final MethodHandle SIGN_INIT = bind("EVP_PKEY_sign_init", JAVA_INT, ADDRESS);
    private static final MethodHandle SIGN =
            bind("EVP_PKEY_sign", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
    private static final MethodHandle FREE_CTX = bind("EVP_PKEY_CTX_free", null, ADDRESS);
    private static final MethodHandle FREE_KEY = bind("EVP_PKEY_free", null, ADDRESS);

    /** OSSL_PARAM on LP64 - the same 40-byte shape {@link OpenSslP256} uses. */
    private static final int PARAM_SIZE = 40;
    private static final int KEYPAIR_SELECTION = 0x87;

    private MemorySegment key;

    OpenSslP256Signer(MemorySegment point, MemorySegment scalar) {
        this.key = importKey(point, scalar);
    }

    private static MemorySegment importKey(MemorySegment point, MemorySegment scalar) {
        try (Arena arena = Arena.ofConfined(); SecretScope integer = SecretScope.allocate(32)) {
            MemorySegment context = pointer(NEW, NULL, arena.allocateFrom("EC"), NULL);
            MemorySegment result = arena.allocate(ADDRESS);
            try {
                MemorySegment params = arena.allocate(4L * PARAM_SIZE, 8);
                parameter(arena, params, 0, "group", 4, arena.allocateFrom("prime256v1"), 10);
                parameter(arena, params, 1, "pub", 5, point, 65);
                nativeInteger(scalar, integer.segment());
                parameter(arena, params, 2, "priv", 2, integer.segment(), 32);

                ok(IMPORT_INIT, context);
                ok(IMPORT, context, result, KEYPAIR_SELECTION, params);
                MemorySegment imported = result.get(ADDRESS, 0);

                MemorySegment check = pointer(NEW_KEY, NULL, imported, NULL);
                try {
                    ok(PAIR_CHECK, check);
                } finally {
                    invoke(FREE_CTX, check);
                }
                return imported;
            } catch (RuntimeException | Error e) {
                invoke(FREE_KEY, result.get(ADDRESS, 0));
                throw e;
            } finally {
                invoke(FREE_CTX, context);
            }
        }
    }

    @Override
    public int sign(MemorySegment digest, MemorySegment der) {
        MemorySegment context = NULL;
        try (Arena arena = Arena.ofConfined()) {
            context = pointer(NEW_KEY, NULL, key, NULL);
            ok(SIGN_INIT, context);
            MemorySegment length = arena.allocate(JAVA_LONG);
            length.set(JAVA_LONG, 0, der.byteSize());
            ok(SIGN, context, der, length, digest, digest.byteSize());
            long written = length.get(JAVA_LONG, 0);
            if (written <= 0 || written > der.byteSize()) {
                throw new IllegalStateException("unexpected OpenSSL ECDSA signature length");
            }
            return (int) written;
        } finally {
            invoke(FREE_CTX, context);
        }
    }

    @Override
    public void close() {
        MemorySegment old = key;
        key = NULL;
        invoke(FREE_KEY, old);
    }

    /** OpenSSL wants the scalar in native byte order; the copy is its own inverse. */
    private static void nativeInteger(MemorySegment from, MemorySegment to) {
        for (int i = 0; i < 32; i++) {
            int at = ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN ? 31 - i : i;
            to.set(JAVA_BYTE, i, from.get(JAVA_BYTE, at));
        }
    }

    private static void parameter(Arena arena, MemorySegment params, int index, String name,
            int type, MemorySegment data, long size) {
        long at = (long) index * PARAM_SIZE;
        params.set(ADDRESS, at, arena.allocateFrom(name));
        params.set(JAVA_INT, at + 8, type);
        params.set(ADDRESS, at + 16, data);
        params.set(JAVA_LONG, at + 24, size);
        params.set(JAVA_LONG, at + 32, -1L);
    }

    private static MethodHandle bind(String name, ValueLayout result, ValueLayout... arguments) {
        FunctionDescriptor descriptor = result == null ? FunctionDescriptor.ofVoid(arguments)
                : FunctionDescriptor.of(result, arguments);
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(), descriptor);
    }

    private static Object invoke(MethodHandle function, Object... arguments) {
        try {
            return function.invokeWithArguments(arguments);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("OpenSSL ECDSA P-256 downcall failed", e);
        }
    }

    private static void ok(MethodHandle function, Object... arguments) {
        if ((int) invoke(function, arguments) != 1) {
            throw new IllegalStateException("OpenSSL ECDSA P-256 operation failed "
                    + "(invalid key, or the key does not match its certificate)");
        }
    }

    private static MemorySegment pointer(MethodHandle function, Object... arguments) {
        MemorySegment result = (MemorySegment) invoke(function, arguments);
        if (result.equals(NULL)) {
            throw new IllegalStateException("OpenSSL ECDSA P-256 allocation failure");
        }
        return result;
    }
}

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

/** OpenSSL 3 provider API; deliberately no deprecated EC_KEY functions or JCA fallback. */
final class OpenSslP256 implements NativeP256.Backend {
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
    private static final MethodHandle NEW = bind("EVP_PKEY_CTX_new_from_name", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle NEW_KEY = bind("EVP_PKEY_CTX_new_from_pkey", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle KEYGEN_INIT = bind("EVP_PKEY_keygen_init", JAVA_INT, ADDRESS);
    private static final MethodHandle SET_PARAMS = bind("EVP_PKEY_CTX_set_params", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle GENERATE = bind("EVP_PKEY_generate", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle IMPORT_INIT = bind("EVP_PKEY_fromdata_init", JAVA_INT, ADDRESS);
    private static final MethodHandle IMPORT = bind("EVP_PKEY_fromdata", JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS);
    private static final MethodHandle PAIR_CHECK = bind("EVP_PKEY_pairwise_check", JAVA_INT, ADDRESS);
    private static final MethodHandle GET_PUBLIC = bind("EVP_PKEY_get_octet_string_param", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS);
    private static final MethodHandle GET_PARAMS = bind("EVP_PKEY_get_params", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle DERIVE_INIT = bind("EVP_PKEY_derive_init", JAVA_INT, ADDRESS);
    private static final MethodHandle SET_PEER = bind("EVP_PKEY_derive_set_peer", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle DERIVE = bind("EVP_PKEY_derive", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle FREE_CTX = bind("EVP_PKEY_CTX_free", null, ADDRESS);
    private static final MethodHandle FREE_KEY = bind("EVP_PKEY_free", null, ADDRESS);

    // OSSL_PARAM on LP64: key pointer, unsigned int type, padding, data pointer,
    // size_t data_size, size_t return_size. NativeP256 rejects 32-bit Linux.
    private static final int PARAM_SIZE = 40;
    private static final int PUBLIC_SELECTION = 0x86; // ALL_PARAMETERS | PUBLIC_KEY
    private static final int KEYPAIR_SELECTION = 0x87;
    private MemorySegment key;

    OpenSslP256(MemorySegment point, MemorySegment scalar) {
        key = point == null ? generate() : importKey(point, scalar);
    }

    private static MemorySegment generate() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment context = context(arena);
            MemorySegment result = arena.allocate(ADDRESS);
            try {
                ok(KEYGEN_INIT, context);
                MemorySegment params = parameters(arena, 1);
                group(arena, params);
                ok(SET_PARAMS, context, params);
                ok(GENERATE, context, result);
                return result.get(ADDRESS, 0);
            } catch (RuntimeException | Error e) {
                invoke(FREE_KEY, result.get(ADDRESS, 0));
                throw e;
            } finally {
                invoke(FREE_CTX, context);
            }
        }
    }

    private static MemorySegment importKey(MemorySegment point, MemorySegment scalar) {
        try (Arena arena = Arena.ofConfined(); SecretScope integer = SecretScope.allocate(32)) {
            MemorySegment context = context(arena);
            MemorySegment result = arena.allocate(ADDRESS);
            try {
                MemorySegment params = parameters(arena, scalar == null ? 2 : 3);
                group(arena, params);
                parameter(arena, params, 1, "pub", 5, point, 65);
                if (scalar != null) {
                    nativeInteger(scalar, integer.segment());
                    parameter(arena, params, 2, "priv", 2, integer.segment(), 32);
                }
                ok(IMPORT_INIT, context);
                ok(IMPORT, context, result, scalar == null ? PUBLIC_SELECTION : KEYPAIR_SELECTION, params);
                MemorySegment imported = result.get(ADDRESS, 0);
                if (scalar != null) {
                    MemorySegment check = pointer(NEW_KEY, NULL, imported, NULL);
                    try {
                        ok(PAIR_CHECK, check);
                    } finally {
                        invoke(FREE_CTX, check);
                    }
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
    public void publicKey(MemorySegment out) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment publicKey = arena.allocate(65);
            MemorySegment count = arena.allocate(JAVA_LONG);
            ok(GET_PUBLIC, key, arena.allocateFrom("pub"), publicKey, 65L, count);
            if (count.get(JAVA_LONG, 0) != 65 || publicKey.get(JAVA_BYTE, 0) != 4) {
                throw new IllegalStateException("unexpected OpenSSL P-256 public key");
            }
            MemorySegment.copy(publicKey, 0, out, 0, 65);
        }
    }

    @Override
    public void derive(MemorySegment peer, MemorySegment out) {
        MemorySegment peerKey = importKey(peer, null);
        MemorySegment context = NULL;
        try (Arena arena = Arena.ofConfined()) {
            context = pointer(NEW_KEY, NULL, key, NULL);
            ok(DERIVE_INIT, context);
            // Unlike the _ex variant with validate_peer=0, this validates the point.
            ok(SET_PEER, context, peerKey);
            MemorySegment length = arena.allocate(JAVA_LONG);
            length.set(JAVA_LONG, 0, 32L);
            ok(DERIVE, context, out, length);
            if (length.get(JAVA_LONG, 0) != 32) {
                throw new IllegalStateException("unexpected OpenSSL P-256 secret length");
            }
        } finally {
            invoke(FREE_CTX, context);
            invoke(FREE_KEY, peerKey);
        }
    }

    @Override
    public void privateScalar(MemorySegment out) {
        try (Arena arena = Arena.ofConfined(); SecretScope integer = SecretScope.allocate(32)) {
            MemorySegment params = parameters(arena, 1);
            parameter(arena, params, 0, "priv", 2, integer.segment(), 32);
            ok(GET_PARAMS, key, params);
            long returned = params.get(JAVA_LONG, 32);
            if (returned <= 0 || returned > 32) {
                throw new IllegalStateException("unexpected OpenSSL P-256 private scalar size");
            }
            nativeInteger(integer.segment(), out); // reversal is its own inverse
        }
    }

    @Override
    public void close() {
        MemorySegment old = key;
        key = NULL;
        invoke(FREE_KEY, old);
    }

    private static void nativeInteger(MemorySegment from, MemorySegment to) {
        for (int i = 0; i < 32; i++) {
            int at = ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN ? 31 - i : i;
            to.set(JAVA_BYTE, i, from.get(JAVA_BYTE, at));
        }
    }

    private static MemorySegment context(Arena arena) {
        return pointer(NEW, NULL, arena.allocateFrom("EC"), NULL);
    }

    private static MemorySegment parameters(Arena arena, int count) {
        return arena.allocate((count + 1L) * PARAM_SIZE, 8); // final entry stays zero
    }

    private static void group(Arena arena, MemorySegment params) {
        parameter(arena, params, 0, "group", 4, arena.allocateFrom("prime256v1"), 10);
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
            throw new IllegalStateException("OpenSSL P-256 downcall failed", e);
        }
    }

    private static void ok(MethodHandle function, Object... arguments) {
        if ((int) invoke(function, arguments) != 1) {
            throw new IllegalStateException("OpenSSL P-256 operation failed (invalid key or provider failure)");
        }
    }

    private static MemorySegment pointer(MethodHandle function, Object... arguments) {
        MemorySegment result = (MemorySegment) invoke(function, arguments);
        if (result.equals(NULL)) throw new IllegalStateException("OpenSSL P-256 allocation/provider failure");
        return result;
    }
}

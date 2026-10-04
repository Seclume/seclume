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

/**
 * P-384 and X25519 through the OpenSSL 3 provider API - the same calls
 * {@link OpenSslP256} makes for P-256, and {@code HybridMlKem}'s for X25519.
 */
final class OpenSslEcdh implements NativeEcdh.Backend {
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("libcrypto.so.3", Arena.global());
    private static final MethodHandle NEW = bind("EVP_PKEY_CTX_new_from_name", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle NEW_KEY = bind("EVP_PKEY_CTX_new_from_pkey", ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle KEYGEN_INIT = bind("EVP_PKEY_keygen_init", JAVA_INT, ADDRESS);
    private static final MethodHandle SET_PARAMS = bind("EVP_PKEY_CTX_set_params", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle GENERATE = bind("EVP_PKEY_generate", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle IMPORT_INIT = bind("EVP_PKEY_fromdata_init", JAVA_INT, ADDRESS);
    private static final MethodHandle IMPORT = bind("EVP_PKEY_fromdata", JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS);
    private static final MethodHandle GET_PUBLIC = bind("EVP_PKEY_get_octet_string_param", JAVA_INT, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS);
    private static final MethodHandle RAW_PUBLIC = bind("EVP_PKEY_get_raw_public_key", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle NEW_RAW_PUBLIC = bind("EVP_PKEY_new_raw_public_key_ex", ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG);
    private static final MethodHandle DERIVE_INIT = bind("EVP_PKEY_derive_init", JAVA_INT, ADDRESS);
    private static final MethodHandle SET_PEER = bind("EVP_PKEY_derive_set_peer", JAVA_INT, ADDRESS, ADDRESS);
    private static final MethodHandle DERIVE = bind("EVP_PKEY_derive", JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle FREE_CTX = bind("EVP_PKEY_CTX_free", null, ADDRESS);
    private static final MethodHandle FREE_KEY = bind("EVP_PKEY_free", null, ADDRESS);

    /** OSSL_PARAM on LP64, as in OpenSslP256. */
    private static final int PARAM_SIZE = 40;
    private static final int PUBLIC_SELECTION = 0x86;

    private final NativeEcdh.Group group;
    private MemorySegment key;

    OpenSslEcdh(NativeEcdh.Group group) {
        this.group = group;
        this.key = generate(group);
    }

    private static MemorySegment generate(NativeEcdh.Group group) {
        try (Arena arena = Arena.ofConfined()) {
            boolean x25519 = group == NativeEcdh.Group.X25519;
            MemorySegment context = pointer(NEW, NULL, arena.allocateFrom(x25519 ? "X25519" : "EC"),
                    NULL);
            MemorySegment result = arena.allocate(ADDRESS);
            try {
                ok(KEYGEN_INIT, context);
                if (!x25519) {
                    MemorySegment params = arena.allocate(2L * PARAM_SIZE, 8);
                    parameter(arena, params, 0, "group", 4, arena.allocateFrom("secp384r1"), 9);
                    ok(SET_PARAMS, context, params);
                }
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

    @Override
    public void publicKey(MemorySegment out) {
        int size = group.publicSize();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment publicKey = arena.allocate(size);
            MemorySegment count = arena.allocate(JAVA_LONG);
            if (group == NativeEcdh.Group.X25519) {
                count.set(JAVA_LONG, 0, size);
                ok(RAW_PUBLIC, key, publicKey, count);
            } else {
                ok(GET_PUBLIC, key, arena.allocateFrom("pub"), publicKey, (long) size, count);
                if (publicKey.get(JAVA_BYTE, 0) != 4) {
                    throw new IllegalStateException("OpenSSL returned a compressed " + group + " point");
                }
            }
            if (count.get(JAVA_LONG, 0) != size) {
                throw new IllegalStateException("unexpected OpenSSL " + group + " public key size");
            }
            MemorySegment.copy(publicKey, 0, out, 0, size);
        }
    }

    @Override
    public void derive(MemorySegment peer, MemorySegment out) {
        MemorySegment peerKey = importPublic(peer);
        MemorySegment context = NULL;
        try (Arena arena = Arena.ofConfined()) {
            context = pointer(NEW_KEY, NULL, key, NULL);
            ok(DERIVE_INIT, context);
            ok(SET_PEER, context, peerKey);              // validates the peer's key
            MemorySegment length = arena.allocate(JAVA_LONG);
            length.set(JAVA_LONG, 0, group.secretSize());
            ok(DERIVE, context, out, length);
            if (length.get(JAVA_LONG, 0) != group.secretSize()) {
                throw new IllegalStateException("unexpected OpenSSL " + group + " secret length");
            }
        } finally {
            invoke(FREE_CTX, context);
            invoke(FREE_KEY, peerKey);
        }
    }

    private MemorySegment importPublic(MemorySegment peer) {
        try (Arena arena = Arena.ofConfined()) {
            if (group == NativeEcdh.Group.X25519) {
                return pointer(NEW_RAW_PUBLIC, NULL, arena.allocateFrom("X25519"), NULL, peer,
                        (long) group.publicSize());
            }
            MemorySegment context = pointer(NEW, NULL, arena.allocateFrom("EC"), NULL);
            MemorySegment result = arena.allocate(ADDRESS);
            try {
                MemorySegment params = arena.allocate(3L * PARAM_SIZE, 8);
                parameter(arena, params, 0, "group", 4, arena.allocateFrom("secp384r1"), 9);
                parameter(arena, params, 1, "pub", 5, peer, group.publicSize());
                ok(IMPORT_INIT, context);
                ok(IMPORT, context, result, PUBLIC_SELECTION, params);
                return result.get(ADDRESS, 0);
            } catch (RuntimeException | Error e) {
                invoke(FREE_KEY, result.get(ADDRESS, 0));
                throw e;
            } finally {
                invoke(FREE_CTX, context);
            }
        }
    }

    @Override
    public void close() {
        MemorySegment old = key;
        key = NULL;
        invoke(FREE_KEY, old);
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
            throw new IllegalStateException("OpenSSL ECDH downcall failed", e);
        }
    }

    private static void ok(MethodHandle function, Object... arguments) {
        if ((int) invoke(function, arguments) != 1) {
            throw new IllegalStateException("OpenSSL ECDH operation failed (invalid key or "
                    + "provider failure)");
        }
    }

    private static MemorySegment pointer(MethodHandle function, Object... arguments) {
        MemorySegment result = (MemorySegment) invoke(function, arguments);
        if (result.equals(NULL)) {
            throw new IllegalStateException("OpenSSL ECDH allocation/provider failure");
        }
        return result;
    }
}

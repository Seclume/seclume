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

import space.seclume.secret.SecretScope;

/**
 * P-384 and X25519 through CNG, as {@link CngP256} does P-256 and
 * {@code CngMlKem} X25519.
 *
 * <p>Byte order, as found for those two: the NIST curves' blob coordinates are
 * big-endian and so is TLS; the curve25519 public blob holds the RFC 7748
 * little-endian u as it is; and the raw secret comes out reversed for both.
 */
final class CngEcdh implements NativeEcdh.Backend {
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
    private static final MethodHandle OPEN = bind("BCryptOpenAlgorithmProvider", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle SET_PROPERTY = bind("BCryptSetProperty", ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle GENERATE = bind("BCryptGenerateKeyPair", ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle FINALIZE = bind("BCryptFinalizeKeyPair", ADDRESS, JAVA_INT);
    private static final MethodHandle IMPORT = bind("BCryptImportKeyPair", ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle EXPORT = bind("BCryptExportKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle AGREE = bind("BCryptSecretAgreement", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle DERIVE = bind("BCryptDeriveKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle DESTROY_SECRET = bind("BCryptDestroySecret", ADDRESS);
    private static final MethodHandle DESTROY_KEY = bind("BCryptDestroyKey", ADDRESS);
    private static final MethodHandle CLOSE = bind("BCryptCloseAlgorithmProvider", ADDRESS, JAVA_INT);
    private static final int P384_PUBLIC_MAGIC = 0x334b4345;      // BCRYPT_ECDH_PUBLIC_P384_MAGIC
    private static final int GENERIC_PUBLIC_MAGIC = 0x504b4345;   // BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC

    private final NativeEcdh.Group group;
    /** The coordinate size in the blob: 48 for P-384, 32 for curve25519. */
    private final int coordinate;
    private final int magic;
    private MemorySegment algorithm = MemorySegment.NULL;
    private MemorySegment key = MemorySegment.NULL;

    CngEcdh(NativeEcdh.Group group) {
        this.group = group;
        boolean x25519 = group == NativeEcdh.Group.X25519;
        this.coordinate = x25519 ? 32 : 48;
        this.magic = x25519 ? GENERIC_PUBLIC_MAGIC : P384_PUBLIC_MAGIC;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment handle = arena.allocate(ADDRESS);
            call(OPEN, handle, wide(arena, x25519 ? "ECDH" : "ECDH_P384"), MemorySegment.NULL, 0);
            algorithm = handle.get(ADDRESS, 0);
            if (x25519) {
                MemorySegment curve = wide(arena, "curve25519");
                call(SET_PROPERTY, algorithm, wide(arena, "ECCCurveName"), curve,
                        (int) curve.byteSize(), 0);
            }
            call(GENERATE, algorithm, handle, x25519 ? 255 : 384, 0);
            key = handle.get(ADDRESS, 0);
            call(FINALIZE, key, 0);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    private int blobSize() {
        return 8 + 2 * coordinate;
    }

    @Override
    public void publicKey(MemorySegment out) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = arena.allocate(blobSize(), 4);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(EXPORT, key, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"), blob, blobSize(),
                    count, 0);
            if (count.get(JAVA_INT, 0) != blobSize() || blob.get(JAVA_INT, 0) != magic
                    || blob.get(JAVA_INT, 4) != coordinate) {
                throw new IllegalStateException("unexpected CNG " + group + " public blob");
            }
            if (group == NativeEcdh.Group.X25519) {
                MemorySegment.copy(blob, 8, out, 0, 32);
            } else {
                out.set(JAVA_BYTE, 0, (byte) 4);
                MemorySegment.copy(blob, 8, out, 1, 2L * coordinate);
            }
        }
    }

    @Override
    public void derive(MemorySegment peer, MemorySegment out) {
        MemorySegment peerKey = MemorySegment.NULL;
        MemorySegment secret = MemorySegment.NULL;
        int size = group.secretSize();
        try (Arena arena = Arena.ofConfined(); SecretScope raw = SecretScope.allocate(size)) {
            MemorySegment blob = arena.allocate(blobSize(), 4);
            blob.set(JAVA_INT, 0, magic);
            blob.set(JAVA_INT, 4, coordinate);
            if (group == NativeEcdh.Group.X25519) {
                MemorySegment.copy(peer, 0, blob, 8, 32);        // and a Y of zeros
            } else {
                MemorySegment.copy(peer, 1, blob, 8, 2L * coordinate);
            }
            MemorySegment handle = arena.allocate(ADDRESS);
            call(IMPORT, algorithm, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"), handle,
                    blob, blobSize(), 0);                         // validated by CNG
            peerKey = handle.get(ADDRESS, 0);
            call(AGREE, key, peerKey, handle, 0);
            secret = handle.get(ADDRESS, 0);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(DERIVE, secret, wide(arena, "TRUNCATE"), MemorySegment.NULL, raw.segment(), size,
                    count, 0);
            if (count.get(JAVA_INT, 0) != size) {
                throw new IllegalStateException("unexpected CNG " + group + " secret length");
            }
            for (int i = 0; i < size; i++) {
                out.set(JAVA_BYTE, i, raw.segment().get(JAVA_BYTE, size - 1 - i));
            }
        } finally {
            try {
                if (!secret.equals(MemorySegment.NULL)) {
                    call(DESTROY_SECRET, secret);
                }
            } finally {
                if (!peerKey.equals(MemorySegment.NULL)) {
                    call(DESTROY_KEY, peerKey);
                }
            }
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
                throw new IllegalStateException("CNG ECDH failed: NTSTATUS 0x"
                        + Integer.toHexString(status));
            }
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("CNG ECDH downcall failed", e);
        }
    }
}

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

/** CNG ECDH_P256. Blob coordinates are big-endian; RAW_SECRET is little-endian. */
final class CngP256 implements NativeP256.Backend {
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
    private static final MethodHandle OPEN = bind("BCryptOpenAlgorithmProvider", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle GENERATE = bind("BCryptGenerateKeyPair", ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle FINALIZE = bind("BCryptFinalizeKeyPair", ADDRESS, JAVA_INT);
    private static final MethodHandle IMPORT = bind("BCryptImportKeyPair", ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle EXPORT = bind("BCryptExportKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle AGREE = bind("BCryptSecretAgreement", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle DERIVE = bind("BCryptDeriveKey", ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle DESTROY_SECRET = bind("BCryptDestroySecret", ADDRESS);
    private static final MethodHandle DESTROY_KEY = bind("BCryptDestroyKey", ADDRESS);
    private static final MethodHandle CLOSE = bind("BCryptCloseAlgorithmProvider", ADDRESS, JAVA_INT);
    private static final int PUBLIC_MAGIC = 0x314b4345; // BCRYPT_ECDH_PUBLIC_P256_MAGIC
    private static final int PRIVATE_MAGIC = 0x324b4345;

    private MemorySegment algorithm = MemorySegment.NULL;
    private MemorySegment key = MemorySegment.NULL;

    CngP256(MemorySegment point, MemorySegment scalar) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment handle = arena.allocate(ADDRESS);
            call(OPEN, handle, wide(arena, "ECDH_P256"), MemorySegment.NULL, 0);
            algorithm = handle.get(ADDRESS, 0);
            if (point == null) {
                call(GENERATE, algorithm, handle, 256, 0);
                key = handle.get(ADDRESS, 0);
                call(FINALIZE, key, 0);
            } else {
                key = importBlob(point, scalar);
            }
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    private MemorySegment importBlob(MemorySegment point, MemorySegment scalar) {
        int size = scalar == null ? 72 : 104;
        try (Arena arena = Arena.ofConfined(); SecretScope blob = SecretScope.allocate(size)) {
            blob.segment().set(JAVA_INT, 0, scalar == null ? PUBLIC_MAGIC : PRIVATE_MAGIC);
            blob.segment().set(JAVA_INT, 4, 32);
            MemorySegment.copy(point, 1, blob.segment(), 8, 64);
            if (scalar != null) {
                MemorySegment.copy(scalar, 0, blob.segment(), 72, 32);
            }
            MemorySegment handle = arena.allocate(ADDRESS);
            call(IMPORT, algorithm, MemorySegment.NULL,
                    wide(arena, scalar == null ? "ECCPUBLICBLOB" : "ECCPRIVATEBLOB"),
                    handle, blob.segment(), size, 0); // do not disable point validation
            return handle.get(ADDRESS, 0);
        }
    }

    @Override
    public void publicKey(MemorySegment out) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = arena.allocate(72, 4);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(EXPORT, key, MemorySegment.NULL, wide(arena, "ECCPUBLICBLOB"), blob, 72, count, 0);
            if (count.get(JAVA_INT, 0) != 72 || blob.get(JAVA_INT, 0) != PUBLIC_MAGIC
                    || blob.get(JAVA_INT, 4) != 32) {
                throw new IllegalStateException("unexpected CNG public blob");
            }
            out.set(JAVA_BYTE, 0, (byte) 4);
            MemorySegment.copy(blob, 8, out, 1, 64);
        }
    }

    @Override
    public void derive(MemorySegment peer, MemorySegment out) {
        MemorySegment peerKey = importBlob(peer, null);
        MemorySegment secret = MemorySegment.NULL;
        try (Arena arena = Arena.ofConfined(); SecretScope raw = SecretScope.allocate(32)) {
            MemorySegment handle = arena.allocate(ADDRESS);
            call(AGREE, key, peerKey, handle, 0);
            secret = handle.get(ADDRESS, 0);
            MemorySegment count = arena.allocate(JAVA_INT);
            call(DERIVE, secret, wide(arena, "TRUNCATE"), MemorySegment.NULL, raw.segment(), 32, count, 0);
            if (count.get(JAVA_INT, 0) != 32) {
                throw new IllegalStateException("unexpected CNG ECDH length");
            }
            for (int i = 0; i < 32; i++) {
                out.set(JAVA_BYTE, i, raw.segment().get(JAVA_BYTE, 31 - i));
            }
        } finally {
            try {
                if (!secret.equals(MemorySegment.NULL)) call(DESTROY_SECRET, secret);
            } finally {
                call(DESTROY_KEY, peerKey);
            }
        }
    }

    @Override
    public void privateScalar(MemorySegment out) {
        try (Arena arena = Arena.ofConfined(); SecretScope blob = SecretScope.allocate(104)) {
            MemorySegment count = arena.allocate(JAVA_INT);
            call(EXPORT, key, MemorySegment.NULL, wide(arena, "ECCPRIVATEBLOB"), blob.segment(), 104, count, 0);
            if (count.get(JAVA_INT, 0) != 104 || blob.segment().get(JAVA_INT, 0) != PRIVATE_MAGIC) {
                throw new IllegalStateException("unexpected CNG private blob");
            }
            MemorySegment.copy(blob.segment(), 72, out, 0, 32);
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
        for (int i = 0; i < text.length(); i++) out.set(ValueLayout.JAVA_CHAR, 2L * i, text.charAt(i));
        return out;
    }

    private static MethodHandle bind(String name, ValueLayout... arguments) {
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, arguments));
    }

    private static void call(MethodHandle function, Object... args) {
        try {
            int status = (int) function.invokeWithArguments(args);
            if (status != 0) throw new IllegalStateException("CNG P-256 failed: NTSTATUS 0x" + Integer.toHexString(status));
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("CNG P-256 downcall failed", e);
        }
    }
}

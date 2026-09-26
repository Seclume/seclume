package space.seclume.crypto;

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

/**
 * AES-GCM through Windows CNG (bcrypt.dll): AES-NI where the CPU has it. The
 * key is imported once into a CNG key object, which CNG wipes when it is
 * destroyed.
 */
final class CngAesGcm implements AesGcmCipher {

    private static final SymbolLookup LIB = SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
    private static final MethodHandle OPEN = bind("BCryptOpenAlgorithmProvider", ADDRESS, ADDRESS, ADDRESS, JAVA_INT);
    private static final MethodHandle SET_PROPERTY = bind("BCryptSetProperty", ADDRESS, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle GENERATE_KEY = bind("BCryptGenerateSymmetricKey", ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT);
    private static final MethodHandle ENCRYPT = bind("BCryptEncrypt", ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle DECRYPT = bind("BCryptDecrypt", ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT);
    private static final MethodHandle DESTROY_KEY = bind("BCryptDestroyKey", ADDRESS);
    private static final MethodHandle CLOSE = bind("BCryptCloseAlgorithmProvider", ADDRESS, JAVA_INT);

    /** STATUS_AUTH_TAG_MISMATCH. */
    private static final int TAG_MISMATCH = 0xC000A002;
    /** sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) on 64-bit Windows. */
    private static final int MODE_INFO_SIZE = 88;

    private MemorySegment algorithm = MemorySegment.NULL;
    private MemorySegment key = MemorySegment.NULL;

    CngAesGcm(MemorySegment secret, long offset, int length) {
        if (ValueLayout.ADDRESS.byteSize() != 8) {
            throw new IllegalStateException("CNG AES-GCM is wired for 64-bit Windows");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment handle = arena.allocate(ADDRESS);
            check(call(OPEN, handle, wide(arena, "AES"), MemorySegment.NULL, 0),
                    "BCryptOpenAlgorithmProvider");
            algorithm = handle.get(ADDRESS, 0);
            MemorySegment mode = wide(arena, "ChainingModeGCM");
            check(call(SET_PROPERTY, algorithm, wide(arena, "ChainingMode"), mode,
                    (int) mode.byteSize(), 0), "BCryptSetProperty");
            check(call(GENERATE_KEY, algorithm, handle, MemorySegment.NULL, 0,
                    secret.asSlice(offset, length), length, 0), "BCryptGenerateSymmetricKey");
            key = handle.get(ADDRESS, 0);
        } catch (RuntimeException | Error failure) {
            close();
            throw failure;
        }
    }

    @Override
    public void encrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad, long aadOffset,
                        long aadLength, MemorySegment in, long inOffset, long length,
                        MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment info = modeInfo(arena, nonce, nonceOffset, aad, aadOffset, aadLength,
                    out.asSlice(outOffset + length, AesGcm.TAG));
            MemorySegment written = arena.allocate(JAVA_INT);
            check(call(ENCRYPT, key, in.asSlice(inOffset, length), (int) length, info,
                    MemorySegment.NULL, 0, out.asSlice(outOffset, length), (int) length,
                    written, 0), "BCryptEncrypt");
        }
    }

    @Override
    public boolean decrypt(MemorySegment nonce, long nonceOffset, MemorySegment aad,
                           long aadOffset, long aadLength, MemorySegment in, long inOffset,
                           long length, MemorySegment out, long outOffset) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment info = modeInfo(arena, nonce, nonceOffset, aad, aadOffset, aadLength,
                    in.asSlice(inOffset + length, AesGcm.TAG));
            MemorySegment written = arena.allocate(JAVA_INT);
            int status = call(DECRYPT, key, in.asSlice(inOffset, length), (int) length, info,
                    MemorySegment.NULL, 0, out.asSlice(outOffset, length), (int) length,
                    written, 0);
            if (status == TAG_MISMATCH) {
                if (length > 0) {
                    out.asSlice(outOffset, length).fill((byte) 0);
                }
                return false;
            }
            check(status, "BCryptDecrypt");
            return true;
        }
    }

    /** BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, version 1, for one message. */
    private static MemorySegment modeInfo(Arena arena, MemorySegment nonce, long nonceOffset,
                                          MemorySegment aad, long aadOffset, long aadLength,
                                          MemorySegment tag) {
        MemorySegment info = arena.allocate(MODE_INFO_SIZE, 8);
        info.fill((byte) 0);
        info.set(JAVA_INT, 0, MODE_INFO_SIZE);                       // cbSize
        info.set(JAVA_INT, 4, 1);                                    // dwInfoVersion
        info.set(ADDRESS, 8, nonce.asSlice(nonceOffset, AesGcm.NONCE)); // pbNonce
        info.set(JAVA_INT, 16, AesGcm.NONCE);                        // cbNonce
        if (aadLength > 0) {
            info.set(ADDRESS, 24, aad.asSlice(aadOffset, aadLength));   // pbAuthData
            info.set(JAVA_INT, 32, (int) aadLength);                 // cbAuthData
        }
        info.set(ADDRESS, 40, tag);                                  // pbTag
        info.set(JAVA_INT, 48, AesGcm.TAG);                          // cbTag
        info.set(JAVA_LONG, 72, 0L);                                 // cbData
        return info;
    }

    @Override
    public String implementation() {
        return "cng";
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

    private static void check(int status, String what) {
        if (status != 0) {
            throw new IllegalStateException("CNG AES-GCM failed in " + what + ": NTSTATUS 0x"
                    + Integer.toHexString(status));
        }
    }

    private static MethodHandle bind(String name, ValueLayout... arguments) {
        return Linker.nativeLinker().downcallHandle(LIB.find(name).orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, arguments));
    }

    private static int call(MethodHandle function, Object... arguments) {
        try {
            return (int) function.invokeWithArguments(arguments);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("CNG AES-GCM downcall failed", e);
        }
    }
}

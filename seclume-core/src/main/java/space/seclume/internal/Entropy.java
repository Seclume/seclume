package space.seclume.internal;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

/**
 * Randomness straight into an off-heap segment.
 *
 * <p>{@link SecureRandom#nextBytes(byte[])} can only write into a
 * {@code byte[]}. For plain random bytes that would be harmless - randomness is
 * not a secret - but here those bytes become padding <em>next to</em> the
 * password in the same buffer, and a second copying step is one more place to
 * get it wrong. Hence {@code BCryptGenRandom} on Windows,
 * {@code /dev/urandom} otherwise, and only if both are missing the detour via
 * an array that is zeroed immediately.
 */
public final class Entropy {

    private static final MethodHandle BCRYPT_GEN_RANDOM = lookupBCryptGenRandom();
    /** BCRYPT_USE_SYSTEM_PREFERRED_RNG - then hAlgorithm may be null. */
    private static final int USE_SYSTEM_PREFERRED_RNG = 0x00000002;

    private Entropy() {
    }

    /** Fills the whole segment with random bytes. */
    public static void fill(MemorySegment target) {
        fill(target, 0, target.byteSize());
    }

    /** Fills {@code length} bytes starting at {@code offset}. */
    public static void fill(MemorySegment target, long offset, long length) {
        if (length <= 0) {
            return;
        }
        MemorySegment slice = target.asSlice(offset, length);
        if (fillFromBCrypt(slice) || fillFromUrandom(slice)) {
            return;
        }
        fillFromSecureRandom(slice);
    }

    /**
     * Random bytes that are never zero - PKCS#1 v1.5 padding needs that,
     * because a zero marks the end of the padding.
     */
    public static void fillNonZero(MemorySegment target, long offset, long length) {
        fill(target, offset, length);
        for (long i = 0; i < length; i++) {
            while (target.get(ValueLayout.JAVA_BYTE, offset + i) == 0) {
                fill(target, offset + i, 1);
            }
        }
    }

    private static boolean fillFromBCrypt(MemorySegment target) {
        if (BCRYPT_GEN_RANDOM == null) {
            return false;
        }
        try {
            int status = (int) BCRYPT_GEN_RANDOM.invokeExact(
                    MemorySegment.NULL, target, (int) target.byteSize(), USE_SYSTEM_PREFERRED_RNG);
            return status == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean fillFromUrandom(MemorySegment target) {
        if (Platform.isWindows()) {
            return false;
        }
        try (FileChannel channel = FileChannel.open(Path.of("/dev/urandom"), StandardOpenOption.READ)) {
            ByteBuffer buffer = target.asByteBuffer();
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    return false;
                }
            }
            return true;
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    private static void fillFromSecureRandom(MemorySegment target) {
        byte[] scratch = new byte[(int) target.byteSize()];
        try {
            new SecureRandom().nextBytes(scratch);
            MemorySegment.copy(MemorySegment.ofArray(scratch), 0, target, 0, scratch.length);
        } finally {
            java.util.Arrays.fill(scratch, (byte) 0);
        }
    }

    private static MethodHandle lookupBCryptGenRandom() {
        if (!Platform.isWindows()) {
            return null;
        }
        try {
            SymbolLookup bcrypt = SymbolLookup.libraryLookup("bcrypt.dll", Arena.global());
            // NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG)
            return Linker.nativeLinker().downcallHandle(
                    bcrypt.find("BCryptGenRandom").orElseThrow(),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
        } catch (RuntimeException e) {
            return null;
        }
    }
}

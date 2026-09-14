package space.seclume.sqlserver.auth;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import space.seclume.internal.Utf;

/**
 * The password encoding of TDS - LOGIN7, SQL Server authentication.
 *
 * <p>Microsoft calls it obfuscation, and that is all it is: the password is
 * re-encoded to UTF-16LE, then each byte has its nibbles swapped and is XORed
 * with {@code 0xA5}. That is reversible without any key at all - whoever has
 * the bytes has the password.
 *
 * <p><b>This is why the connection belongs behind TLS.</b> The obfuscation
 * protects against nothing; it only keeps the password from standing in the
 * packet verbatim. A capture without TLS is equivalent to the password itself.
 * TDS provides for encrypting the login packet, and the driver has to use it -
 * see {@code docs/protocol/sqlserver.md}.
 *
 * <p>What this class does achieve is something else: the whole path from the
 * password to the finished field runs in native memory. The obvious one-liner
 * would be {@code password.getBytes(StandardCharsets.UTF_16LE)} - and that
 * puts the password on the heap as a {@code byte[]}, where it stays until
 * something happens to overwrite it. That is exactly what this library exists
 * to prevent, and exactly why {@code seclume-core} carries its own UTF-16
 * encoder.
 */
public final class TdsPassword {

    /** The fixed XOR value from the TDS specification. */
    private static final byte MASK = (byte) 0xA5;

    private TdsPassword() {
    }

    /**
     * How many bytes the obfuscated password occupies.
     *
     * <p>UTF-16 needs two bytes per character of the basic plane and four for
     * everything above it - emoji, for instance. The caller has to size the
     * buffer beforehand, hence this as a separate step.
     */
    public static int encodedLength(MemorySegment password, long offset, int length) {
        return Utf.utf16LeUpperBound(length);
    }

    /**
     * Encodes and obfuscates the password.
     *
     * @param password UTF-8 in native memory, the way the {@code SecretProvider}
     *                 delivers it
     * @param out      target; needs {@link #encodedLength} bytes
     * @return the length of the field written, in bytes
     */
    public static int obfuscate(MemorySegment password, long passwordOffset, int passwordLength,
                                MemorySegment out, long outOffset) {
        int written = Utf.utf8ToUtf16Le(password, passwordOffset, passwordLength, out, outOffset);
        for (int i = 0; i < written; i++) {
            byte value = out.get(ValueLayout.JAVA_BYTE, outOffset + i);
            // Swap the nibbles, then XOR - both in one pass.
            byte swapped = (byte) (((value & 0x0f) << 4) | ((value & 0xf0) >>> 4));
            out.set(ValueLayout.JAVA_BYTE, outOffset + i, (byte) (swapped ^ MASK));
        }
        return written;
    }

    /**
     * The inverse - for tests only.
     *
     * <p>It lives here rather than in test code because it demonstrates what
     * the obfuscation is: reversible, without a key. Anyone who reads this
     * method understands why TLS is not optional with SQL Server.
     */
    public static void deobfuscate(MemorySegment data, long offset, int length) {
        for (int i = 0; i < length; i++) {
            byte value = (byte) (data.get(ValueLayout.JAVA_BYTE, offset + i) ^ MASK);
            byte swapped = (byte) (((value & 0x0f) << 4) | ((value & 0xf0) >>> 4));
            data.set(ValueLayout.JAVA_BYTE, offset + i, swapped);
        }
    }
}

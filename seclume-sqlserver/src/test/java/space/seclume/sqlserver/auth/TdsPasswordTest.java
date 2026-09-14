package space.seclume.sqlserver.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The TDS password encoding, checked against an independent computation.
 *
 * <p>The rule is published in {@code MS-TDS}: UTF-16LE, swap the nibbles, XOR
 * with {@code 0xA5}. The comparison here runs the same rule but with the
 * built-in Java facilities - that is, with exactly the
 * {@code getBytes(UTF_16LE)} that is forbidden inside the driver. In a test
 * that is fine: this is a throwaway password that stands in the source anyway.
 */
class TdsPasswordTest {

    /** The same rule with built-in facilities - the independent cross-check. */
    private static byte[] withJava(String password) {
        byte[] utf16 = password.getBytes(StandardCharsets.UTF_16LE);
        byte[] out = new byte[utf16.length];
        for (int i = 0; i < utf16.length; i++) {
            int value = utf16[i] & 0xff;
            int swapped = ((value & 0x0f) << 4) | ((value & 0xf0) >>> 4);
            out[i] = (byte) (swapped ^ 0xA5);
        }
        return out;
    }

    @Test
    void matchesAnIndependentComputation() {
        for (String password : new String[] {
                "secret", "a", "Passwort mit Umlaut äöü", "🔐 emoji", "",
                "ein ziemlich langes Passwort mit Sonderzeichen !\"§$%&/()=?"}) {
            try (Arena arena = Arena.ofConfined()) {
                byte[] utf8 = password.getBytes(StandardCharsets.UTF_8);
                MemorySegment source = segment(arena, utf8);
                MemorySegment out = arena.allocate(
                        Math.max(TdsPassword.encodedLength(source, 0, utf8.length), 1));
                int written = TdsPassword.obfuscate(source, 0, utf8.length, out, 0);
                assertArrayEquals(withJava(password), bytes(out, written), password);
            }
        }
    }

    /**
     * The encoding is reversible - without a key, without a secret.
     *
     * <p>This test is here not because the inverse is needed, but because it
     * is the reason why SQL Server without TLS is not acceptable.
     */
    @Test
    void theObfuscationIsTriviallyReversible() {
        String password = "Nicht wirklich geschuetzt äöü";
        byte[] utf8 = password.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = segment(arena, utf8);
            MemorySegment out = arena.allocate(TdsPassword.encodedLength(source, 0, utf8.length));
            int written = TdsPassword.obfuscate(source, 0, utf8.length, out, 0);
            assertNotEquals(password, new String(bytes(out, written), StandardCharsets.UTF_16LE));

            TdsPassword.deobfuscate(out, 0, written);
            assertEquals(password, new String(bytes(out, written), StandardCharsets.UTF_16LE));
        }
    }

    /** Characters outside the basic plane need four bytes, not two. */
    @Test
    void countsSurrogatePairsCorrectly() {
        byte[] utf8 = "🔐".getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment source = segment(arena, utf8);
            MemorySegment out = arena.allocate(TdsPassword.encodedLength(source, 0, utf8.length));
            assertEquals(4, TdsPassword.obfuscate(source, 0, utf8.length, out, 0));
        }
    }

    private static MemorySegment segment(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            result[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }
        return result;
    }
}

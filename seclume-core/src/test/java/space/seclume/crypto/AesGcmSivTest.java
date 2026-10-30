package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * What {@link AesGcmSiv} promises beyond the vectors of {@code WycheproofTest}:
 * the property field encryption is built on - a repeated nonce reveals
 * equality and nothing else - and the way it fails.
 */
class AesGcmSivTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Random RANDOM = new Random(8);

    /** RFC 8452 appendix C.2, the AES-256 case with eight bytes of plaintext and one of AAD. */
    @Test
    void rfc8452Appendix() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = hex(arena,
                    "0100000000000000000000000000000000000000000000000000000000000000");
            MemorySegment nonce = hex(arena, "030000000000000000000000");
            MemorySegment aad = hex(arena, "01");
            MemorySegment plain = hex(arena, "0200000000000000");
            MemorySegment out = arena.allocate(8 + 16);
            AesGcmSiv.encrypt(key, 0, 32, nonce, 0, aad, 0, 1, plain, 0, 8, out, 0);
            assertEquals("1de22967237a813291213f267e3b452f02d01ae33e4ec854",
                    HEX.formatHex(out.toArray(ValueLayout.JAVA_BYTE)));
        }
    }

    @Test
    void theSameNonceAndPlaintextGiveTheSameCiphertextAndADifferentPlaintextDoesNot() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 32, 1);
            MemorySegment nonce = arena.allocate(12);
            byte[] a1 = seal(arena, key, nonce, "4111 1111 1111 1111");
            byte[] a2 = seal(arena, key, nonce, "4111 1111 1111 1111");
            byte[] b = seal(arena, key, nonce, "4111 1111 1111 1112");
            assertArrayEquals(a1, a2, "deterministic under one nonce");
            assertFalse(Arrays.equals(a1, b));
            // GCM under a repeated nonce XORs to the XOR of the plaintexts; SIV must not.
            int same = 0;
            for (int i = 0; i < 19; i++) {
                same += a1[i] == b[i] ? 1 : 0;
            }
            assertTrue(same < 5, "a one-character change left " + same + " of 19 bytes equal - "
                    + "a counter that did not depend on the message");
        }
    }

    @Test
    void anotherNonceGivesAnotherCiphertext() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 32, 2);
            MemorySegment n1 = arena.allocate(12);
            MemorySegment n2 = arena.allocate(12);
            n2.set(ValueLayout.JAVA_BYTE, 11, (byte) 1);
            assertNotEquals(HEX.formatHex(seal(arena, key, n1, "x")),
                    HEX.formatHex(seal(arena, key, n2, "x")));
        }
    }

    @Test
    void everyAlteredByteFailsAndLeavesNothingBehind() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 32, 3);
            MemorySegment nonce = random(arena, 12, 4);
            MemorySegment aad = random(arena, 7, 5);
            byte[] message = "the plaintext of a forged value".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII);
            MemorySegment sealed = arena.allocate(message.length + 16L);
            AesGcmSiv.encrypt(key, 0, 32, nonce, 0, aad, 0, 7,
                    MemorySegment.ofArray(message), 0, message.length, sealed, 0);
            MemorySegment out = arena.allocate(message.length);
            for (long at = 0; at < sealed.byteSize(); at++) {
                byte original = sealed.get(ValueLayout.JAVA_BYTE, at);
                sealed.set(ValueLayout.JAVA_BYTE, at, (byte) (original ^ 0x01));
                out.fill((byte) 0x55);
                assertFalse(AesGcmSiv.decrypt(key, 0, 32, nonce, 0, aad, 0, 7,
                        sealed, 0, message.length, out, 0), "byte " + at + " altered");
                assertArrayEquals(new byte[message.length], out.toArray(ValueLayout.JAVA_BYTE),
                        "plaintext left behind after byte " + at + " was altered");
                sealed.set(ValueLayout.JAVA_BYTE, at, original);
            }
            assertTrue(AesGcmSiv.decrypt(key, 0, 32, nonce, 0, aad, 0, 7,
                    sealed, 0, message.length, out, 0));
            assertArrayEquals(message, out.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void inPlaceBothWays() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = random(arena, 16, 6);
            MemorySegment nonce = random(arena, 12, 7);
            MemorySegment aad = arena.allocate(1);
            byte[] message = new byte[100];
            RANDOM.nextBytes(message);
            MemorySegment buffer = arena.allocate(116);
            MemorySegment.copy(message, 0, buffer, ValueLayout.JAVA_BYTE, 0, 100);
            MemorySegment separate = arena.allocate(116);
            AesGcmSiv.encrypt(key, 0, 16, nonce, 0, aad, 0, 0, buffer, 0, 100, separate, 0);
            AesGcmSiv.encrypt(key, 0, 16, nonce, 0, aad, 0, 0, buffer, 0, 100, buffer, 0);
            assertArrayEquals(separate.toArray(ValueLayout.JAVA_BYTE),
                    buffer.toArray(ValueLayout.JAVA_BYTE));
            assertTrue(AesGcmSiv.decrypt(key, 0, 16, nonce, 0, aad, 0, 0, buffer, 0, 100,
                    buffer, 0));
            assertArrayEquals(message, buffer.asSlice(0, 100).toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void onlyTheKeysAndLengthsOfRfc8452() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(32);
            MemorySegment nonce = arena.allocate(12);
            MemorySegment none = arena.allocate(16);
            assertThrows(IllegalArgumentException.class, () -> AesGcmSiv.encrypt(key, 0, 24,
                    nonce, 0, none, 0, 0, none, 0, 0, none, 0));
            assertThrows(IllegalArgumentException.class, () -> AesGcmSiv.encrypt(key, 0, 32,
                    nonce, 0, none, 0, 0, none, 0, AesGcmSiv.MAX_LENGTH + 1, none, 0));
            assertThrows(IllegalArgumentException.class, () -> AesGcmSiv.decrypt(key, 0, 32,
                    nonce, 0, none, 0, -1, none, 0, 0, none, 0));
        }
    }

    private static byte[] seal(Arena arena, MemorySegment key, MemorySegment nonce, String text) {
        byte[] message = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        MemorySegment out = arena.allocate(message.length + 16L);
        AesGcmSiv.encrypt(key, 0, (int) key.byteSize(), nonce, 0, arena.allocate(1), 0, 0,
                MemorySegment.ofArray(message), 0, message.length, out, 0);
        return out.toArray(ValueLayout.JAVA_BYTE);
    }

    private static MemorySegment hex(Arena arena, String hex) {
        byte[] bytes = HEX.parseHex(hex);
        MemorySegment segment = arena.allocate(bytes.length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static MemorySegment random(Arena arena, int length, long seed) {
        // Fixed bytes per seed, so that a failure replays; drawn from the seeded field.
        byte[] bytes = new byte[length];
        long state = seed * 0x9E3779B97F4A7C15L;
        for (int i = 0; i < length; i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            bytes[i] = (byte) (state >>> 56);
        }
        MemorySegment segment = arena.allocate(length);
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, length);
        return segment;
    }
}

package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.Aes;
import space.seclume.crypto.AesKey;

/**
 * {@code AUTH_SVR_RESPONSE}, the server's proof that it knows the password:
 * 16 random bytes and {@code SERVER_TO_CLIENT}, AES-CBC under the combo key
 * with a zero IV. Built here the way a server builds it, for both key
 * lengths - 32 bytes with the 12c verifier, 24 with the 11g one.
 *
 * <p>Whether a real server builds it this way is the CI's Oracle job to say:
 * every login there goes through the check.
 */
class ServerProofTest {

    private static final byte[] MARKER = "SERVER_TO_CLIENT".getBytes(StandardCharsets.US_ASCII);

    @Test
    void aProofUnderTheComboKeyIsAccepted() {
        for (int keyLength : new int[] {32, 24}) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment key = filled(arena, keyLength, 0x31);
                MemorySegment proof = proof(arena, key, keyLength, MARKER, 32);
                assertTrue(O5Login12c.serverProofMatches(key, 0, keyLength, proof, 0, 32),
                        keyLength + "-byte key");
                MemorySegment padded = proof(arena, key, keyLength, MARKER, 48);
                assertTrue(O5Login12c.serverProofMatches(key, 0, keyLength, padded, 0, 48),
                        keyLength + "-byte key, a proof with a further block");
            }
        }
    }

    @Test
    void aProofUnderAnotherKeyIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = filled(arena, 32, 0x31);
            MemorySegment other = filled(arena, 32, 0x32);
            MemorySegment proof = proof(arena, other, 32, MARKER, 32);
            assertFalse(O5Login12c.serverProofMatches(key, 0, 32, proof, 0, 32));
        }
    }

    @Test
    void aProofWithoutTheMarkerIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = filled(arena, 32, 0x31);
            byte[] almost = MARKER.clone();
            almost[almost.length - 1] ^= 1;
            MemorySegment proof = proof(arena, key, 32, almost, 32);
            assertFalse(O5Login12c.serverProofMatches(key, 0, 32, proof, 0, 32));
        }
    }

    @Test
    void aProofOfTheWrongLengthIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = filled(arena, 32, 0x31);
            MemorySegment proof = proof(arena, key, 32, MARKER, 32);
            assertFalse(O5Login12c.serverProofMatches(key, 0, 32, proof, 0, 16),
                    "one block holds no marker");
            assertFalse(O5Login12c.serverProofMatches(key, 0, 32, proof, 0, 31),
                    "not a whole number of blocks");
            assertFalse(O5Login12c.serverProofMatches(key, 0, 32, proof, 0, 0), "empty");
        }
    }

    /** {@code length} bytes: 16 of noise, the marker, zeroes - encrypted as a server does. */
    private static MemorySegment proof(Arena arena, MemorySegment key, int keyLength,
                                       byte[] marker, int length) {
        MemorySegment plain = filled(arena, length, 0x77);
        MemorySegment.copy(marker, 0, plain, ValueLayout.JAVA_BYTE, 16, marker.length);
        plain.asSlice(16 + marker.length).fill((byte) 0);
        MemorySegment out = arena.allocate(length);
        try (AesKey aes = new AesKey(key, 0, keyLength)) {
            Aes.cbcEncrypt(aes, arena.allocate(Aes.BLOCK), plain, 0, out, 0, length);
        }
        return out;
    }

    private static MemorySegment filled(Arena arena, int length, int seed) {
        MemorySegment out = arena.allocate(length);
        for (int i = 0; i < length; i++) {
            out.set(ValueLayout.JAVA_BYTE, i, (byte) (seed + i * 13));
        }
        return out;
    }
}

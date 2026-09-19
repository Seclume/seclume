package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * The frozen form of a connection's encryption, checked the only way that
 * actually proves it: by sealing a record with the original keys and with
 * the thawed ones and requiring the bytes to be <b>identical</b>.
 *
 * <p>Comparing fields would not do it. AES-GCM's output depends on the key,
 * the IV and the sequence number together - so two protections that produce
 * the same ciphertext for the same plaintext agree on all three, and two
 * that disagree anywhere produce completely different bytes. It is the same
 * reasoning the AEAD tag gives elsewhere in this package: the cipher is the
 * comparison.
 *
 * <p>The sequence number is the field this is really aimed at. A migration
 * that carried the secrets and quietly restarted the counter would look
 * perfect in every field-by-field test and be refused by the peer on the
 * very first record.
 */
class TlsMigrationTest {

    private static final byte[] PLAINTEXT = "a record that both must produce alike"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    @Test
    void aThawedConnectionSealsExactlyWhatTheOriginalWouldHave() {
        for (HashAlgorithm hash : new HashAlgorithm[] {HashAlgorithm.SHA_256, HashAlgorithm.SHA_384}) {
            int keyLength = hash == HashAlgorithm.SHA_384 ? 32 : 16;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment readSecret = secret(arena, hash.digestLength(), 0x11);
                MemorySegment writeSecret = secret(arena, hash.digestLength(), 0x22);

                try (RecordProtection reading = RecordProtection.fromSecret(hash, readSecret, keyLength);
                        RecordProtection writing = RecordProtection.fromSecret(hash, writeSecret, keyLength)) {
                    // Somewhere in the middle of a conversation, not at record zero.
                    reading.sequence(7);
                    writing.sequence(12);

                    MemorySegment blob = arena.allocate(TlsMigration.encodedLength(hash));
                    int length = TlsMigration.encode(blob, 0, reading, writing);
                    assertEquals(TlsMigration.encodedLength(hash), length);

                    byte[] expected = seal(arena, writing);      // advances the original to 13

                    TlsMigration.Thawed thawed = TlsMigration.decode(blob, 0, length);
                    try {
                        assertEquals(7, thawed.reading().sequence());
                        assertEquals(12, thawed.writing().sequence());
                        assertArrayEquals(expected, seal(arena, thawed.writing()),
                                hash + ": the thawed connection must seal the same bytes - key, "
                                        + "IV and sequence number all travelled or none did");
                    } finally {
                        thawed.reading().close();
                        thawed.writing().close();
                    }
                }
            }
        }
    }

    /**
     * The control for the test above: one step out on the counter and the
     * bytes are unrecognisable. Without this, "the bytes match" would not
     * establish that the sequence number was carried at all.
     */
    @Test
    void oneStepWrongOnTheCounterChangesEverything() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = secret(arena, 32, 0x33);
            try (RecordProtection first = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
                    RecordProtection second = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16)) {
                first.sequence(5);
                second.sequence(6);
                assertFalse(java.util.Arrays.equals(seal(arena, first), seal(arena, second)),
                        "the same key at a different sequence number must not produce the same "
                                + "record, or this whole test proves nothing");
            }
        }
    }

    // ---- what must be refused --------------------------------------------

    @Test
    void aDamagedBlobIsRefusedRatherThanUsed() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = valid(arena);
            int length = TlsMigration.encodedLength(HashAlgorithm.SHA_256);
            // A single bit anywhere in the secret, which no field check would notice.
            long at = length - 5;
            blob.set(ValueLayout.JAVA_BYTE, at,
                    (byte) (blob.get(ValueLayout.JAVA_BYTE, at) ^ 1));
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> TlsMigration.decode(blob, 0, length));
            org.junit.jupiter.api.Assertions.assertTrue(refused.getMessage().contains("checksum"),
                    refused.getMessage());
        }
    }

    @Test
    void someoneElsesBufferIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = valid(arena);
            blob.set(ValueLayout.JAVA_BYTE, 0, (byte) 0);
            assertThrows(IllegalArgumentException.class,
                    () -> TlsMigration.decode(blob, 0, TlsMigration.encodedLength(HashAlgorithm.SHA_256)));
        }
    }

    @Test
    void aNewerVersionIsRefusedRatherThanHalfUnderstood() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = valid(arena);
            blob.set(ValueLayout.JAVA_BYTE, 7, (byte) (TlsMigration.VERSION + 1));
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> TlsMigration.decode(blob, 0, TlsMigration.encodedLength(HashAlgorithm.SHA_256)));
            org.junit.jupiter.api.Assertions.assertTrue(refused.getMessage().contains("version"),
                    refused.getMessage());
        }
    }

    @Test
    void aTruncatedBlobIsRefused() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment blob = valid(arena);
            assertThrows(IllegalArgumentException.class, () -> TlsMigration.decode(blob, 0, 20));
        }
    }

    // ---- fixtures ---------------------------------------------------------

    private static MemorySegment valid(Arena arena) {
        MemorySegment secret = secret(arena, 32, 0x44);
        MemorySegment blob = arena.allocate(TlsMigration.encodedLength(HashAlgorithm.SHA_256));
        try (RecordProtection reading = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
                RecordProtection writing = RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16)) {
            TlsMigration.encode(blob, 0, reading, writing);
        }
        return blob;
    }

    private static MemorySegment secret(Arena arena, int length, int seed) {
        MemorySegment out = arena.allocate(length);
        for (int i = 0; i < length; i++) {
            out.set(ValueLayout.JAVA_BYTE, i, (byte) (seed + i * 7));
        }
        return out;
    }

    private static byte[] seal(Arena arena, RecordProtection protection) {
        MemorySegment plain = arena.allocate(PLAINTEXT.length);
        MemorySegment.copy(PLAINTEXT, 0, plain, ValueLayout.JAVA_BYTE, 0, PLAINTEXT.length);
        MemorySegment out = arena.allocate(RecordProtection.sealedLength(PLAINTEXT.length));
        int written = protection.seal(RecordProtection.APPLICATION_DATA, plain, 0,
                PLAINTEXT.length, out, 0);
        return out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
    }
}

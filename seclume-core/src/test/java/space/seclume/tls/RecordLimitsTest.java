package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import org.junit.jupiter.api.Test;
import space.seclume.crypto.HashAlgorithm;

/**
 * The size and shape limits of the record layer that no test pinned
 * (mutation testing, round 9: T20-T22): what is too long to seal, too short
 * to open, and a TLS 1.3 record that is nothing but zeroes.
 */
class RecordLimitsTest {
    private static final int MAX_PLAINTEXT = 1 << 14;
    private static final int TAG = 16;
    private static final int EXPLICIT = 8;

    private static MemorySegment secret(Arena arena) {
        MemorySegment s = arena.allocate(32);
        for (int i = 0; i < 32; i++) {
            s.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 3));
        }
        return s;
    }

    private static RecordProtection tls13(Arena arena) {
        return RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret(arena), 16);
    }

    private static RecordProtection tls12(Arena arena) {
        MemorySegment block = arena.allocate(20);
        for (int i = 0; i < 20; i++) {
            block.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 5 + 2));
        }
        return RecordProtection.forTls12(HashAlgorithm.SHA_256, block, 0, 16, 16);
    }

    /**
     * A TLS 1.3 record of exactly the tag has no room for the inner content
     * type: not opened. One byte more is opened and fails on the tag. A
     * negative length - a caller's arithmetic gone wrong - opens nothing.
     */
    @Test
    void aTls13RecordOfOnlyTheTagOrANegativeLengthIsNotOpened() {
        try (Arena arena = Arena.ofConfined()) {
            RecordProtection v13 = tls13(arena);
            MemorySegment record = arena.allocate(RecordProtection.HEADER + TAG + 1);
            assertNull(v13.open(record, 0, RecordProtection.HEADER + TAG, arena.allocate(64), 0),
                    "a record of only the tag was opened");
            assertNull(v13.open(record, 0, -1, arena.allocate(64), 0), "a negative length");
            assertNull(v13.open(record, 0, RecordProtection.HEADER + TAG + 1, arena.allocate(64), 0),
                    "a forged one-byte record was let through");
        }
    }

    @Test
    void moreThanTwoToTheFourteenBytesAreNeverSealed() {
        try (Arena arena = Arena.ofConfined(); RecordProtection v13 = tls13(arena); RecordProtection v12 = tls12(arena)) {
            MemorySegment plain = arena.allocate(MAX_PLAINTEXT + 1);
            MemorySegment out = arena.allocate(RecordProtection.HEADER + EXPLICIT + MAX_PLAINTEXT + 1 + 1 + TAG);
            assertThrows(IllegalArgumentException.class, () -> v13.seal((byte) 23, plain, 0, MAX_PLAINTEXT + 1, out, 0));
            assertThrows(IllegalArgumentException.class, () -> v12.seal((byte) 23, plain, 0, MAX_PLAINTEXT + 1, out, 0));
        }
    }

    @Test
    void aTls12RecordTooShortForNonceAndTagIsNotOpened() {
        try (Arena arena = Arena.ofConfined(); RecordProtection v12 = tls12(arena)) {
            MemorySegment record = arena.allocate(RecordProtection.HEADER + EXPLICIT + TAG);
            record.set(ValueLayout.JAVA_BYTE, 0, (byte) 23);
            assertNull(v12.open(record, 0, RecordProtection.HEADER + EXPLICIT + TAG - 1, arena.allocate(64), 0));
        }
    }

    @Test
    void aTls12RecordAnnouncingMoreThanTwoToTheFourteenIsRefusedBeforeDecrypting() {
        try (Arena arena = Arena.ofConfined(); RecordProtection v12 = tls12(arena)) {
            int length = RecordProtection.HEADER + EXPLICIT + MAX_PLAINTEXT + 1 + TAG;
            MemorySegment record = arena.allocate(length);
            assertThrows(IllegalArgumentException.class,
                    () -> v12.open(record, 0, length, arena.allocate(MAX_PLAINTEXT + 1), 0));
        }
    }

    /**
     * RFC 8446 section 5.4: an inner plaintext longer than 2^14 + 1 bytes is
     * record_overflow - refused before decrypting, and at 2^14 + 1 still
     * opened (here it does not authenticate, which is a different answer).
     */
    @Test
    void aTls13InnerPlaintextBeyondTwoToTheFourteenPlusOneIsRefused() {
        try (Arena arena = Arena.ofConfined(); RecordProtection v13 = tls13(arena)) {
            for (int inner : new int[] {MAX_PLAINTEXT + 2, MAX_PLAINTEXT + 216, MAX_PLAINTEXT + 256 - TAG}) {
                int length = RecordProtection.HEADER + inner + TAG;
                MemorySegment record = arena.allocate(length);
                record.set(ValueLayout.JAVA_BYTE, 0, (byte) 23);
                assertThrows(IllegalArgumentException.class,
                        () -> v13.open(record, 0, length, arena.allocate(inner), 0), inner + " bytes");
            }
            int length = RecordProtection.HEADER + MAX_PLAINTEXT + 1 + TAG;
            MemorySegment record = arena.allocate(length);
            record.set(ValueLayout.JAVA_BYTE, 0, (byte) 23);
            assertNull(v13.open(record, 0, length, arena.allocate(MAX_PLAINTEXT + 1), 0),
                    "2^14 + 1 is within the limit: decrypted, and refused only for its tag");
        }
    }

    @Test
    void aTls13RecordOfNothingButZeroesHasNoContentTypeAndIsRefused() {
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls13(arena); RecordProtection receiver = tls13(arena)) {
            MemorySegment zeroes = arena.allocate(5);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + 5 + 1 + TAG);
            int written = sender.seal((byte) 0, zeroes, 0, 5, wire, 0);
            assertNull(receiver.open(wire, 0, written, arena.allocate(64), 0),
                    "RFC 8446 5.4: an inner plaintext of only zeroes is unexpected_message, not an empty record");
        }
    }

    @Test
    void aTls13RecordShorterThanItsTagIsNotOpened() {
        try (Arena arena = Arena.ofConfined(); RecordProtection v13 = tls13(arena)) {
            MemorySegment record = arena.allocate(RecordProtection.HEADER + TAG);
            record.set(ValueLayout.JAVA_BYTE, 0, (byte) 23);
            for (int body : new int[] {0, 1, TAG - 1}) {
                assertNull(v13.open(record, 0, RecordProtection.HEADER + body, arena.allocate(64), 0),
                        "a body of " + body + " bytes cannot even hold the tag");
            }
        }
    }

    @Test
    void exactlyTwoToTheFourteenBytesStillTravelInTls12() {
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls12(arena); RecordProtection receiver = tls12(arena)) {
            MemorySegment plain = arena.allocate(MAX_PLAINTEXT);
            plain.fill((byte) 0x5a);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + EXPLICIT + MAX_PLAINTEXT + TAG);
            int written = sender.seal((byte) 23, plain, 0, MAX_PLAINTEXT, wire, 0);
            RecordProtection.Opened opened = receiver.open(wire, 0, written, arena.allocate(MAX_PLAINTEXT), 0);
            org.junit.jupiter.api.Assertions.assertNotNull(opened, "the largest record there may be");
            org.junit.jupiter.api.Assertions.assertEquals(MAX_PLAINTEXT, opened.length());
        }
    }
}

package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;

/**
 * The record protection at the edges of what it accepts - the longest inner
 * content, an empty TLS 1.2 record, an output buffer of exactly the right
 * size - and the KeyUpdate secret against HKDF computed here with the JDK.
 *
 * <p>The record tests that go through a socket reached these lines slowly
 * enough that PIT timed their faults out on a slow runner and let them
 * survive on a fast one.
 */
class RecordProtectionEdgesTest {

    private static final int TAG = 16;
    private static final int MAX_INNER = 16384 + 256 - TAG;

    private static MemorySegment secret(Arena arena) {
        MemorySegment s = arena.allocate(32);
        for (int i = 0; i < 32; i++) {
            s.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 9 + 4));
        }
        return s;
    }

    private static RecordProtection tls13(Arena arena) {
        return RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret(arena), 16);
    }

    private static RecordProtection tls12(Arena arena) {
        MemorySegment block = arena.allocate(16 + 4);
        for (int i = 0; i < 20; i++) {
            block.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 3 + 1));
        }
        return RecordProtection.forTls12(HashAlgorithm.SHA_256, block, 0, 16, 16);
    }

    @Test
    void theLongestInnerContentIsOpenedAndOneByteMoreIsRefused() {
        try (Arena arena = Arena.ofConfined(); RecordProtection p = tls13(arena)) {
            MemorySegment record = arena.allocate(RecordProtection.HEADER + MAX_INNER + 1 + TAG);
            MemorySegment out = arena.allocate(MAX_INNER + 1);
            assertNull(p.open(record, 0, RecordProtection.HEADER + MAX_INNER + TAG, out, 0),
                    "the longest there may be: opened, and zeroes do not authenticate");
            assertThrows(IllegalArgumentException.class,
                    () -> p.open(record, 0, RecordProtection.HEADER + MAX_INNER + 1 + TAG, out, 0));
        }
    }

    /**
     * Opened with room for the inner type (straight into the caller's buffer)
     * and with room for the payload alone (through the protection's own).
     */
    @Test
    void aSealedRecordOpensToWhatWasSealedWithOrWithoutRoomForItsType() {
        byte[] text = "a record".getBytes(StandardCharsets.US_ASCII);
        for (int room : new int[] {text.length + 1, text.length}) {
            try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls13(arena);
                    RecordProtection receiver = tls13(arena)) {
                MemorySegment plain = arena.allocate(text.length);
                MemorySegment.copy(text, 0, plain, ValueLayout.JAVA_BYTE, 0, text.length);
                MemorySegment wire = arena.allocate(RecordProtection.HEADER + text.length + 1 + TAG);
                int written = sender.seal((byte) 22, plain, 0, text.length, wire, 0);
                MemorySegment out = arena.allocate(room);

                RecordProtection.Opened opened = receiver.open(wire, 0, written, out, 0);
                assertNotNull(opened, "room for " + room);
                assertEquals(22, opened.contentType());
                assertArrayEquals(text, out.asSlice(0, opened.length()).toArray(ValueLayout.JAVA_BYTE));
            }
        }
    }

    @Test
    void anEmptyTls12RecordOpensIntoNoRoomAtAll() {
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls12(arena);
                RecordProtection receiver = tls12(arena)) {
            MemorySegment none = arena.allocate(1);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + 8 + TAG);
            int written = sender.seal((byte) 23, none, 0, 0, wire, 0);
            assertEquals(wire.byteSize(), written);

            RecordProtection.Opened opened = receiver.open(wire, 0, written, arena.allocate(0), 0);
            assertNotNull(opened, "an empty record with a valid tag");
            assertEquals(23, opened.contentType());
            assertEquals(0, opened.length());
        }
    }

    @Test
    void aTls12RecordOpensIntoExactlyItsLengthAndNotIntoLess() {
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls12(arena);
                RecordProtection receiver = tls12(arena)) {
            MemorySegment plain = arena.allocate(40);
            plain.fill((byte) 0x61);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + 8 + 40 + TAG);
            int written = sender.seal((byte) 23, plain, 0, 40, wire, 0);

            IllegalArgumentException small = assertThrows(IllegalArgumentException.class,
                    () -> receiver.open(wire, 0, written, arena.allocate(39), 0));
            assertTrue(small.getMessage().contains("no room for 40 bytes"), small.getMessage());
            MemorySegment exact = arena.allocate(40);
            RecordProtection.Opened opened = receiver.open(wire, 0, written, exact, 0);
            assertNotNull(opened);
            assertEquals(40, opened.length());
            assertArrayEquals(plain.toArray(ValueLayout.JAVA_BYTE), exact.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void aTls12RecordOf16KiBIsSealed() {
        try (Arena arena = Arena.ofConfined(); RecordProtection p = tls12(arena)) {
            MemorySegment plain = arena.allocate(16384);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + 8 + 16384 + TAG);
            assertEquals(wire.byteSize(), p.seal((byte) 23, plain, 0, 16384, wire, 0));
        }
    }

    /**
     * RFC 8446 section 7.2: application_traffic_secret_N+1 =
     * HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length),
     * one HMAC block for SHA-256.
     */
    @Test
    void aKeyUpdateDerivesTheSecretRfc8446Gives() throws Exception {
        try (Arena arena = Arena.ofConfined(); RecordProtection p = tls13(arena);
                RecordProtection next = p.next()) {
            byte[] label = "tls13 traffic upd".getBytes(StandardCharsets.US_ASCII);
            byte[] info = new byte[2 + 1 + label.length + 1 + 1];
            info[1] = 32;
            info[2] = (byte) label.length;
            System.arraycopy(label, 0, info, 3, label.length);
            info[3 + label.length] = 0;                  // empty context
            info[4 + label.length] = 1;                  // HKDF-Expand's counter
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(secret(arena).toArray(ValueLayout.JAVA_BYTE), "HmacSHA256"));
            byte[] expected = hmac.doFinal(info);

            MemorySegment got = arena.allocate(next.secretLength());
            next.copySecretInto(got, 0);
            assertArrayEquals(expected, got.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Test
    void closedKeysCannotSealAnotherRecord() {
        try (Arena arena = Arena.ofConfined()) {
            RecordProtection p = tls13(arena);
            p.close();
            MemorySegment out = arena.allocate(RecordProtection.HEADER + 2 + TAG);
            assertThrows(IllegalStateException.class,
                    () -> p.seal(RecordProtection.APPLICATION_DATA, out, 0, 1, out, 0));
            assertThrows(IllegalStateException.class, () -> p.copySecretInto(arena.allocate(32), 0),
                    "the secret's memory was released, not only wiped");
            p.close();                                   // and a second close is harmless
        }
    }

    /** Eight bytes into the caller's buffer, which then has room for the payload and no more. */
    @Test
    void anOffsetIntoTheOutputCountsAgainstItsRoom() {
        byte[] text = "offset".getBytes(StandardCharsets.US_ASCII);
        int offset = 8;
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls13(arena);
                RecordProtection receiver = tls13(arena)) {
            MemorySegment plain = arena.allocate(text.length);
            MemorySegment.copy(text, 0, plain, ValueLayout.JAVA_BYTE, 0, text.length);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + text.length + 1 + TAG);
            int written = sender.seal((byte) 22, plain, 0, text.length, wire, 0);
            MemorySegment out = arena.allocate(offset + text.length);

            RecordProtection.Opened opened = receiver.open(wire, 0, written, out, offset);
            assertNotNull(opened);
            assertArrayEquals(text, out.asSlice(offset, opened.length()).toArray(ValueLayout.JAVA_BYTE));
        }
        try (Arena arena = Arena.ofConfined(); RecordProtection sender = tls12(arena);
                RecordProtection receiver = tls12(arena)) {
            MemorySegment plain = arena.allocate(40);
            MemorySegment wire = arena.allocate(RecordProtection.HEADER + 8 + 40 + TAG);
            int written = sender.seal((byte) 23, plain, 0, 40, wire, 0);
            assertThrows(IllegalArgumentException.class,
                    () -> receiver.open(wire, 0, written, arena.allocate(offset + 39), offset));
        }
    }
}

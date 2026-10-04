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
import java.nio.ByteBuffer;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.crypto.HashAlgorithm;

/**
 * The TLS 1.2 AES-GCM record (RFC 5288, RFC 5246 section 6.2.3.3) against the
 * JDK's AES-GCM, both ways: what this writes the JDK opens, and what the JDK
 * writes this opens - nonce, additional data and frame are each a place where
 * two implementations can disagree while both look right on their own.
 */
class Tls12RecordProtectionTest {

    private static final Random RANDOM = new Random(12);

    @ParameterizedTest(name = "AES-{0}")
    @ValueSource(ints = {128, 256})
    void whatThisSealsTheJdkOpens(int bits) throws Exception {
        byte[] key = bytes(bits / 8);
        byte[] salt = bytes(4);
        try (Arena arena = Arena.ofConfined();
                RecordProtection sealer = protection(arena, key, salt)) {
            MemorySegment out = arena.allocate(1 << 15);
            for (long sequence = 0; sequence < 3; sequence++) {
                byte[] plain = bytes(100 + (int) sequence);
                int written = sealer.seal((byte) 23, inNative(arena, plain), 0, plain.length,
                        out, 0);
                byte[] record = out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE);
                assertEquals(23, record[0]);
                assertEquals(0x0303, ((record[1] & 0xff) << 8) | (record[2] & 0xff));
                assertEquals(written - 5, ((record[3] & 0xff) << 8) | (record[4] & 0xff));
                assertEquals(8 + plain.length + 16, written - 5);
                assertArrayEquals(plain, jdkOpen(key, salt, sequence, record));
            }
        }
    }

    @ParameterizedTest(name = "AES-{0}")
    @ValueSource(ints = {128, 256})
    void whatTheJdkSealsThisOpens(int bits) throws Exception {
        byte[] key = bytes(bits / 8);
        byte[] salt = bytes(4);
        try (Arena arena = Arena.ofConfined();
                RecordProtection opener = protection(arena, key, salt)) {
            MemorySegment out = arena.allocate(1 << 15);
            for (long sequence = 0; sequence < 3; sequence++) {
                byte[] plain = bytes(77);
                // A peer may send any explicit nonce; this one is random.
                byte[] record = jdkSeal(key, salt, sequence, bytes(8), (byte) 22, plain);
                RecordProtection.Opened opened = opener.open(inNative(arena, record), 0,
                        record.length, out, 0);
                assertNotNull(opened, "record " + sequence + " did not open");
                assertEquals(22, opened.contentType());
                assertArrayEquals(plain, out.asSlice(0, opened.length()).toArray(ValueLayout.JAVA_BYTE));
            }
            assertEquals(3, opener.sequence());
        }
    }

    @Test
    void aChangedByteOrAWrongSequenceNumberDoesNotOpen() throws Exception {
        byte[] key = bytes(16);
        byte[] salt = bytes(4);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(1 << 15);
            byte[] plain = bytes(40);
            // The type, the explicit nonce, the ciphertext and the tag. The two version
            // and two length bytes of the header are framing: RFC 5246 authenticates
            // the type, a fixed version and the plaintext length, not the header bytes.
            for (int at : new int[] {0, 5, 12, 13, 30, 5 + 8 + 40 + 15}) {
                byte[] record = jdkSeal(key, salt, 0, bytes(8), (byte) 23, plain);
                record[at] ^= 1;
                try (RecordProtection opener = protection(arena, key, salt)) {
                    assertNull(opener.open(inNative(arena, record), 0, record.length, out, 0),
                            "a record with byte " + at + " changed was accepted");
                }
            }
            byte[] second = jdkSeal(key, salt, 1, bytes(8), (byte) 23, plain);
            try (RecordProtection opener = protection(arena, key, salt)) {
                assertNull(opener.open(inNative(arena, second), 0, second.length, out, 0),
                        "record 1 opened as record 0");
            }
        }
    }

    @Test
    void anEmptyApplicationRecordIsARecord() throws Exception {
        byte[] key = bytes(16);
        byte[] salt = bytes(4);
        try (Arena arena = Arena.ofConfined();
                RecordProtection sealer = protection(arena, key, salt)) {
            MemorySegment out = arena.allocate(64);
            int written = sealer.seal((byte) 23, arena.allocate(1), 0, 0, out, 0);
            assertEquals(5 + 8 + 16, written);
            assertEquals(0, jdkOpen(key, salt, 0,
                    out.asSlice(0, written).toArray(ValueLayout.JAVA_BYTE)).length);
        }
    }

    @Test
    void thereIsNoKeyUpdate() {
        try (Arena arena = Arena.ofConfined();
                RecordProtection protection = protection(arena, bytes(16), bytes(4))) {
            assertTrue(protection.isTls12());
            assertThrows(IllegalStateException.class, protection::next);
            assertEquals(20, protection.secretLength());
        }
    }

    private static RecordProtection protection(Arena arena, byte[] key, byte[] salt) {
        MemorySegment block = arena.allocate(key.length + 4);
        MemorySegment.copy(MemorySegment.ofArray(key), 0, block, 0, key.length);
        MemorySegment.copy(MemorySegment.ofArray(salt), 0, block, key.length, 4);
        return RecordProtection.forTls12(HashAlgorithm.SHA_256, block, 0, key.length, key.length);
    }

    private static byte[] jdkSeal(byte[] key, byte[] salt, long sequence, byte[] explicit,
            byte type, byte[] plain) throws Exception {
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce(salt, explicit)));
        gcm.updateAAD(additional(sequence, type, plain.length));
        byte[] sealed = gcm.doFinal(plain);
        int body = 8 + sealed.length;
        ByteBuffer record = ByteBuffer.allocate(5 + body);
        record.put(type).put((byte) 3).put((byte) 3).putShort((short) body);
        record.put(explicit).put(sealed);
        return record.array();
    }

    private static byte[] jdkOpen(byte[] key, byte[] salt, long sequence, byte[] record)
            throws Exception {
        byte[] explicit = java.util.Arrays.copyOfRange(record, 5, 13);
        byte[] sealed = java.util.Arrays.copyOfRange(record, 13, record.length);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce(salt, explicit)));
        gcm.updateAAD(additional(sequence, record[0], sealed.length - 16));
        return gcm.doFinal(sealed);
    }

    private static byte[] nonce(byte[] salt, byte[] explicit) {
        return ByteBuffer.allocate(12).put(salt).put(explicit).array();
    }

    private static byte[] additional(long sequence, byte type, int length) {
        return ByteBuffer.allocate(13).putLong(sequence).put(type).put((byte) 3).put((byte) 3)
                .putShort((short) length).array();
    }

    /** The native AES-GCM takes native memory only, as the record layer always gives it. */
    private static MemorySegment inNative(Arena arena, byte[] data) {
        MemorySegment segment = arena.allocate(Math.max(1, data.length));
        MemorySegment.copy(MemorySegment.ofArray(data), 0, segment, 0, data.length);
        return segment;
    }

    private static byte[] bytes(int n) {
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }
}

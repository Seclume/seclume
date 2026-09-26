package space.seclume.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hkdf;

/**
 * The record construction, checked where two implementations can disagree.
 *
 * <p>The cipher underneath is already anchored outside this project -
 * {@code AesGcmTest} compares it with SunJCE byte for byte. What is new here is
 * the wrapping, and every piece of it is a convention that cannot be derived
 * from first principles: which bytes are the additional data, how the nonce is
 * built, where the content type sits, how padding is recognised.
 *
 * <p>So the important test is not a round trip - that would pass on any
 * self-consistent invention. It is {@link #theSealedRecordIsWhatTheSpecSays()},
 * which rebuilds the record with the JDK's cipher and the construction written
 * out by hand, and compares. If this code and that description disagree, one of
 * them is wrong and the test says so.
 *
 * <p><b>This was the weak point, and it is now closed elsewhere.</b> Every
 * check in this class rebuilds the record from the same reading of the
 * specification the code was written from, so a misreading would agree with
 * itself and pass. {@code Rfc8448VectorsTest} supplies what this class cannot:
 * 27 records out of the published traces of RFC 8448, encrypted by an
 * implementation that never saw this code, all of which {@link
 * RecordProtection#open} opens to exactly the plaintext the RFC prints beside
 * them. The construction is therefore checked against the wire and not only
 * against the specification as read.
 */
class RecordProtectionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The sealed record equals the construction, computed independently.
     *
     * <p>Key and IV come out of the traffic secret the same way both times, but
     * everything after that - the nonce, the additional data, the inner content
     * type - is written out here in the order the specification gives, with the
     * JDK doing the encryption. Agreement means the two readings match.
     */
    @Test
    void theSealedRecordIsWhatTheSpecSays() throws Exception {
        byte[] trafficSecret = random(48);
        byte[] payload = random(100);

        byte[] ours;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection protection =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                MemorySegment out = arena.allocate(RecordProtection.sealedLength(payload.length));
                int written = protection.seal((byte) 22, of(arena, payload), 0, payload.length,
                        out, 0);
                ours = bytes(out, written);
            }
        }

        // The same thing, by hand.
        byte[] key = expandLabel(trafficSecret, "key", 32);
        byte[] iv = expandLabel(trafficSecret, "iv", 12);
        byte[] header = {23, 3, 3, (byte) ((payload.length + 1 + 16) >>> 8),
            (byte) (payload.length + 1 + 16)};
        byte[] inner = new byte[payload.length + 1];
        System.arraycopy(payload, 0, inner, 0, payload.length);
        inner[payload.length] = 22;                       // the content type, inside

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, iv));           // sequence 0, so the nonce is the IV
        cipher.updateAAD(header);
        byte[] body = cipher.doFinal(inner);

        byte[] expected = new byte[header.length + body.length];
        System.arraycopy(header, 0, expected, 0, header.length);
        System.arraycopy(body, 0, expected, header.length, body.length);
        assertArrayEquals(expected, ours);
    }

    /**
     * And at sequence 5 the nonce is the IV with the counter xored in.
     *
     * <p>Separate from the first test on purpose: at sequence zero the nonce
     * and the IV are the same bytes, so an implementation that ignored the
     * counter entirely would pass that one.
     */
    @Test
    void theNonceCarriesTheSequenceNumber() throws Exception {
        byte[] trafficSecret = random(48);
        byte[] payload = random(7);

        byte[] ours;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection protection =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                protection.sequence(5);
                MemorySegment out = arena.allocate(RecordProtection.sealedLength(payload.length));
                int written = protection.seal((byte) 23, of(arena, payload), 0, payload.length,
                        out, 0);
                ours = bytes(out, written);
            }
        }

        byte[] key = expandLabel(trafficSecret, "key", 32);
        byte[] iv = expandLabel(trafficSecret, "iv", 12);
        iv[11] = (byte) (iv[11] ^ 5);
        byte[] header = {23, 3, 3, 0, (byte) (payload.length + 1 + 16)};
        byte[] inner = new byte[payload.length + 1];
        System.arraycopy(payload, 0, inner, 0, payload.length);
        inner[payload.length] = 23;

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, iv));
        cipher.updateAAD(header);
        byte[] body = cipher.doFinal(inner);

        byte[] expected = new byte[5 + body.length];
        System.arraycopy(header, 0, expected, 0, 5);
        System.arraycopy(body, 0, expected, 5, body.length);
        assertArrayEquals(expected, ours);
    }

    /** Sealing and opening across sizes, including nothing at all. */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 15, 16, 17, 1000, 16384})
    void whatIsSealedCanBeOpened(int length) {
        byte[] payload = random(length);
        byte[] trafficSecret = random(48);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection sender =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32);
                 RecordProtection receiver =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                MemorySegment wire = arena.allocate(RecordProtection.sealedLength(length));
                int written = sender.seal((byte) 23, of(arena, payload), 0, length, wire, 0);

                MemorySegment out = arena.allocate(Math.max(length, 1));
                RecordProtection.Opened opened = receiver.open(wire, 0, written, out, 0);
                assertEquals((byte) 23, opened.contentType());
                assertEquals(length, opened.length());
                assertArrayEquals(payload, bytes(out, length));
            }
        }
    }

    /**
     * Opened straight into a buffer with room for the inner type - the way
     * RecordStream opens every record - and again into one without: the same
     * payload, and nothing of the inner type left behind it. Several records
     * in a row, so that the buffers kept by the key are reused.
     */
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 17, 1000, 16384})
    void openedWithOrWithoutRoomForTheInnerType(int length) {
        byte[] trafficSecret = random(32);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection sender =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16);
                 RecordProtection receiver =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_256, secret, 16)) {
                MemorySegment wire = arena.allocate(RecordProtection.sealedLength(length));
                MemorySegment roomy = arena.allocate(length + 64);
                MemorySegment tight = arena.allocate(Math.max(length, 1));
                for (int record = 0; record < 4; record++) {
                    byte[] payload = random(length);
                    byte type = (byte) (record % 2 == 0 ? 23 : 22);
                    int written = sender.seal(type, of(arena, payload), 0, length, wire, 0);
                    boolean direct = record % 2 == 0;
                    MemorySegment out = direct ? roomy : tight;
                    out.fill((byte) 0);
                    RecordProtection.Opened opened = receiver.open(wire, 0, written, out, 0);
                    assertEquals(type, opened.contentType());
                    assertEquals(length, opened.length());
                    assertArrayEquals(payload, bytes(out, length));
                    if (direct) {
                        assertEquals(0, roomy.get(ValueLayout.JAVA_BYTE, length),
                                "the inner type stayed behind the payload");
                    }
                }
            }
        }
    }

    /**
     * Records have to be opened in order, and that is the point.
     *
     * <p>The sequence number is never on the wire; both sides count. A receiver
     * one record out of step cannot open anything - which is exactly what makes
     * it part of the state a moved connection has to carry, and what makes
     * getting it wrong visible at once rather than later.
     */
    @Test
    void aRecordOutOfOrderCannotBeOpened() {
        byte[] trafficSecret = random(48);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection sender =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32);
                 RecordProtection receiver =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                MemorySegment first = arena.allocate(RecordProtection.sealedLength(8));
                MemorySegment second = arena.allocate(RecordProtection.sealedLength(8));
                int a = sender.seal((byte) 23, of(arena, random(8)), 0, 8, first, 0);
                int b = sender.seal((byte) 23, of(arena, random(8)), 0, 8, second, 0);

                MemorySegment out = arena.allocate(8);
                assertNull(receiver.open(second, 0, b, out, 0),
                        "the second record opened at sequence zero");
                assertEquals(0, receiver.sequence(), "a failed open must not count");
                assertTrue(receiver.open(first, 0, a, out, 0) != null);
            }
        }
    }

    /** A key update gives different keys and starts counting again. */
    @Test
    void aKeyUpdateChangesEverything() {
        byte[] trafficSecret = random(48);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, trafficSecret);
            try (RecordProtection first =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                MemorySegment before = arena.allocate(RecordProtection.sealedLength(4));
                first.seal((byte) 23, of(arena, new byte[4]), 0, 4, before, 0);

                try (RecordProtection second = first.next()) {
                    assertEquals(0, second.sequence(), "a key update restarts the count");
                    MemorySegment after = arena.allocate(RecordProtection.sealedLength(4));
                    second.seal((byte) 23, of(arena, new byte[4]), 0, 4, after, 0);
                    assertNotEquals(
                            java.util.HexFormat.of().formatHex(bytes(before, 5 + 4 + 1 + 16)),
                            java.util.HexFormat.of().formatHex(bytes(after, 5 + 4 + 1 + 16)),
                            "the same payload under new keys must not produce the same bytes");
                }
            }
        }
    }

    /** The outer type on the wire is always application_data. */
    @Test
    void theRealTypeIsNotVisibleOnTheWire() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment secret = of(arena, random(48));
            try (RecordProtection protection =
                         RecordProtection.fromSecret(HashAlgorithm.SHA_384, secret, 32)) {
                MemorySegment wire = arena.allocate(RecordProtection.sealedLength(4));
                protection.seal((byte) 22, of(arena, new byte[4]), 0, 4, wire, 0);
                assertEquals(RecordProtection.APPLICATION_DATA,
                        wire.get(ValueLayout.JAVA_BYTE, 0),
                        "a handshake record must not announce itself as one");
            }
        }
    }

    // ---- the small machinery ---------------------------------------------

    private static byte[] expandLabel(byte[] secret, String label, int length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            Hkdf.expandLabel(HashAlgorithm.SHA_384, of(arena, secret), label, null, out, 0,
                    length);
            return bytes(out, length);
        }
    }

    private static MemorySegment of(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        if (bytes.length > 0) {
            MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        }
        return segment;
    }

    private static byte[] bytes(MemorySegment segment, int length) {
        byte[] out = new byte[length];
        MemorySegment.copy(segment, ValueLayout.JAVA_BYTE, 0, out, 0, length);
        return out;
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

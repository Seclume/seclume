package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PSource;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The crypto package at its edges, checked against the JDK's own
 * implementations: DER ECDSA signatures of every length form and at every
 * bound, PBKDF2 past 255 output blocks in the Java code, and RSA encryption of
 * the longest message each padding takes, decrypted by the JDK. Written
 * against the mutants PIT left alive in this package.
 */
class CryptoEdgesTest {

    private static KeyPair rsa;

    @BeforeAll
    static void anRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsa = generator.generateKeyPair();
    }

    // ------------------------------------------------------------ DER ECDSA

    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    private static byte[] integer(byte[] value) {
        return concat(bytes(0x02, value.length), value);
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    private static String refusal(byte[] der, int field) {
        return assertThrows(IllegalArgumentException.class, () -> OpenSslSigningKey.rawEcdsa(der, field)).getMessage();
    }

    @Test
    void aShortFormSequenceMayEndExactlyAtTheEndOfTheInput() {
        byte[] body = concat(integer(bytes(0x01)), integer(bytes(0x7f)));
        byte[] der = concat(bytes(0x30, body.length), body);
        assertArrayEquals(bytes(0, 0, 0, 1, 0, 0, 0, 0x7f), OpenSslSigningKey.rawEcdsa(der, 4),
                "short integers are padded on the left");
        byte[] longer = concat(bytes(0x30, body.length + 1), body);
        assertEquals("a DER sequence length exceeds input bounds", refusal(longer, 4));
        assertEquals("not a DER ECDSA signature", refusal(bytes(0x30), 4), "one byte is not a sequence");
        assertEquals("not a DER ECDSA signature", refusal(bytes(0x31, 0), 4));
        assertEquals("not a DER ECDSA signature", refusal(null, 4));
    }

    @Test
    void aLongFormSequenceTakesOneToFourLengthBytes() {
        byte[] body = concat(integer(filled(66, 0x11)), integer(filled(66, 0x22)));
        assertEquals(136, body.length);
        byte[] one = concat(bytes(0x30, 0x81, body.length), body);
        byte[] raw = OpenSslSigningKey.rawEcdsa(one, 66);
        assertArrayEquals(concat(filled(66, 0x11), filled(66, 0x22)), raw);
        byte[] two = concat(bytes(0x30, 0x82, 0x00, body.length), body);
        assertArrayEquals(raw, OpenSslSigningKey.rawEcdsa(two, 66), "a length of two bytes, the first zero");
        byte[] four = concat(bytes(0x30, 0x84, 0, 0, 0, body.length), body);
        assertArrayEquals(raw, OpenSslSigningKey.rawEcdsa(four, 66));
        assertEquals("an invalid DER sequence length header", refusal(concat(bytes(0x30, 0x80), body), 66));
        assertEquals("an invalid DER sequence length header",
                refusal(concat(bytes(0x30, 0x85, 0, 0, 0, 0, body.length), body), 66));
        assertEquals("an invalid DER sequence length header", refusal(bytes(0x30, 0x82, 0x00), 66),
                "the length bytes themselves cut off");
        assertEquals("a DER sequence length exceeds input bounds",
                refusal(concat(bytes(0x30, 0x81, body.length + 1), body), 66));
        assertEquals("a DER sequence length exceeds input bounds",
                refusal(concat(bytes(0x30, 0x84, 0x80, 0, 0, 0), body), 66), "a negative length");
        assertEquals("a DER sequence length exceeds input bounds",
                refusal(concat(bytes(0x30, 0x82, 0x01, body.length), body), 66),
                "the high length byte counts: 256 + 136");
    }

    @Test
    void anIntegerMayEndExactlyAtTheEndOfTheInputAndNotBeyond() {
        byte[] r = integer(bytes(0x05));
        byte[] fullS = integer(bytes(0x06, 0x07));
        byte[] der = concat(bytes(0x30, r.length + fullS.length), r, fullS);
        assertArrayEquals(bytes(0, 5, 6, 7), OpenSslSigningKey.rawEcdsa(der, 2));
        byte[] cut = Arrays.copyOf(der, der.length - 1);
        cut[1] = (byte) (cut.length - 2);
        assertEquals("a DER integer value exceeds input bounds", refusal(cut, 2));
        byte[] tagOnly = concat(bytes(0x30, r.length + 1), r, bytes(0x02));
        assertEquals("a DER integer length field is truncated", refusal(tagOnly, 2));
        byte[] noSecond = concat(bytes(0x30, r.length), r);
        assertEquals("not a DER ECDSA signature", refusal(noSecond, 2), "only one integer");
        byte[] notInteger = concat(bytes(0x30, r.length + 3), r, bytes(0x04, 1, 0));
        assertEquals("not a DER ECDSA signature", refusal(notInteger, 2));
    }

    @Test
    void leadingZerosAreDroppedOnlyDownToTheFieldSize() {
        // A positive integer with its top bit set gets a zero in DER: 33 bytes for a 32-byte field.
        byte[] high = concat(bytes(0x00), filled(32, 0xff));
        byte[] der = concat(bytes(0x30, 2 * (high.length + 2)), integer(high), integer(high));
        assertArrayEquals(filled(64, 0xff), OpenSslSigningKey.rawEcdsa(der, 32));
        byte[] two = concat(bytes(0x00, 0x00), filled(31, 0xab));
        byte[] der2 = concat(bytes(0x30, 2 * (two.length + 2)), integer(two), integer(two));
        assertArrayEquals(concat(bytes(0), filled(31, 0xab), bytes(0), filled(31, 0xab)),
                OpenSslSigningKey.rawEcdsa(der2, 32), "33 bytes, two zeros: one dropped, one kept");
        byte[] exact = filled(32, 0x01);
        byte[] derExact = concat(bytes(0x30, 2 * 34), integer(exact), integer(exact));
        assertArrayEquals(filled(64, 0x01), OpenSslSigningKey.rawEcdsa(derExact, 32), "exactly the field: as it is");
        byte[] tooLong = concat(bytes(0x01), filled(32, 0));
        byte[] derLong = concat(bytes(0x30, 2 * 35), integer(tooLong), integer(tooLong));
        assertEquals("an ECDSA integer longer than the field", refusal(derLong, 32));
    }

    // ------------------------------------------------------------ PBKDF2

    @Test
    void theJavaPbkdf2CountsBlocksPast255AsTheJdkDoes() throws Exception {
        int length = 257 * 32 + 5;                     // 258 blocks of SHA-256, the last one cut
        byte[] expected = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec("pw".toCharArray(), "salt".getBytes(StandardCharsets.US_ASCII), 1,
                        length * 8))
                .getEncoded();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            Pbkdf2.deriveInJava(HashAlgorithm.SHA_256, arena.allocateFrom("pw", StandardCharsets.US_ASCII)
                            .asSlice(0, 2),
                    arena.allocateFrom("salt", StandardCharsets.US_ASCII).asSlice(0, 4), 1, out);
            assertArrayEquals(expected, out.toArray(ValueLayout.JAVA_BYTE),
                    "block 256 has a counter of 00 00 01 00, block 257 of 00 00 01 01");
            MemorySegment again = arena.allocate(length);
            Pbkdf2.derive(HashAlgorithm.SHA_256, arena.allocateFrom("pw", StandardCharsets.US_ASCII).asSlice(0, 2),
                    arena.allocateFrom("salt", StandardCharsets.US_ASCII).asSlice(0, 4), 1, again);
            assertArrayEquals(expected, again.toArray(ValueLayout.JAVA_BYTE), "and the library the same");
        }
    }

    @Test
    void pbkdf2TakesAtLeastOneIterationAndAnEmptyOutputIsNothing() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment password = arena.allocate(4);
            for (int wrong : new int[] {0, -1}) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> Pbkdf2.derive(HashAlgorithm.SHA_256, password, password, wrong, arena.allocate(8)));
                assertEquals("iterations must be at least 1", e.getMessage());
            }
            Pbkdf2.derive(HashAlgorithm.SHA_256, password, password, 1, arena.allocate(0));
        }
    }

    // ------------------------------------------------------------ RSA

    private static RsaPublicKey ours(Arena arena) {
        RSAPublicKey key = (RSAPublicKey) rsa.getPublic();
        byte[] modulus = key.getModulus().toByteArray();
        byte[] exponent = key.getPublicExponent().toByteArray();
        return RsaPublicKey.of(arena.allocateFrom(ValueLayout.JAVA_BYTE, modulus),
                arena.allocateFrom(ValueLayout.JAVA_BYTE, exponent));
    }

    private static MemorySegment message(Arena arena, int length) {
        MemorySegment message = arena.allocate(Math.max(1, length));
        for (int i = 0; i < length; i++) {
            message.set(ValueLayout.JAVA_BYTE, i, (byte) (i * 7 + 1));
        }
        return message;
    }

    private static byte[] plain(MemorySegment message, int length) {
        return message.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE);
    }

    @Test
    void pkcs1TakesUpToElevenBytesLessThanTheModulus() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            RsaPublicKey key = ours(arena);
            int k = key.modulusBytes();
            assertEquals(256, k);
            Cipher jdk = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            jdk.init(Cipher.DECRYPT_MODE, rsa.getPrivate());
            for (int length : new int[] {0, 1, k - 11}) {
                MemorySegment message = message(arena, length);
                MemorySegment out = arena.allocate(k);
                assertEquals(k, Rsa.encryptPkcs1(key, message, 0, length, out, 0));
                assertArrayEquals(plain(message, length), jdk.doFinal(out.toArray(ValueLayout.JAVA_BYTE)),
                        length + " bytes");
            }
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> Rsa.encryptPkcs1(key, message(arena, k - 10), 0, k - 10, arena.allocate(k), 0));
            assertEquals("message of 246 bytes is too long for a 2048 bit key", e.getMessage());
        }
    }

    private static Cipher oaep(HashAlgorithm hash) throws Exception {
        String name = hash == HashAlgorithm.SHA_1 ? "SHA-1" : "SHA-256";
        MGF1ParameterSpec mgf = hash == HashAlgorithm.SHA_1 ? MGF1ParameterSpec.SHA1 : MGF1ParameterSpec.SHA256;
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, rsa.getPrivate(),
                new OAEPParameterSpec(name, "MGF1", mgf, PSource.PSpecified.DEFAULT));
        return cipher;
    }

    @Test
    void oaepTakesUpToTwoHashesAndTwoBytesLessThanTheModulus() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            RsaPublicKey key = ours(arena);
            int k = key.modulusBytes();
            for (HashAlgorithm hash : new HashAlgorithm[] {HashAlgorithm.SHA_1, HashAlgorithm.SHA_256}) {
                int most = k - 2 * hash.digestLength() - 2;
                Cipher jdk = oaep(hash);
                for (int length : new int[] {0, 1, 32, most}) {
                    MemorySegment message = message(arena, length);
                    MemorySegment out = arena.allocate(k);
                    assertEquals(k, Rsa.encryptOaep(key, hash, message, 0, length, out, 0));
                    assertArrayEquals(plain(message, length), jdk.doFinal(out.toArray(ValueLayout.JAVA_BYTE)),
                            hash + ", " + length + " bytes");
                }
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> Rsa.encryptOaep(key, hash, message(arena, most + 1), 0, most + 1, arena.allocate(k), 0));
                assertEquals("message of " + (most + 1) + " bytes is too long for OAEP with " + hash
                        + " and a 2048 bit key", e.getMessage());
            }
        }
    }

    @Test
    void theSameMessageEncryptsDifferentlyEachTime() {
        try (Arena arena = Arena.ofConfined()) {
            RsaPublicKey key = ours(arena);
            MemorySegment message = message(arena, 20);
            MemorySegment a = arena.allocate(256);
            MemorySegment b = arena.allocate(256);
            Rsa.encryptOaep(key, HashAlgorithm.SHA_256, message, 0, 20, a, 0);
            Rsa.encryptOaep(key, HashAlgorithm.SHA_256, message, 0, 20, b, 0);
            assertFalse(Arrays.equals(a.toArray(ValueLayout.JAVA_BYTE), b.toArray(ValueLayout.JAVA_BYTE)),
                    "a random seed for every encryption");
            Rsa.encryptPkcs1(key, message, 0, 20, a, 0);
            Rsa.encryptPkcs1(key, message, 0, 20, b, 0);
            assertFalse(Arrays.equals(a.toArray(ValueLayout.JAVA_BYTE), b.toArray(ValueLayout.JAVA_BYTE)));
            BigInteger n = ((RSAPublicKey) rsa.getPublic()).getModulus();
            assertEquals(-1, new BigInteger(1, a.toArray(ValueLayout.JAVA_BYTE)).compareTo(n), "below the modulus");
        }
    }

    @Test
    void anOffsetMessageAndAnOffsetTarget() throws Exception {
        try (Arena arena = Arena.ofConfined()) {
            RsaPublicKey key = ours(arena);
            MemorySegment message = message(arena, 40);
            MemorySegment out = arena.allocate(256 + 9);
            assertEquals(256, Rsa.encryptOaep(key, HashAlgorithm.SHA_1, message, 8, 16, out, 9));
            assertArrayEquals(message.asSlice(8, 16).toArray(ValueLayout.JAVA_BYTE),
                    oaep(HashAlgorithm.SHA_1).doFinal(out.asSlice(9, 256).toArray(ValueLayout.JAVA_BYTE)));
        }
    }
}

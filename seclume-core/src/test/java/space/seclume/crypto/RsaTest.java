package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.spec.MGF1ParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import space.seclume.Segments;

/**
 * RSA cannot be checked with fixed vectors - the padding is random. The proof
 * therefore runs the other way round: we encrypt, the JCA decrypts with the
 * private key, and the plaintext has to come back out. On top of that the
 * big-number arithmetic is held against {@link BigInteger} - allowed in a test,
 * not in production code.
 */
class RsaTest {

    private static KeyPair keyPair2048;
    private static KeyPair keyPair1024;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair2048 = generator.generateKeyPair();
        generator.initialize(1024);
        keyPair1024 = generator.generateKeyPair();
    }

    @Test
    void modPowMatchesBigInteger() {
        Random random = new Random(20260905L);
        for (int bytes : new int[] {8, 32, 64, 128}) {
            byte[] modulusBytes = new byte[bytes];
            byte[] baseBytes = new byte[bytes];
            random.nextBytes(modulusBytes);
            random.nextBytes(baseBytes);
            modulusBytes[0] |= (byte) 0x80;          // volle Laenge
            modulusBytes[bytes - 1] |= 1;            // odd, like an RSA modulus

            BigInteger modulus = new BigInteger(1, modulusBytes);
            BigInteger base = new BigInteger(1, baseBytes);
            BigInteger exponent = BigInteger.valueOf(65537);
            byte[] expected = toFixed(base.modPow(exponent, modulus), bytes);

            try (Arena arena = Arena.ofConfined()) {
                int words = BigWords.wordCount(bytes);
                MemorySegment modulusWords = arena.allocate(words * 4L);
                MemorySegment baseWords = arena.allocate(words * 4L);
                MemorySegment result = arena.allocate(words * 4L);
                MemorySegment out = arena.allocate(bytes);
                BigWords.fromBytes(Segments.bytes(arena, modulusBytes), 0, bytes, modulusWords, words);
                BigWords.fromBytes(Segments.bytes(arena, baseBytes), 0, bytes, baseWords, words);
                MemorySegment exponentBytes = Segments.hex(arena, "010001");
                BigWords.modPow(baseWords, exponentBytes, 0, 3, modulusWords, words, result, arena);
                BigWords.toBytes(result, words, out, 0, bytes);
                assertArrayEquals(expected, Segments.toBytes(out), "modPow with " + bytes + " bytes");
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1024, 2048})
    void pkcs1RoundTripThroughJca(int keySize) throws Exception {
        KeyPair pair = keySize == 2048 ? keyPair2048 : keyPair1024;
        byte[] message = "s3cr3t-p@ssw0rd\0".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext;
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = publicKey(arena, (RSAPublicKey) pair.getPublic())) {
            MemorySegment plain = Segments.bytes(arena, message);
            MemorySegment out = arena.allocate(key.modulusBytes());
            int written = Rsa.encryptPkcs1(key, plain, 0, message.length, out, 0);
            assertEquals(keySize / 8, written);
            ciphertext = Segments.toBytes(out);
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        assertArrayEquals(message, cipher.doFinal(ciphertext));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA_1", "SHA_256"})
    void oaepRoundTripThroughJca(String hashName) throws Exception {
        HashAlgorithm hash = HashAlgorithm.valueOf(hashName);
        byte[] message = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext;
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = publicKey(arena, (RSAPublicKey) keyPair2048.getPublic())) {
            MemorySegment plain = Segments.bytes(arena, message);
            MemorySegment out = arena.allocate(key.modulusBytes());
            Rsa.encryptOaep(key, hash, plain, 0, message.length, out, 0);
            ciphertext = Segments.toBytes(out);
        }

        String jcaHash = hash == HashAlgorithm.SHA_1 ? "SHA-1" : "SHA-256";
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair2048.getPrivate(),
                new OAEPParameterSpec(jcaHash, "MGF1",
                        hash == HashAlgorithm.SHA_1 ? MGF1ParameterSpec.SHA1 : MGF1ParameterSpec.SHA256,
                        PSource.PSpecified.DEFAULT));
        assertArrayEquals(message, cipher.doFinal(ciphertext));
    }

    /** The route MySQL takes: the key as a DER SubjectPublicKeyInfo. */
    @Test
    void parsesSubjectPublicKeyInfo() throws Exception {
        RSAPublicKey reference = (RSAPublicKey) keyPair2048.getPublic();
        byte[] der = reference.getEncoded();

        byte[] ciphertext;
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = RsaPublicKey.fromSubjectPublicKeyInfo(Segments.bytes(arena, der))) {
            assertEquals(256, key.modulusBytes());
            MemorySegment plain = Segments.ascii(arena, "hello");
            MemorySegment out = arena.allocate(key.modulusBytes());
            Rsa.encryptPkcs1(key, plain, 0, 5, out, 0);
            ciphertext = Segments.toBytes(out);
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair2048.getPrivate());
        assertArrayEquals("hello".getBytes(StandardCharsets.US_ASCII), cipher.doFinal(ciphertext));
    }

    @Test
    void rejectsOversizedMessage() {
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = publicKey(arena, (RSAPublicKey) keyPair1024.getPublic())) {
            MemorySegment plain = arena.allocate(200);
            MemorySegment out = arena.allocate(key.modulusBytes());
            assertThrows(IllegalArgumentException.class,
                    () -> Rsa.encryptPkcs1(key, plain, 0, 200, out, 0));
        }
    }

    /** Two runs with the same message must never look alike. */
    @Test
    void paddingIsRandom() {
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = publicKey(arena, (RSAPublicKey) keyPair1024.getPublic())) {
            MemorySegment plain = Segments.ascii(arena, "same message");
            MemorySegment first = arena.allocate(key.modulusBytes());
            MemorySegment second = arena.allocate(key.modulusBytes());
            Rsa.encryptPkcs1(key, plain, 0, 12, first, 0);
            Rsa.encryptPkcs1(key, plain, 0, 12, second, 0);
            org.junit.jupiter.api.Assertions.assertNotEquals(
                    Segments.toHex(first), Segments.toHex(second));
        }
    }

    /**
     * Leading zero bytes - the one DER puts in front of a modulus whose top
     * bit is set, and any more - are not part of the key; one byte always
     * stays, even of a number that is all zeros.
     */
    @Test
    void leadingZeroBytesAreNotPartOfTheKey() {
        RSAPublicKey jca = (RSAPublicKey) keyPair2048.getPublic();
        byte[] modulus = jca.getModulus().toByteArray();          // 257 bytes: 0x00 first
        assertEquals(257, modulus.length);
        byte[] padded = new byte[modulus.length + 2];
        System.arraycopy(modulus, 0, padded, 2, modulus.length);
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = RsaPublicKey.of(Segments.bytes(arena, padded),
                     Segments.bytes(arena, new byte[] {0, 0, 0, 1, 0, 1}))) {
            assertEquals(256, key.modulusBytes());
            assertEquals(3, key.exponentLength());
            assertArrayEquals(new byte[] {1, 0, 1},
                    key.exponentBytes().toArray(java.lang.foreign.ValueLayout.JAVA_BYTE));
            assertEquals("RsaPublicKey[bits=2048]", key.toString());
        }
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey zeros = RsaPublicKey.of(Segments.bytes(arena, new byte[] {0, 0}),
                     Segments.bytes(arena, new byte[] {0, 0}))) {
            assertEquals(1, zeros.modulusBytes());
            assertEquals(1, zeros.exponentLength());
        }
    }

    /** A closed key is refused, its memory is gone, and closing twice is harmless. */
    @Test
    void aClosedKeyIsRefusedAndItsMemoryGone() {
        try (Arena arena = Arena.ofConfined()) {
            RsaPublicKey key = publicKey(arena, (RSAPublicKey) keyPair1024.getPublic());
            MemorySegment words = key.modulusWords();
            MemorySegment exponent = key.exponentBytes();
            key.close();
            key.close();
            assertThrows(IllegalStateException.class, key::modulusBytes);
            assertThrows(IllegalStateException.class, key::modulusWords);
            assertThrows(IllegalStateException.class, key::exponentBytes);
            assertThrows(IllegalStateException.class,
                    () -> words.get(java.lang.foreign.ValueLayout.JAVA_BYTE, 0));
            assertThrows(IllegalStateException.class,
                    () -> exponent.get(java.lang.foreign.ValueLayout.JAVA_BYTE, 0));
        }
    }

    private static RsaPublicKey publicKey(Arena arena, RSAPublicKey key) {
        return RsaPublicKey.of(
                Segments.bytes(arena, key.getModulus().toByteArray()),
                Segments.bytes(arena, key.getPublicExponent().toByteArray()));
    }

    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }
}

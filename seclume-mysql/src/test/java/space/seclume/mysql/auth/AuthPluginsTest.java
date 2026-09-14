package space.seclume.mysql.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.spec.MGF1ParameterSpec;

import org.junit.jupiter.api.Test;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.RsaPublicKey;

/**
 * The MySQL login methods, recomputed.
 *
 * <p>There are no official test vectors for these methods the way there are for
 * the hashes - they only exist in the server's source. The proof therefore runs
 * through an <b>independent recomputation with the JCA</b>: the same formula, a
 * different implementation, a different memory management. If either of the two
 * deviates, it shows up here.
 *
 * <p>The passwords in these tests are throwaway values and stand in the code in
 * the clear on purpose - a test that does not know its own input can prove
 * nothing.
 */
class AuthPluginsTest {

    private static final byte[] SCRAMBLE = new byte[20];

    static {
        new Random(4711).nextBytes(SCRAMBLE);
    }

    /** {@code SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw)))}, computed with the JCA. */
    private static byte[] nativeWithJca(String password) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] stage1 = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
        byte[] stage2 = sha1.digest(stage1);
        sha1.reset();
        sha1.update(SCRAMBLE);
        sha1.update(stage2);
        byte[] mask = sha1.digest();
        byte[] result = new byte[20];
        for (int i = 0; i < 20; i++) {
            result[i] = (byte) (stage1[i] ^ mask[i]);
        }
        return result;
    }

    /** {@code SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) || scramble)}. */
    private static byte[] cachingSha2WithJca(String password) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] stage1 = sha256.digest(password.getBytes(StandardCharsets.UTF_8));
        byte[] stage2 = sha256.digest(stage1);
        sha256.reset();
        sha256.update(stage2);
        sha256.update(SCRAMBLE);
        byte[] mask = sha256.digest();
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++) {
            result[i] = (byte) (stage1[i] ^ mask[i]);
        }
        return result;
    }

    @Test
    void nativePasswordMatchesAnIndependentComputation() throws Exception {
        for (String password : new String[] {"secret", "a", "mit Umlaut äöü",
                "ein ziemlich langes Passwort mit Sonderzeichen !\"§$%&/()=?"}) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(20);
                int written = NativePassword.response(utf8(arena, password), 0,
                        utf8Length(password), scramble(arena), 0, out, 0);
                assertEquals(20, written, password);
                assertArrayEquals(nativeWithJca(password), bytes(out, 20), password);
            }
        }
    }

    /** An empty password gives an empty answer - the protocol requires it so. */
    @Test
    void anEmptyPasswordProducesAnEmptyResponse() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(32);
            assertEquals(0, NativePassword.response(arena.allocate(1), 0, 0,
                    scramble(arena), 0, out, 0));
            assertEquals(0, CachingSha2Password.response(arena.allocate(1), 0, 0,
                    scramble(arena), 0, out, 0));
        }
    }

    @Test
    void cachingSha2MatchesAnIndependentComputation() throws Exception {
        for (String password : new String[] {"secret", "x", "mit Umlaut äöü", "🔐 emoji"}) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(32);
                int written = CachingSha2Password.response(utf8(arena, password), 0,
                        utf8Length(password), scramble(arena), 0, out, 0);
                assertEquals(32, written, password);
                assertArrayEquals(cachingSha2WithJca(password), bytes(out, 32), password);
            }
        }
    }

    /**
     * The full path: encrypt, then decrypt again with the private key and undo
     * the XOR. If the password comes out, padding, masking and exponentiation
     * agree with one another.
     */
    @Test
    void theEncryptedPasswordCanBeDecryptedByTheServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String password = "mein Passwort äöü";

        byte[] cipherText;
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = RsaPublicKey.fromSubjectPublicKeyInfo(
                     MemorySegment.ofArray(pair.getPublic().getEncoded()))) {
            MemorySegment out = arena.allocate(key.modulusBytes());
            int written = CachingSha2Password.encryptedPassword(key, HashAlgorithm.SHA_1,
                    utf8(arena, password), 0, utf8Length(password), scramble(arena), 0, out, 0);
            assertEquals(key.modulusBytes(), written);
            cipherText = bytes(out, written);
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.DECRYPT_MODE, (RSAPrivateKey) pair.getPrivate(),
                new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1,
                        PSource.PSpecified.DEFAULT));
        byte[] masked = cipher.doFinal(cipherText);

        byte[] expected = password.getBytes(StandardCharsets.UTF_8);
        assertEquals(expected.length + 1, masked.length, "the terminating zero is missing");
        for (int i = 0; i < masked.length; i++) {
            masked[i] ^= SCRAMBLE[i % 20];
        }
        assertEquals((byte) 0, masked[masked.length - 1]);
        byte[] recovered = new byte[expected.length];
        System.arraycopy(masked, 0, recovered, 0, expected.length);
        assertArrayEquals(expected, recovered);
    }

    /** The same password twice gives two different ciphertexts - OAEP rolls dice. */
    @Test
    void encryptionIsNotDeterministic() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        try (Arena arena = Arena.ofConfined();
             RsaPublicKey key = RsaPublicKey.fromSubjectPublicKeyInfo(
                     MemorySegment.ofArray(pair.getPublic().getEncoded()))) {
            MemorySegment first = arena.allocate(key.modulusBytes());
            MemorySegment second = arena.allocate(key.modulusBytes());
            CachingSha2Password.encryptedPassword(key, HashAlgorithm.SHA_1,
                    utf8(arena, "gleich"), 0, 6, scramble(arena), 0, first, 0);
            CachingSha2Password.encryptedPassword(key, HashAlgorithm.SHA_1,
                    utf8(arena, "gleich"), 0, 6, scramble(arena), 0, second, 0);
            assertNotEquals(java.util.Arrays.toString(bytes(first, key.modulusBytes())),
                    java.util.Arrays.toString(bytes(second, key.modulusBytes())));
        }
    }

    @Test
    void readsThePemKeyTheServerSends() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'})
                        .encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment text = utf8(arena, pem);
            try (RsaPublicKey key = ServerPublicKey.parsePem(text, 0, utf8Length(pem))) {
                assertEquals(256, key.modulusBytes());
            }
        }
    }

    /** What is not PEM is refused - not read as a random key. */
    @Test
    void rejectsSomethingThatIsNotAPemKey() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment junk = utf8(arena, "no key here, sorry\n");
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> ServerPublicKey.parsePem(junk, 0, 19));
            assertTrue(failure.getMessage().contains("PEM"));
        }
    }

    // ---- helpers ---------------------------------------------------------

    private static MemorySegment utf8(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemorySegment segment = arena.allocate(bytes.length + 1);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
        return segment;
    }

    private static int utf8Length(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static MemorySegment scramble(Arena arena) {
        MemorySegment segment = arena.allocate(20);
        MemorySegment.copy(MemorySegment.ofArray(SCRAMBLE), 0, segment, 0, 20);
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

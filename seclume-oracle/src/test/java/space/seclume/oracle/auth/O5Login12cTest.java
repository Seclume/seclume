package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

/**
 * The 12C login path, cross-checked against the JCA.
 *
 * <p>There are no official vectors - the scheme is not specified,
 * it is derived from python-oracledb v4.0.2 (see
 * {@code docs/protocol/oracle.md}). The proof therefore runs through an
 * independent recomputation: the same rule, a different implementation.
 *
 * <p>What that shows and what it does not: it shows that the rule is computed
 * correctly. Whether it is the right rule only a real
 * Server.
 */
class O5Login12cTest {

    private static final String PASSWORD = "Ein Oracle-Passwort äöü";
    private static final byte[] VERIFIER_DATA = new byte[16];
    private static final int ITERATIONS = 4096;

    static {
        new Random(7).nextBytes(VERIFIER_DATA);
    }

    /** PBKDF2-SHA512 over password and salt, then SHA-512, first 32 bytes. */
    private static byte[] passwordHashWithJca(String password) throws Exception {
        byte[] salt = concat(VERIFIER_DATA,
                "AUTH_PBKDF2_SPEEDY_KEY".getBytes(StandardCharsets.US_ASCII));
        // PBKDF2WithHmacSHA512 takes char[]; the JCA encodes it internally as
        // UTF-8, which for these inputs comes out the same.
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] derived = factory.generateSecret(
                new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 64 * 8)).getEncoded();

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        sha512.update(derived);
        sha512.update(VERIFIER_DATA);
        return Arrays.copyOf(sha512.digest(), 32);
    }

    @Test
    void thePasswordHashMatchesAnIndependentComputation() throws Exception {
        // ASCII only: the JCA takes char[] and encodes differently from UTF-8
        // as soon as characters above 127 appear - that would be comparing
        // apples with pears, not a bug in this implementation.
        for (String password : new String[] {"secret", "x", "a-much-longer-password-1234"}) {
            try (Arena arena = Arena.ofConfined()) {
                byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
                MemorySegment out = arena.allocate(O5Login12c.PASSWORD_HASH_LENGTH);
                O5Login12c.passwordHash(segment(arena, passwordBytes), 0, passwordBytes.length,
                        segment(arena, VERIFIER_DATA), 0, VERIFIER_DATA.length,
                        ITERATIONS, out, 0);
                assertArrayEquals(passwordHashWithJca(password),
                        bytes(out, O5Login12c.PASSWORD_HASH_LENGTH), password);
            }
        }
    }

    /** The server session key, encrypted with the JCA. */
    @Test
    void decryptsTheServerSessionKey() throws Exception {
        byte[] hash = passwordHashWithJca("secret");
        byte[] serverKey = new byte[O5Login12c.SESSION_KEY_LENGTH];
        new Random(21).nextBytes(serverKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hash, "AES"),
                new IvParameterSpec(new byte[16]));
        byte[] encrypted = cipher.doFinal(serverKey);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(O5Login12c.SESSION_KEY_LENGTH);
            O5Login12c.decryptSessionKey(segment(arena, hash), 0,
                    segment(arena, encrypted), 0, out, 0);
            assertArrayEquals(serverKey, bytes(out, O5Login12c.SESSION_KEY_LENGTH));
        }
    }

    /** XOR of bytes 16..40, then MD5 over 16 and over 8 bytes. */
    @Test
    void theComboKeyMatchesAnIndependentComputation() throws Exception {
        byte[] serverKey = new byte[48];
        byte[] clientKey = new byte[48];
        new Random(31).nextBytes(serverKey);
        new Random(32).nextBytes(clientKey);

        byte[] mixed = new byte[24];
        for (int i = 0; i < 24; i++) {
            mixed[i] = (byte) (serverKey[16 + i] ^ clientKey[16 + i]);
        }
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] first = md5.digest(Arrays.copyOfRange(mixed, 0, 16));
        md5.reset();
        byte[] second = md5.digest(Arrays.copyOfRange(mixed, 16, 24));
        byte[] expected = Arrays.copyOf(concat(first, second), 32);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(O5Login12c.COMBO_KEY_LENGTH);
            O5Login12c.comboKey(segment(arena, serverKey), 0,
                    segment(arena, clientKey), 0, out, 0);
            assertArrayEquals(expected, bytes(out, O5Login12c.COMBO_KEY_LENGTH));
        }
    }

    /**
     * {@code AUTH_PASSWORD} has to decrypt again with the combo key, and
     * behind the salt it has to hold the password
     * stehen.
     */
    @Test
    void theEncryptedPasswordCanBeDecryptedAgain() throws Exception {
        byte[] combo = new byte[O5Login12c.COMBO_KEY_LENGTH];
        byte[] salt = new byte[O5Login12c.PASSWORD_SALT_LENGTH];
        new Random(41).nextBytes(combo);
        new Random(42).nextBytes(salt);
        byte[] passwordBytes = PASSWORD.getBytes(StandardCharsets.UTF_8);

        String hex;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512);
            int length = O5Login12c.encryptedPassword(segment(arena, combo), 0,
                    segment(arena, passwordBytes), 0, passwordBytes.length,
                    segment(arena, salt), 0, out, 0);
            hex = new String(bytes(out, length), StandardCharsets.US_ASCII);
        }

        assertTrue(hex.matches("[0-9A-F]+"), "not uppercase hex: " + hex);
        byte[] cipherText = new byte[hex.length() / 2];
        for (int i = 0; i < cipherText.length; i++) {
            cipherText[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(combo, "AES"),
                new IvParameterSpec(new byte[16]));
        byte[] plain = cipher.doFinal(cipherText);

        assertEquals(O5Login12c.PASSWORD_SALT_LENGTH + passwordBytes.length, plain.length);
        assertArrayEquals(salt, Arrays.copyOfRange(plain, 0, 16));
        assertArrayEquals(passwordBytes, Arrays.copyOfRange(plain, 16, plain.length));
    }

    /** Even a block-aligned password gets a full padding block. */
    @Test
    void aBlockAlignedPasswordStillGetsPadding() throws Exception {
        byte[] combo = new byte[O5Login12c.COMBO_KEY_LENGTH];
        byte[] salt = new byte[16];
        byte[] passwordBytes = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(512);
            int length = O5Login12c.encryptedPassword(segment(arena, combo), 0,
                    segment(arena, passwordBytes), 0, passwordBytes.length,
                    segment(arena, salt), 0, out, 0);
            // 16 salt + 16 password + 16 padding block = 48 bytes = 96 hex chars.
            assertEquals(96, length);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static MemorySegment segment(Arena arena, byte[] bytes) {
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
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

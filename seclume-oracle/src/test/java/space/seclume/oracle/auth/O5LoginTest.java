package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

/**
 * The Oracle key derivation, cross-checked against the JCA.
 *
 * <p>There are no official test vectors for O5LOGON - the scheme is not
 * specified, only publicly analysed. The proof therefore runs through an
 * independent recomputation: the same rule, a different implementation, a
 * different memory management.
 *
 * <p>What is <b>not</b> checked here is whether the rule is right. Only a real
 * server can say that. What is checked: if it is right, this code computes it
 * correctly - and off-heap at that.
 */
class O5LoginTest {

    private static final String PASSWORD = "Ein Oracle-Passwort äöü";
    private static final byte[] SALT = new byte[10];

    static {
        new Random(1234).nextBytes(SALT);
    }

    /** {@code SHA1(password || salt)}, padded to 24 bytes with zeroes. */
    private static byte[] keyWithJca(String password) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(password.getBytes(StandardCharsets.UTF_8));
        sha1.update(SALT);
        return Arrays.copyOf(sha1.digest(), 24);
    }

    @Test
    void derivesTheSameKeyAsAnIndependentComputation() throws Exception {
        for (String password : new String[] {PASSWORD, "x", "", "🔐 emoji"}) {
            try (Arena arena = Arena.ofConfined()) {
                byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
                MemorySegment out = arena.allocate(O5Login.KEY_LENGTH);
                O5Login.deriveKey(segment(arena, passwordBytes), 0, passwordBytes.length,
                        segment(arena, SALT), 0, SALT.length, out, 0);
                assertArrayEquals(keyWithJca(password), bytes(out, O5Login.KEY_LENGTH), password);
            }
        }
    }

    /**
     * A session key encrypted with the JCA has to decrypt here - AES-192-CBC
     * with a zero IV, the way the protocol
     * verlangt.
     */
    @Test
    void decryptsWhatTheJcaEncrypted() throws Exception {
        byte[] key = keyWithJca(PASSWORD);
        byte[] serverKey = new byte[48];
        new Random(99).nextBytes(serverKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
        byte[] encrypted = cipher.doFinal(serverKey);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(encrypted.length);
            O5Login.decryptSessionKey(segment(arena, key), 0,
                    segment(arena, encrypted), 0, encrypted.length, out, 0);
            assertArrayEquals(serverKey, bytes(out, serverKey.length));
        }
    }

    /** A length that is not a multiple of the block size is refused. */
    @Test
    void refusesAMalformedSessionKey() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(O5Login.KEY_LENGTH);
            MemorySegment session = arena.allocate(40);
            MemorySegment out = arena.allocate(40);
            assertThrows(IllegalArgumentException.class,
                    () -> O5Login.decryptSessionKey(key, 0, session, 0, 40, out, 0));
        }
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

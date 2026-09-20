package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * A known-answer test for the 12c key derivation.
 *
 * <p>The whole chain is pinned down offline: a single wrong byte anywhere - in
 * PBKDF2, in the AES steps, in the combo key - produces a completely different
 * {@code AUTH_PASSWORD}, and this test says so without needing a server.
 *
 * <h2>And the password is right here on purpose</h2>
 *
 * <p>{@link #PASSWORD} belongs to a throwaway database user that exists for
 * this vector and can do nothing but log in. Publishing it is the point: with
 * the session keys, the salt and the encrypted {@code AUTH_PASSWORD} in one
 * file, anyone could try candidate passwords offline and see which one
 * decrypts. That is an attack when the password is secret - and nothing at all
 * when it is printed three lines further down.
 *
 * <p>The derivation itself comes from {@code python-oracledb}, Oracle's own
 * thin driver, which Oracle publishes under UPL-1.0 or Apache-2.0. See
 * {@code PROVENANCE.md}.
 */
class LoginVectorTest {

    // ---- the server's half of the exchange ---------------------------------

    private static final String SERVER_SESSION_KEY =
            "E4A56A1179C9C7FE97E26E0D6C0A3AD5F627E7E05B150BB128B3A6D8B0585654";
    private static final String VERIFIER_DATA = "46C889300FBB3799CB5357B5FE3965BE";
    private static final String COMBO_SALT = "291A7929F0C8E180B9FFD9A266C5C4CA";
    private static final int GENERATION_COUNT = 4096;
    private static final int DERIVATION_COUNT = 3;

    // ---- chosen: random in a real login, fixed here so it reproduces -------
    //
    // The two strings are exactly 32 and 16 bytes because that is what the
    // protocol wants there. Nothing else about them matters, and they carry
    // no name on purpose: a vector that has to be rebuilt whenever the
    // project is renamed is a vector waiting to break.

    /** The throwaway account this vector belongs to. */
    private static final String USER = "sl_vector";
    /** Published on purpose - see the class comment. */
    private static final String PASSWORD = "seclumeVector1";
    /** Stands in for the 32 random bytes a login generates. */
    private static final String CLIENT_HALF = "a fixed client half, 32 bytes!!!";
    /** Stands in for the 16 random bytes in front of the password. */
    private static final String PASSWORD_SALT = "a fixed salt 16b";

    // ---- the two results the derivation has to produce ---------------------

    /** The client's half as it goes on the wire: encrypted with the password hash. */
    private static final String CLIENT_SESSION_KEY =
            "7F1C1CB37A105D47999DB9D421341D56E96B334242C823ACFCBE8F02EBE729E1";
    private static final String AUTH_PASSWORD =
            "37F9268E630740AF190B3304C5E5DBB9063513D2DC48FFC46AC1EF57115635FF";

    /**
     * The whole chain in one go.
     *
     * <p>Two values are asserted, not one, and they fail differently: the
     * client session key breaks if the password key, the password hash or the
     * AES step is wrong, while {@code AUTH_PASSWORD} additionally covers the
     * combo key and the padding. One assertion would have covered both, but
     * not told you which half moved.
     */
    @Test
    void reproducesTheVector() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment password = ascii(arena, PASSWORD);
            MemorySegment verifier = hex(arena, VERIFIER_DATA);
            MemorySegment comboSalt = hex(arena, COMBO_SALT);
            MemorySegment serverEncrypted = hex(arena, SERVER_SESSION_KEY);
            MemorySegment clientHalf = ascii(arena, CLIENT_HALF);
            MemorySegment salt = ascii(arena, PASSWORD_SALT);

            int keyLength = O5Login12c.SESSION_KEY_LENGTH_32;
            MemorySegment passwordKey = arena.allocate(O5Login12c.DERIVED_LENGTH);
            MemorySegment passwordHash = arena.allocate(O5Login12c.PASSWORD_HASH_LENGTH);
            MemorySegment serverHalf = arena.allocate(keyLength);
            MemorySegment clientEncrypted = arena.allocate(keyLength);
            MemorySegment comboKey = arena.allocate(O5Login12c.COMBO_KEY_LENGTH);

            O5Login12c.passwordKey(password, 0, PASSWORD.length(), verifier, 0, 16,
                    GENERATION_COUNT, passwordKey, 0);
            O5Login12c.passwordHashFrom(passwordKey, 0, verifier, 0, 16, passwordHash, 0);

            // The server's half is decrypted with the password hash - which is
            // where a wrong password would already come apart, on both sides.
            O5Login12c.decryptSessionKey(passwordHash, 0, serverEncrypted, 0, keyLength,
                    serverHalf, 0);
            O5Login12c.encryptSessionKey(passwordHash, 0, clientHalf, 0, keyLength,
                    clientEncrypted, 0);
            assertEquals(CLIENT_SESSION_KEY, toHex(clientEncrypted, keyLength),
                    "the client session key changed");

            O5Login12c.comboKey32(clientHalf, 0, serverHalf, 0, comboSalt, 0, 16,
                    DERIVATION_COUNT, comboKey, 0);

            MemorySegment out = arena.allocate(256);
            int written = O5Login12c.encryptedPassword(comboKey, 0, password, 0,
                    PASSWORD.length(), salt, 0, out, 0);
            assertEquals(AUTH_PASSWORD, text(out, written),
                    "the derivation does not reproduce the expected AUTH_PASSWORD");
        }
    }

    /**
     * The user name is carried along so the vector can be reproduced against
     * the account it belongs to.
     */
    @Test
    void namesTheAccountItBelongsTo() {
        assertEquals("sl_vector", USER);
    }

    private static MemorySegment ascii(Arena arena, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.US_ASCII); // seclume-allow: a published test vector, not a secret
        MemorySegment out = arena.allocate(bytes.length);
        MemorySegment.copy(MemorySegment.ofArray(bytes), 0, out, 0, bytes.length);
        return out;
    }

    private static MemorySegment hex(Arena arena, String text) {
        MemorySegment out = arena.allocate(text.length() / 2);
        for (int i = 0; i < text.length() / 2; i++) {
            out.set(ValueLayout.JAVA_BYTE, i,
                    (byte) ((Character.digit(text.charAt(i * 2), 16) << 4)
                            | Character.digit(text.charAt(i * 2 + 1), 16)));
        }
        return out;
    }

    private static String toHex(MemorySegment segment, int length) {
        StringBuilder out = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            int value = segment.get(ValueLayout.JAVA_BYTE, i) & 0xff;
            out.append(Character.forDigit(value >>> 4, 16))
               .append(Character.forDigit(value & 0x0f, 16));
        }
        return out.toString().toUpperCase(java.util.Locale.ROOT);
    }

    private static String text(MemorySegment segment, int length) {
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append((char) (segment.get(ValueLayout.JAVA_BYTE, i) & 0xff));
        }
        return out.toString();
    }
}

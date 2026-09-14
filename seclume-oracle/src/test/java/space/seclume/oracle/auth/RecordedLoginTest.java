package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * The 12c derivation against a <b>recorded</b> handshake.
 *
 * <p>Oracle's login is not publicly specified, so the derivation was not read
 * but measured. A recorded handshake pins the whole chain down offline: a
 * single wrong byte anywhere - in PBKDF2, in the AES steps, in the combo key -
 * produces a completely different {@code AUTH_PASSWORD}, and this test says so
 * without needing a server.
 *
 * <h2>Where these numbers come from, and what each one is worth</h2>
 *
 * <p><b>Genuine, from a real Oracle Free 23ai:</b> the server session key, the
 * verifier, the combo salt and the two iteration counts. They were captured
 * from a live handshake, and <b>the server then accepted a login derived from
 * exactly these values on that same connection</b> - so they are not just
 * plausible bytes, they are bytes a real server signed off on.
 *
 * <p><b>Chosen, not captured:</b> the client's half of the session key and the
 * salt in front of the password. Both are random in a real login, so freezing
 * them is the only way to have a reproducible vector at all. They are spelled
 * as readable text rather than random-looking hex so that nobody has to wonder
 * later which of these numbers came off the wire.
 *
 * <h2>And the password is right here on purpose</h2>
 *
 * <p>{@link #PASSWORD} belongs to a throwaway database user that exists for
 * this vector and can do nothing but log in. Publishing it is the point: with
 * the session keys, the salt and the encrypted {@code AUTH_PASSWORD} in one
 * file, anyone can try candidate passwords offline and see which one decrypts.
 * That is an offline attack when the password is secret - and nothing at all
 * when it is printed three lines further down.
 *
 * <p>An earlier version of this file carried the same vectors for a password
 * that was <b>not</b> published. That password has been retired. It remains in
 * the history of this repository, so if it was ever used anywhere else, it
 * needs changing there too - the one thing no test can check.
 */
class RecordedLoginTest {

    // ---- genuine: captured from a live handshake the server accepted -------

    private static final String SERVER_SESSION_KEY =
            "4BC2B1507C0D81279A05384EF1642E3A88B0864712D5AD3218C3C36AE949E651";
    private static final String VERIFIER_DATA = "2F92C1208238CBF66F980E09AF9EC18D";
    private static final String COMBO_SALT = "B06854EBE18D6ADDE3FE99C8C2C1DF49";
    private static final int GENERATION_COUNT = 4096;
    private static final int DERIVATION_COUNT = 3;

    // ---- chosen: random in a real login, fixed here so it reproduces -------

    /** The user of the throwaway account this vector was recorded with. */
    private static final String USER = "zl_vector";
    /** Published on purpose - see the class comment. */
    private static final String PASSWORD = "seclumeVector1";
    /** Stands in for the 32 random bytes a login generates. */
    private static final String CLIENT_HALF = "seclume recorded vector, 32 byt";
    /** Stands in for the 16 random bytes in front of the password. */
    private static final String PASSWORD_SALT = "seclume salt 16";

    // ---- the two results the derivation has to produce ---------------------

    /** The client's half as it goes on the wire: encrypted with the password hash. */
    private static final String CLIENT_SESSION_KEY =
            "63C06A1A39B58581DFF518147064E5CA58B2C043157EF257C93C68384AF11B39";
    private static final String AUTH_PASSWORD =
            "80AE3E9AC4557D511FA561F2973986FF8C33A8EF2BAFE1E49F16BD2BC1C957FF";

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
    void reproducesTheRecordedHandshake() {
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
                    "the client session key on the wire changed");

            O5Login12c.comboKey32(clientHalf, 0, serverHalf, 0, comboSalt, 0, 16,
                    DERIVATION_COUNT, comboKey, 0);

            MemorySegment out = arena.allocate(256);
            int written = O5Login12c.encryptedPassword(comboKey, 0, password, 0,
                    PASSWORD.length(), salt, 0, out, 0);
            assertEquals(AUTH_PASSWORD, text(out, written),
                    "the derivation does not reproduce the recorded AUTH_PASSWORD");
        }
    }

    /**
     * The user name is carried along so the vector can be reproduced against
     * the container it came from - {@code docs/protocol/oracle.md} says how.
     */
    @Test
    void namesTheAccountItBelongsTo() {
        assertEquals("zl_vector", USER);
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

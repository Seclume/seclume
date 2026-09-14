package space.seclume.oracle.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import space.seclume.secret.FileSecretProvider;
import space.seclume.secret.SecretScope;

/**
 * The 12c derivation against a <b>recorded</b> handshake.
 *
 * <p>Oracle's login is not publicly specified, so the derivation was not read
 * but measured: a recorded successful handshake contains every value except the
 * password, and the password is known locally. That makes the whole chain
 * checkable without a server - and it pins it down, because a single wrong byte
 * anywhere produces a completely different {@code AUTH_PASSWORD}.
 *
 * <p>The values below come from a throwaway instance. They are session keys of
 * a session that is over; the password is not among them and never will be.
 *
 * <p><b>Before this repository is ever made public, read this.</b> The password
 * is not here, but everything needed to look for it offline is: the two session
 * keys, the salt, and the encrypted {@code AUTH_PASSWORD}. The derivation is
 * documented in {@code docs/protocol/oracle.md}, so anyone can try candidate
 * passwords and see which one decrypts - which is exactly what the test below
 * does with the local file. Against a dictionary that is an offline attack on
 * the test container's password.
 *
 * <p>Inside a private repository that is a fair trade for a test that pins the
 * derivation down. In a public one it is not. What has to happen first: change
 * the password on that container, and replace these vectors with synthetic ones
 * - and remember that they are in the history from 14.09.2026 on, so the
 * history has to be rewritten with them. The blast radius is otherwise small,
 * with one caveat nobody but the owner can check: <b>whether that password is
 * used anywhere else.</b>
 */
class RecordedLoginTest {

    private static final String SERVER_SESSION_KEY = "REDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVE";
    private static final String VERIFIER_DATA = "REDACTEDOLDVECTORREDACTEDOLDVECT";
    private static final String COMBO_SALT = "REDACTEDOLDVECTORREDACTEDOLDVECT";
    private static final int GENERATION_COUNT = 4096;
    private static final int DERIVATION_COUNT = 3;
    private static final String CLIENT_SESSION_KEY = "REDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVE";
    private static final String RECORDED_PASSWORD = "REDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLDVECTORREDACTEDOLD";

    /** The salt that was in front of the password in the recording. */
    private static final String RECORDED_SALT_HEX = "";

    private static Path passwordFile;

    @BeforeAll
    static void findThePassword() {
        for (Path candidate : List.of(Path.of(".local-oracle-password"),
                Path.of("..", ".local-oracle-password"))) {
            if (Files.exists(candidate)) {
                passwordFile = candidate.toAbsolutePath().normalize();
            }
        }
        Assumptions.assumeTrue(passwordFile != null, "no .local-oracle-password");
    }

    /**
     * The recorded {@code AUTH_PASSWORD} comes back out - which can only
     * happen if password key, password hash, both session key halves and the
     * combo key are all right.
     */
    @Test
    void reproducesTheRecordedAuthPassword() throws Exception {
        try (Arena arena = Arena.ofConfined();
             SecretScope password = SecretScope.fromProvider(
                     new FileSecretProvider(passwordFile, 256))) {
            MemorySegment verifier = hex(arena, VERIFIER_DATA);
            MemorySegment comboSalt = hex(arena, COMBO_SALT);
            MemorySegment serverEncrypted = hex(arena, SERVER_SESSION_KEY);
            MemorySegment clientEncrypted = hex(arena, CLIENT_SESSION_KEY);
            MemorySegment recorded = hex(arena, RECORDED_PASSWORD);

            MemorySegment passwordKey = arena.allocate(O5Login12c.DERIVED_LENGTH);
            MemorySegment passwordHash = arena.allocate(O5Login12c.PASSWORD_HASH_LENGTH);
            int length = O5Login12c.SESSION_KEY_LENGTH_32;
            MemorySegment serverHalf = arena.allocate(length);
            MemorySegment clientHalf = arena.allocate(length);
            MemorySegment comboKey = arena.allocate(O5Login12c.COMBO_KEY_LENGTH);

            O5Login12c.passwordKey(password.secret(), 0, password.length(),
                    verifier, 0, 16, GENERATION_COUNT, passwordKey, 0);
            O5Login12c.passwordHashFrom(passwordKey, 0, verifier, 0, 16, passwordHash, 0);
            O5Login12c.decryptSessionKey(passwordHash, 0, serverEncrypted, 0,
                    length, serverHalf, 0);
            // The client half of the recording, decrypted the same way the
            // server does it - that is what makes the recording reproducible.
            O5Login12c.decryptSessionKey(passwordHash, 0, clientEncrypted, 0,
                    length, clientHalf, 0);
            O5Login12c.comboKey32(clientHalf, 0, serverHalf, 0, comboSalt, 0, 16,
                    DERIVATION_COUNT, comboKey, 0);

            // The salt of the recorded value is its first block, decrypted.
            MemorySegment plain = arena.allocate(recorded.byteSize());
            O5Login12c.decryptSessionKey(comboKey, 0, recorded, 0,
                    (int) recorded.byteSize(), plain, 0);

            MemorySegment salt = arena.allocate(16);
            MemorySegment.copy(plain, 0, salt, 0, 16);
            MemorySegment out = arena.allocate(256);
            int written = O5Login12c.encryptedPassword(comboKey, 0, password.secret(), 0,
                    password.length(), salt, 0, out, 0);

            assertEquals(RECORDED_PASSWORD, text(out, written),
                    "the derivation does not reproduce the recorded AUTH_PASSWORD");
        }
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

    private static String text(MemorySegment segment, int length) {
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append((char) (segment.get(ValueLayout.JAVA_BYTE, i) & 0xff));
        }
        return out.toString();
    }
}

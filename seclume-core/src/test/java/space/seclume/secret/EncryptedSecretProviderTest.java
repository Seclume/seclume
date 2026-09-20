package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The encrypted secret, decrypted against a ciphertext this code did not make.
 *
 * <p>Every ciphertext here is produced with {@code javax.crypto} - the JCA,
 * which the library deliberately does not use itself. That is the point: the
 * expectation comes from a second implementation of AES-GCM, and it is also
 * the realistic case, because whatever an operator uses to encrypt the file
 * (a JCA-based tool, {@code openssl}) will not be this code. A test in which
 * seclume decrypts what seclume encrypted would show only that it is
 * self-consistent.
 *
 * <p>The JCA is used <b>in the test</b> and never in the library. The heap is
 * irrelevant on this side: a test JVM holding a test password proves nothing
 * either way, and the real check for that is
 * {@code space.seclume.tck.NoSecretInHeap}.
 */
class EncryptedSecretProviderTest {

    private static final byte[] KEY_256 = new byte[32];
    private static final byte[] NONCE = new byte[12];

    static {
        // Fixed, so a failure is reproducible. A real deployment draws both at
        // random - see the class comment of EncryptedSecretProvider on nonces.
        for (int i = 0; i < KEY_256.length; i++) {
            KEY_256[i] = (byte) (i * 7 + 1);
        }
        for (int i = 0; i < NONCE.length; i++) {
            NONCE[i] = (byte) (i * 11 + 3);
        }
    }

    private static final String PASSWORD = "correct horse battery staple";

    /** Encrypted with the JCA, which is not what the library uses. */
    private static String encrypt(byte[] key, byte[] nonce, String plaintext, String aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
        if (aad != null && !aad.isEmpty()) {
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        }
        byte[] sealed = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] whole = new byte[nonce.length + sealed.length];
        System.arraycopy(nonce, 0, whole, 0, nonce.length);
        System.arraycopy(sealed, 0, whole, nonce.length, sealed.length);
        return Base64.getEncoder().encodeToString(whole);
    }

    private static SecretProvider source(Path directory, String name, String content)
            throws IOException {
        Path file = directory.resolve(name);
        Files.writeString(file, content);
        return new FileSecretProvider(file, 4096);
    }

    private static String read(SecretProvider provider) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment target = arena.allocate(provider.maxSecretLength());
            int length = provider.writeSecret(target);
            byte[] bytes = new byte[length];
            MemorySegment.copy(target, ValueLayout.JAVA_BYTE, 0, bytes, 0, length);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    @Test
    void decryptsWhatTheJcaEncrypted(@TempDir Path dir) throws Exception {
        EncryptedSecretProvider provider = new EncryptedSecretProvider(
                source(dir, "db.enc", encrypt(KEY_256, NONCE, PASSWORD, null)),
                source(dir, "kek", Base64.getEncoder().encodeToString(KEY_256)),
                null);

        assertEquals(PASSWORD, read(provider));
    }

    /** All three key lengths, because the key length picks the AES variant. */
    @Test
    void everyAesKeyLengthWorks(@TempDir Path dir) throws Exception {
        for (int length : new int[] {16, 24, 32}) {
            byte[] key = new byte[length];
            System.arraycopy(KEY_256, 0, key, 0, length);

            EncryptedSecretProvider provider = new EncryptedSecretProvider(
                    source(dir, "c" + length, encrypt(key, NONCE, PASSWORD, null)),
                    source(dir, "k" + length, Base64.getEncoder().encodeToString(key)),
                    null);

            assertEquals(PASSWORD, read(provider), "AES-" + (length * 8));
        }
    }

    /**
     * A ciphertext bound to one purpose must not open under another.
     *
     * <p>This is the swap: without associated data the reporting database's
     * ciphertext can be pasted over the production one and decrypts perfectly -
     * a valid secret, just the wrong one. With it the paste fails.
     */
    @Test
    void associatedDataStopsACiphertextBeingMovedElsewhere(@TempDir Path dir) throws Exception {
        String sealed = encrypt(KEY_256, NONCE, PASSWORD, "reporting");
        String key = Base64.getEncoder().encodeToString(KEY_256);

        assertEquals(PASSWORD, read(new EncryptedSecretProvider(
                source(dir, "a.enc", sealed), source(dir, "a.key", key), "reporting")));

        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "b.enc", sealed), source(dir, "b.key", key), "production")));
        assertTrue(refused.getMessage().contains("did not authenticate"), refused.getMessage());
    }

    @Test
    void theWrongKeyIsRefusedRatherThanGuessedAt(@TempDir Path dir) throws Exception {
        byte[] other = KEY_256.clone();
        other[0] = (byte) (other[0] ^ 0xff);

        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "c.enc", encrypt(KEY_256, NONCE, PASSWORD, null)),
                        source(dir, "c.key", Base64.getEncoder().encodeToString(other)),
                        null)));
        assertTrue(refused.getMessage().contains("did not authenticate"));
    }

    /**
     * An altered ciphertext is refused, and nothing is written.
     *
     * <p>That second half is what a tag is for. Decrypting first and checking
     * afterwards would hand the caller plaintext it must not look at - and a
     * caller given plaintext looks at it.
     */
    @Test
    void anAlteredCiphertextIsRefused(@TempDir Path dir) throws Exception {
        byte[] whole = Base64.getDecoder().decode(encrypt(KEY_256, NONCE, PASSWORD, null));
        // Inside the ciphertext, not the tag - both have to be refused.
        int at = whole.length - 20;
        whole[at] = (byte) (whole[at] ^ 0x01);

        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "d.enc", Base64.getEncoder().encodeToString(whole)),
                        source(dir, "d.key", Base64.getEncoder().encodeToString(KEY_256)),
                        null)));
        assertTrue(refused.getMessage().contains("did not authenticate"));
    }

    /** The message names the real problem, not a consequence three steps later. */
    @Test
    void aTruncatedCiphertextSaysSo(@TempDir Path dir) throws Exception {
        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "e.enc", Base64.getEncoder().encodeToString(new byte[20])),
                        source(dir, "e.key", Base64.getEncoder().encodeToString(KEY_256)),
                        null)));
        assertTrue(refused.getMessage().contains("nonce"), refused.getMessage());
    }

    @Test
    void aKeyOfTheWrongLengthSaysSo(@TempDir Path dir) throws Exception {
        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "f.enc", encrypt(KEY_256, NONCE, PASSWORD, null)),
                        source(dir, "f.key", Base64.getEncoder().encodeToString(new byte[20])),
                        null)));
        assertTrue(refused.getMessage().contains("16, 24 or 32"), refused.getMessage());
    }

    @Test
    void somethingThatIsNotBase64SaysWhichHalfItWas(@TempDir Path dir) throws Exception {
        SecretUnavailableException refused = assertThrows(SecretUnavailableException.class,
                () -> read(new EncryptedSecretProvider(
                        source(dir, "g.enc", "this is not base64 at all !!"),
                        source(dir, "g.key", Base64.getEncoder().encodeToString(KEY_256)),
                        null)));
        assertTrue(refused.getMessage().contains("ciphertext"), refused.getMessage());
    }

    /** The way an application actually reaches it: by configuration. */
    @Test
    void theRegistryBuildsItFromConfiguration(@TempDir Path dir) throws Exception {
        Path ciphertext = dir.resolve("conf.enc");
        Path key = dir.resolve("conf.key");
        Files.writeString(ciphertext, encrypt(KEY_256, NONCE, PASSWORD, "main"));
        Files.writeString(key, Base64.getEncoder().encodeToString(KEY_256));

        Map<String, String> settings = new LinkedHashMap<>();
        settings.put("provider", "encrypted");
        settings.put("cipher-provider", "file");
        settings.put("cipher-path", ciphertext.toString());
        settings.put("key-provider", "file");
        settings.put("key-path", key.toString());
        settings.put("aad", "main");

        try (SecretProvider provider = SecretProviders.of(settings)) {
            assertEquals(PASSWORD, read(provider));
        }
    }

    /**
     * Called twice, it answers twice.
     *
     * <p>The provider is asked again on every physical connect, which is what
     * makes rotation work without a restart - so it must not be usable once.
     * A wipe of an inner buffer that went one segment too far would show here.
     */
    @Test
    void itSurvivesBeingAskedRepeatedly(@TempDir Path dir) throws Exception {
        EncryptedSecretProvider provider = new EncryptedSecretProvider(
                source(dir, "h.enc", encrypt(KEY_256, NONCE, PASSWORD, null)),
                source(dir, "h.key", Base64.getEncoder().encodeToString(KEY_256)),
                null);

        for (int round = 0; round < 5; round++) {
            assertEquals(PASSWORD, read(provider), "round " + round);
        }
    }

    /** A real random key and nonce, so the fixed ones above are not load-bearing. */
    @Test
    void itAlsoWorksWithRandomMaterial(@TempDir Path dir) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        random.nextBytes(key);
        random.nextBytes(nonce);

        EncryptedSecretProvider provider = new EncryptedSecretProvider(
                source(dir, "i.enc", encrypt(key, nonce, PASSWORD, "main")),
                source(dir, "i.key", Base64.getEncoder().encodeToString(key)),
                "main");

        assertEquals(PASSWORD, read(provider));
    }
}

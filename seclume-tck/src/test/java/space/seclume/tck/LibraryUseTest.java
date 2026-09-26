package space.seclume.tck;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.HashAlgorithm;
import space.seclume.crypto.Hmac;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.secret.SecretScope;

/**
 * The example from SECRETS-API.md, run: a library signs a webhook payload with
 * an HMAC key that never becomes a Java object - and the heap is searched for
 * the key afterwards.
 */
class LibraryUseTest {

    @Test
    void aWebhookIsSignedWithAKeyThatNeverReachesTheHeap(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("webhook-key");
        byte[] random = new byte[32]; // seclume-allow: the test makes the key file, and wipes this
        new SecureRandom().nextBytes(random);
        // Printable, so the heap search looks for exactly what the file holds.
        Files.writeString(keyFile, HexFormat.of().formatHex(random), StandardCharsets.US_ASCII);
        java.util.Arrays.fill(random, (byte) 0);

        byte[] payload = "{\"order\": 42}".getBytes(StandardCharsets.UTF_8);
        String signature = sign(SecretProviders.fromUri("file:" + keyFile), payload);
        assertEquals(64, signature.length());

        NoSecretInHeap.assertAbsent(keyFile);
    }

    /** The control: the same key held as a String is found - so the pass above means something. */
    @Test
    void aKeyHeldAsAStringIsFound(@TempDir Path dir) throws Exception {
        Path keyFile = dir.resolve("webhook-key");
        byte[] random = new byte[32]; // seclume-allow: the control's key
        new SecureRandom().nextBytes(random);
        held = HexFormat.of().formatHex(random);
        Files.writeString(keyFile, held, StandardCharsets.US_ASCII);
        try {
            AssertionError found = org.junit.jupiter.api.Assertions.assertThrows(
                    AssertionError.class, () -> NoSecretInHeap.assertAbsent(keyFile));
            org.junit.jupiter.api.Assertions.assertTrue(found.getMessage().contains("heap"),
                    found.getMessage());
        } finally {
            held = null;
        }
    }

    /** Where the control keeps its String, reachable for the dump. */
    private static volatile String held;

    /** What a library would write: the key read, used and wiped in native memory. */
    static String sign(SecretProvider source, byte[] payload) {
        try (SecretScope key = SecretScope.fromProvider(source);
             Hmac mac = new Hmac(HashAlgorithm.SHA_256, key.secret());
             Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(payload.length);
            MemorySegment.copy(payload, 0, data, ValueLayout.JAVA_BYTE, 0, payload.length);
            mac.update(data);
            MemorySegment out = arena.allocate(mac.macLength());
            mac.doFinal(out, 0);
            return HexFormat.of().formatHex(out.toArray(ValueLayout.JAVA_BYTE)); // the signature is public
        }
    }
}

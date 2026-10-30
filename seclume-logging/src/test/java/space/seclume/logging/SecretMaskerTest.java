package space.seclume.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.secret.CallbackSecretProvider;
import space.seclume.secret.SecretProvider;
import space.seclume.tck.NoSecretInHeap;
import space.seclume.tck.StaticSecretProvider;

/**
 * The masker finds a secret in text as itself and as its Base64, masks it
 * under its label, leaves text without one untouched, takes up a rotated
 * secret - and holds no copy of any secret on the heap while it waits.
 */
@org.junit.jupiter.api.parallel.Isolated
class SecretMaskerTest {

    @Test
    void aSecretInALogLineIsMaskedUnderItsLabel() {
        try (SecretMasker masker = new SecretMasker(Map.of("db", new StaticSecretProvider(
                "s3cr3t-Pa55word")))) {
            assertEquals(2, masker.forms());
            assertEquals("login with [redacted:db] failed, retrying with [redacted:db]",
                    masker.mask("login with s3cr3t-Pa55word failed, retrying with "
                            + "s3cr3t-Pa55word"));
            String encoded = Base64.getEncoder().encodeToString(
                    "s3cr3t-Pa55word".getBytes(StandardCharsets.UTF_8));
            assertEquals("header [redacted:db] sent", masker.mask("header " + encoded + " sent"));
            assertEquals("[redacted:db]", masker.mask("s3cr3t-Pa55word"));
            String clean = "nothing to see here, not even s3cr3t-Pa55wor";
            assertSame(clean, masker.mask(clean));
            assertSame(null, masker.mask(null));
        }
    }

    @Test
    void textBeyondAsciiAndSecretsTooShortAreHandled() {
        Map<String, SecretProvider> secrets = new LinkedHashMap<>();
        secrets.put("api", new StaticSecretProvider("Grüße-🔑-geheim"));
        secrets.put("pin", new StaticSecretProvider("1234"));
        try (SecretMasker masker = new SecretMasker(secrets)) {
            assertEquals(2, masker.forms(), "the PIN is too short to be looked for");
            assertEquals("key=[redacted:api]; pin=1234",
                    masker.mask("key=Grüße-🔑-geheim; pin=1234"));
        }
    }

    @Test
    void aRotatedSecretIsTakenUpOnRefresh() {
        AtomicReference<String> current = new AtomicReference<>("first-password");
        SecretProvider rotating = new CallbackSecretProvider(64, target -> {
            byte[] bytes = current.get().getBytes(StandardCharsets.UTF_8);
            java.lang.foreign.MemorySegment.copy(bytes, 0, target,
                    java.lang.foreign.ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
        try (SecretMasker masker = new SecretMasker(Map.of("db", rotating))) {
            current.set("second-password");
            assertEquals("x [redacted:db]", masker.mask("x first-password"));
            assertEquals("x second-password", masker.mask("x second-password"));
            masker.refresh();
            assertEquals("x first-password", masker.mask("x first-password"));
            assertEquals("x [redacted:db]", masker.mask("x second-password"));
            SecretMasker.install(masker);
            assertEquals("x [redacted:db]", SecretMasker.maskInstalled("x second-password"));
        }
        assertEquals("x second-password", SecretMasker.maskInstalled("x second-password"),
                "a closed masker is no longer installed");
    }

    /**
     * The secret is made by openssl and read into native memory only; once
     * the masker has its fingerprints, no copy of it is on the heap.
     */
    @Test
    void theMaskerHoldsNoCopyOfTheSecret(@TempDir Path directory) throws Exception {
        Path secretFile = directory.resolve("api-key");
        Process openssl = space.seclume.tck.Shell.builder("-c", "exec openssl \"$@\"",
                "openssl", "rand", "-hex", "-out", secretFile.toString(), "16")
                .redirectErrorStream(true).start();
        assertTrue(openssl.waitFor(30, TimeUnit.SECONDS) && openssl.exitValue() == 0);
        // Without the newline openssl ends the file with.
        Path trimmed = directory.resolve("api-key-trimmed");
        try (var in = java.nio.channels.FileChannel.open(secretFile);
             var out = java.nio.channels.FileChannel.open(trimmed,
                     java.nio.file.StandardOpenOption.CREATE_NEW,
                     java.nio.file.StandardOpenOption.WRITE)) {
            in.transferTo(0, Files.size(secretFile) - 1, out);
        }
        // provider=file reads into native memory - StaticSecretProvider would leak on purpose.
        try (SecretMasker masker = new SecretMasker(Map.of("api",
                space.seclume.secret.SecretProviders.of(Map.of("provider", "file", "path",
                        trimmed.toString()))))) {
            assertEquals(2, masker.forms());
            NoSecretInHeap.assertAbsent(trimmed);
        }
    }
}

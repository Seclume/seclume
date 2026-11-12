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
            assertTrue(masker.forms() >= 2, "itself and its Base64 at least");
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
        try (SecretMasker masker = new SecretMasker(secrets);
             SecretMasker apiOnly = new SecretMasker(Map.of("api",
                     new StaticSecretProvider("Grüße-🔑-geheim")))) {
            assertEquals(apiOnly.forms(), masker.forms(), "the PIN is too short to be looked for");
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
            assertTrue(masker.forms() >= 2);
            NoSecretInHeap.assertAbsent(trimmed);
        }
    }

    /**
     * A checkpoint wipes the key and every tag - with the key in the image a
     * tag would test guesses at the password offline - and the next line
     * masked after the restore is masked as before, under a new key.
     */
    @Test
    void aCheckpointWipesTheKeyAndTheNextLineIsMaskedAsBefore() {
        space.seclume.internal.Checkpoint.wipeAll();
        long before = space.seclume.secret.SecretScope.open();
        try (SecretMasker masker = new SecretMasker(Map.of("db",
                new StaticSecretProvider("checkpointed-Pa55word")))) {
            assertEquals("x [redacted:db]", masker.mask("x checkpointed-Pa55word"));
            int forms = masker.forms();
            space.seclume.internal.Checkpoint.wipeAll();
            assertEquals(before, space.seclume.secret.SecretScope.open(),
                    "the masker's key would be in the image");
            assertEquals(0, masker.forms());
            assertEquals("x [redacted:db]", masker.mask("x checkpointed-Pa55word"));
            assertEquals(forms, masker.forms());
        }
        assertEquals(before, space.seclume.secret.SecretScope.open());
    }

    // ---- the forms a secret takes on its way into a log line ------------------------

    private static final String SECRET = "p@ss/w0rd+\"q\\x~ y";

    private static SecretMasker masker() {
        return new SecretMasker(Map.of("db", new StaticSecretProvider(SECRET)));
    }

    @Test
    void aBasicHeaderIsMaskedWhateverTheUserBeforeThePassword() {
        try (SecretMasker masker = masker()) {
            for (String user : new String[] {"", "a", "ab", "abc", "deploy", "jürgen"}) {
                String header = Base64.getEncoder().encodeToString((user + ":" + SECRET)
                        .getBytes(StandardCharsets.UTF_8));
                String masked = masker.mask("Authorization: Basic " + header);
                assertTrue(masked.contains("[redacted:db]"), user + ": " + masked);
                // What is left of the header is the user's part and at most two
                // characters it shares with the password.
                String left = masked.replace("Authorization: Basic ", "").replace("[redacted:db]",
                        "");
                assertTrue(left.length() <= Base64.getEncoder().encodeToString((user + ":")
                        .getBytes(StandardCharsets.UTF_8)).length() + 4, user + ": " + masked);
            }
        }
    }

    @Test
    void base64UnpaddedAndUrlSafeAreMasked() {
        try (SecretMasker masker = masker()) {
            byte[] bytes = SECRET.getBytes(StandardCharsets.UTF_8);
            for (String encoded : new String[] {
                Base64.getEncoder().encodeToString(bytes),
                Base64.getEncoder().withoutPadding().encodeToString(bytes),
                Base64.getUrlEncoder().encodeToString(bytes),
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)}) {
                String masked = masker.mask("token=" + encoded + "&x=1");
                assertTrue(masked.contains("[redacted:db]"), encoded + " -> " + masked);
                assertTrue(masked.endsWith("&x=1"), masked);
            }
        }
    }

    /**
     * URL-safe Base64 is looked for at each of the three offsets on its own:
     * this secret's Base64 has no {@code +} or {@code /} when it starts a
     * text, and has one when a byte stands before it - as in a token's payload.
     */
    @Test
    void urlSafeBase64InsideALongerTextIsMaskedAtEveryOffset() {
        String secret = "-Lzmdmrf/;~B";
        String own = Base64.getEncoder().encodeToString(secret.getBytes(StandardCharsets.UTF_8));
        assertTrue(!own.contains("+") && !own.contains("/"), "the secret was chosen for that");
        try (SecretMasker masker = new SecretMasker(Map.of("db",
                new StaticSecretProvider(secret)))) {
            for (String before : new String[] {"", "u", "us", "use", "user"}) {
                byte[] bytes = (before + secret).getBytes(StandardCharsets.UTF_8);
                for (String encoded : new String[] {
                    Base64.getEncoder().encodeToString(bytes),
                    Base64.getUrlEncoder().encodeToString(bytes),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)}) {
                    String masked = masker.mask("token " + encoded);
                    assertTrue(masked.contains("[redacted:db]"),
                            "'" + before + "': " + encoded + " -> " + masked);
                }
            }
        }
    }

    /** One line with many secrets of many lengths, some of the same length: each is masked. */
    @Test
    void everyOneOfManySecretsIsMasked() {
        Map<String, SecretProvider> providers = new LinkedHashMap<>();
        StringBuilder line = new StringBuilder("start");
        StringBuilder expected = new StringBuilder("start");
        for (int i = 0; i < 30; i++) {
            String secret = "pw-" + "x".repeat(i % 7) + "#" + (1000 + i);
            providers.put("s" + i, new StaticSecretProvider(secret));
            line.append(' ').append(secret);
            expected.append(" [redacted:s").append(i).append(']');
        }
        try (SecretMasker masker = new SecretMasker(providers)) {
            assertEquals(expected.toString(), masker.mask(line.toString()));
            String clean = "nothing of it: pw-xx#99 and pw-#100";
            assertSame(clean, masker.mask(clean));
        }
    }

    @Test
    void percentEncodedAsInAUrlOrAFormIsMasked() {
        try (SecretMasker masker = masker()) {
            String rfc3986 = java.net.URLEncoder.encode(SECRET, StandardCharsets.UTF_8)
                    .replace("+", "%20").replace("%7E", "~").replace("*", "%2A");
            String form = java.net.URLEncoder.encode(SECRET, StandardCharsets.UTF_8);
            assertEquals("jdbc:x://h/db?password=[redacted:db]&ssl=true",
                    masker.mask("jdbc:x://h/db?password=" + rfc3986 + "&ssl=true"));
            assertEquals("user=a&password=[redacted:db]",
                    masker.mask("user=a&password=" + form));
            // Some encoders write the hex digits in lower case.
            String lower = java.util.regex.Pattern.compile("%[0-9A-F]{2}").matcher(rfc3986)
                    .replaceAll(hex -> hex.group().toLowerCase(java.util.Locale.ROOT));
            assertTrue(!lower.equals(rfc3986), "the secret has a character that is encoded");
            assertEquals("?password=[redacted:db]&ssl=true",
                    masker.mask("?password=" + lower + "&ssl=true"));
        }
    }

    @Test
    void jsonEscapedIsMasked() {
        try (SecretMasker masker = masker()) {
            String escaped = SECRET.replace("\\", "\\\\").replace("\"", "\\\"");
            assertEquals("{\"password\":\"[redacted:db]\"}",
                    masker.mask("{\"password\":\"" + escaped + "\"}"));
            // And as itself, still.
            assertEquals("pw [redacted:db].", masker.mask("pw " + SECRET + "."));
        }
    }

    @Test
    void aSecretNoEncodingChangesIsLookedForOncePerForm() {
        try (SecretMasker plain = new SecretMasker(Map.of("k",
                new StaticSecretProvider("abcdefghijkl")))) {
            // itself, Base64 (whole and at three offsets); nothing to percent- or
            // JSON-escape, and the URL-safe alphabet is the standard one here.
            assertEquals(4, plain.forms());
        }
    }
}

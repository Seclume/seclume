package space.seclume.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.crypto.OpenSslSigningKey;
import space.seclume.tck.NoSecretInHeap;

/**
 * The claim itself: after signing and checking tokens with an HMAC key,
 * signing with an RSA and an EC key, and checking a GitHub webhook, none of
 * the keys is on this JVM's heap - not the PEM, not the DER inside it, not the
 * RSA private exponent, not the HMAC key or the webhook secret.
 *
 * <p>The keys are made in a JVM of its own ({@link KeyMakerMain}); this one
 * only ever holds their paths. The control at the end reads the HMAC key into
 * a {@code String} on purpose, and the search has to find it.
 */
@Timeout(300)
class NoKeyOnTheHeapTest {

    @Test
    void noSigningKeyOnTheHeap() throws Exception {
        Path directory = Files.createTempDirectory("seclume-jwt-proof");
        Process maker = new ProcessBuilder(List.of(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                KeyMakerMain.class.getName(), directory.toString()))
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start();
        try {
            assertTrue(maker.waitFor(120, TimeUnit.SECONDS));
            assertEquals(0, maker.exitValue());
            List<String> searched = new ArrayList<>(List.of("hmac-key", "webhook-secret"));

            try (SeclumeJwt jwt = SeclumeJwt.of("HS256?provider=file&path="
                    + slashes(directory.resolve("hmac-key")))) {
                for (int i = 0; i < 3; i++) {
                    String token = jwt.sign(Map.of("sub", "user-" + i));
                    assertTrue(jwt.verify(token).contains("user-" + i));
                }
            }
            try (SeclumeHmac webhook = SeclumeHmac.of("SHA256?provider=file&path="
                    + slashes(directory.resolve("webhook-secret")))) {
                assertTrue(webhook.verifyGitHub(Files.readString(directory.resolve(
                        "github-header")), KeyMakerMain.BODY.getBytes(StandardCharsets.UTF_8)));
            }
            if (OpenSslSigningKey.available()) {
                for (String[] key : new String[][] {{"RS256", "rsa"}, {"PS256", "rsa"},
                        {"ES256", "ec"}}) {
                    try (SeclumeJwt jwt = SeclumeJwt.of(key[0] + "?provider=file&path="
                            + slashes(directory.resolve(key[1] + ".pem")))) {
                        jwt.sign(Map.of("iss", "app-1"));
                        jwt.sign(Map.of("iss", "app-2"));
                    }
                }
                searched.addAll(List.of("rsa.pem", "rsa.der", "rsa-d.bin", "ec.pem", "ec.der"));
            }

            for (String secret : searched) {
                NoSecretInHeap.assertAbsent(directory.resolve(secret));
            }

            String leaked = Files.readString(directory.resolve("hmac-key")); // seclume-allow: the control, put on the heap on purpose
            AssertionError found = assertThrows(AssertionError.class,
                    () -> NoSecretInHeap.assertAbsent(directory.resolve("hmac-key")));
            assertTrue(found.getMessage().contains("the secret is on the heap"),
                    found.getMessage());
            Reference.reachabilityFence(leaked);

            // And the same for a key of bytes: the DER a PEM decoded on the heap
            // would leave behind - which is what the search for rsa.der is for.
            if (searched.contains("ec.der")) {
                byte[] decoded = Files.readAllBytes(directory.resolve("ec.der")); // seclume-allow: the control, put on the heap on purpose
                AssertionError der = assertThrows(AssertionError.class,
                        () -> NoSecretInHeap.assertAbsent(directory.resolve("ec.der")));
                assertTrue(der.getMessage().contains("the secret is on the heap"),
                        der.getMessage());
                Reference.reachabilityFence(decoded);
            }
        } finally {
            maker.destroyForcibly();
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
    }

    private static String slashes(Path path) {
        return path.toString().replace('\\', '/');
    }
}

package space.seclume.jwt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import space.seclume.crypto.OpenSslSigningKey;

/**
 * Tokens made here and checked by the JDK's own crypto - HMAC by
 * {@code javax.crypto.Mac}, RSA, PSS and ECDSA by {@code Signature} with the
 * public key - and tokens checked here that must be refused.
 */
class SeclumeJwtTest {

    private static final String KEY = "a-32-byte-hmac-key-for-hs256-ok!";
    private static final Base64.Decoder B64 = Base64.getUrlDecoder();

    private static Path file(Path dir, String name, String content) throws Exception {
        Path path = dir.resolve(name);
        Files.writeString(path, content);
        return path;
    }

    private static String spec(String alg, Path key, String extra) {
        return alg + "?provider=file&path=" + key.toString().replace('\\', '/') + extra;
    }

    /** Signing and checking are Signature events - a failed check says so. */
    @Test
    void signaturesAreRecorded(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, ""))) {
            var events = space.seclume.tck.Recorded.during(() -> {
                String token = jwt.sign(Map.of("sub", "x"));
                jwt.verify(token);
                assertThrows(InvalidTokenException.class, () -> jwt.verify(
                        token.substring(0, token.lastIndexOf('.') + 1) + "AAAA"));
            }, "space.seclume.Signature");
            assertEquals(3, events.size(), events.toString());
            assertEquals("sign", events.get(0).getString("operation"));
            assertEquals("HS256", events.get(0).getString("algorithm"));
            assertTrue(events.get(1).getBoolean("succeeded"));
            assertEquals("verify", events.get(2).getString("operation"));
            assertTrue(!events.get(2).getBoolean("succeeded"));
        }
    }

    @Test
    void hs256IsTheJdksHmacAndRoundTrips(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, "&kid=k1"))) {
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("sub", "user-42");
            claims.put("roles", List.of("a", "b"));
            claims.put("n", 7);
            String token = jwt.sign(claims);
            String[] parts = token.split("\\.");
            assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}",
                    new String(B64.decode(parts[0]), StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            byte[] expected = mac.doFinal((parts[0] + "." + parts[1])
                    .getBytes(StandardCharsets.US_ASCII));
            assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(expected),
                    parts[2]);
            assertEquals("{\"sub\":\"user-42\",\"roles\":[\"a\",\"b\"],\"n\":7}",
                    jwt.verify(token));
        }
    }

    @Test
    void whatVerifyRefuses(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, ""))) {
            String token = jwt.sign(Map.of("sub", "a"));
            String[] parts = token.split("\\.");
            String none = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
            assertMessage("alg none", () -> jwt.verify(none + "." + parts[1] + "."));
            String hs512 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"alg\":\"HS512\"}".getBytes(StandardCharsets.UTF_8));
            assertMessage("alg HS512", () -> jwt.verify(hs512 + "." + parts[1] + "." + parts[2]));
            String other = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"sub\":\"admin\"}".getBytes(StandardCharsets.UTF_8));
            assertMessage("does not match",
                    () -> jwt.verify(parts[0] + "." + other + "." + parts[2]));
            assertMessage("three parts", () -> jwt.verify("a.b"));
            assertMessage("base64url", () -> jwt.verify("a.b.c!"));
        }
        try (SeclumeJwt wrongKey = SeclumeJwt.of(spec("HS256", file(dir, "other",
                "another-32-byte-key-for-hs256!!!"), ""));
             SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, ""))) {
            String token = wrongKey.sign(Map.of("sub", "a"));
            assertMessage("does not match", () -> jwt.verify(token));
        }
    }

    /**
     * One token, one string: the JDK's decoder also takes padding and a last
     * character whose spare bits are set, and a signature written so decodes
     * to the same MAC - a different string for the same token, which a list
     * of used or revoked tokens kept by their string would not recognise.
     */
    @Test
    void aTokenIsAcceptedOnlyAsItIsWritten(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, ""))) {
            String token = jwt.sign(Map.of("sub", "a"));
            jwt.verify(token);
            int dot = token.lastIndexOf('.');
            String signature = token.substring(dot + 1);
            // HS256: 32 bytes, 43 characters, two spare bits in the last one.
            assertEquals(43, signature.length());
            String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            char last = signature.charAt(42);
            String spareBit = signature.substring(0, 42) + alphabet.charAt(alphabet.indexOf(last) ^ 1);
            assertArrayEquals(B64.decode(signature), B64.decode(spareBit), "the same MAC");
            assertMessage("spare bits", () -> jwt.verify(token.substring(0, dot + 1) + spareBit));
            assertMessage("padded", () -> jwt.verify(token + "="));
            String[] parts = token.split("\\.");
            assertMessage("base64url", () -> jwt.verify(parts[0] + "=." + parts[1] + "." + parts[2]));
        }
    }

    /** RFC 7515: a critical extension the recipient does not understand invalidates the token. */
    @Test
    void aCriticalHeaderParameterIsRefused(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, ""))) {
            String token = jwt.sign(Map.of("crit", List.of("exp-bound"), "exp-bound", true),
                    Map.of("sub", "a"));
            assertMessage("crit", () -> jwt.verify(token));
            // Without crit the same extra header parameter is only information.
            jwt.verify(jwt.sign(Map.of("exp-bound", true), Map.of("sub", "a")));
        }
    }

    @Test
    void expiryAndNotBefore(@TempDir Path dir) throws Exception {
        Path key = file(dir, "hs", KEY);
        Clock at1000 = Clock.fixed(Instant.ofEpochSecond(1000), ZoneOffset.UTC);
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", key, "&leeway=10"))) {
            jwt.clock(at1000);
            jwt.verify(jwt.sign(Map.of("exp", 1005)));                 // in time
            jwt.verify(jwt.sign(Map.of("exp", 995)));                  // within the leeway
            assertMessage("expired", () -> jwt.verify(jwt.sign(Map.of("exp", 990))));
            jwt.verify(jwt.sign(Map.of("nbf", 1008)));                 // within the leeway
            assertMessage("not valid before", () -> jwt.verify(jwt.sign(Map.of("nbf", 1011))));
            assertMessage("whole number", () -> jwt.verify(jwt.sign(Map.of("exp", "soon"))));
        }
    }

    @Test
    void aShortHmacKeyIsRefused(@TempDir Path dir) throws Exception {
        try (SeclumeJwt jwt = SeclumeJwt.of(spec("HS256", file(dir, "short", "too-short"), ""))) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> jwt.sign(Map.of("sub", "a")));
            assertTrue(e.getMessage().contains("at least 32 bytes"), e.getMessage());
        }
    }

    @Test
    void rsaPssAndEcTokensAreCheckedByTheJdk(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(space.seclume.crypto.PrivateSigningKey.available(), "no OpenSSL 3 or CNG here");
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsa = rsaGenerator.generateKeyPair();
        Path rsaKey = file(dir, "rsa.pem", pem(rsa));
        check("RS256", rsaKey, rsa, Signature.getInstance("SHA256withRSA"));
        Signature pss = Signature.getInstance("RSASSA-PSS");
        pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        check("PS256", rsaKey, rsa, pss);

        for (String[] curve : new String[][] {{"ES256", "secp256r1", "SHA256"},
                {"ES384", "secp384r1", "SHA384"}, {"ES512", "secp521r1", "SHA512"}}) {
            KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
            ecGenerator.initialize(new ECGenParameterSpec(curve[1]));
            KeyPair ec = ecGenerator.generateKeyPair();
            check(curve[0], file(dir, curve[0] + ".pem", pem(ec)), ec,
                    Signature.getInstance(curve[2] + "withECDSAinP1363Format"));
        }

        try (SeclumeJwt wrong = SeclumeJwt.of(spec("ES256", rsaKey, ""))) {
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> wrong.sign(Map.of("sub", "a")));
            assertTrue(e.getMessage().contains("needs an EC key"), e.getMessage());
            assertThrows(IllegalStateException.class, () -> wrong.verify("a.b.c"));
        }
    }

    /**
     * ES256 is ECDSA on P-256, ES384 on P-384, ES512 on P-521 (RFC 7518,
     * 3.4) - the algorithm names the curve. A P-256 key under ES512 signed a
     * token whose signature verifiers that check the curve refuse and lax ones
     * take; a P-384 key under ES256 failed on some signatures only. Each is
     * refused at the first signature, naming the curve.
     */
    @Test
    void anEcKeyOnAnotherCurveThanTheAlgorithmsIsRefused(@TempDir Path dir) throws Exception {
        Assumptions.assumeTrue(space.seclume.crypto.PrivateSigningKey.available(), "no OpenSSL 3 or CNG here");
        for (String[] wrong : new String[][] {{"ES512", "secp256r1"}, {"ES256", "secp384r1"},
                {"ES384", "secp521r1"}}) {
            KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
            ecGenerator.initialize(new ECGenParameterSpec(wrong[1]));
            Path key = file(dir, wrong[0] + "-" + wrong[1] + ".pem", pem(ecGenerator.generateKeyPair()));
            try (SeclumeJwt jwt = SeclumeJwt.of(spec(wrong[0], key, ""))) {
                IllegalStateException e = assertThrows(IllegalStateException.class,
                        () -> jwt.sign(Map.of("sub", "a")), wrong[0] + " with " + wrong[1]);
                assertTrue(e.getMessage().contains("curve"), e.getMessage());
            }
        }
    }

    private static void check(String alg, Path key, KeyPair pair, Signature verifier)
            throws Exception {
        try (SeclumeJwt jwt = SeclumeJwt.of(spec(alg, key, "&kid=" + alg))) {
            String token = jwt.sign(Map.of("x5t", "abc"), Map.of("iss", "app-1"));
            String[] parts = token.split("\\.");
            assertTrue(new String(B64.decode(parts[0]), StandardCharsets.UTF_8)
                    .contains("\"x5t\":\"abc\""));
            verifier.initVerify(pair.getPublic());
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            assertTrue(verifier.verify(B64.decode(parts[2])), alg);
        }
    }

    private static String pem(KeyPair pair) {
        return "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    void specRefusals() {
        assertMessage("never 'none'", () -> SeclumeJwt.of("none?provider=file&path=/x"));
        assertMessage("no key named", () -> SeclumeJwt.of("HS256"));
    }

    private static void assertMessage(String part, org.junit.jupiter.api.function.Executable e) {
        RuntimeException thrown = assertThrows(RuntimeException.class, e);
        assertTrue(thrown.getMessage().contains(part), thrown.getMessage());
    }
}

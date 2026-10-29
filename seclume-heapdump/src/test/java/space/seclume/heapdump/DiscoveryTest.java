package space.seclume.heapdump;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The detectors on bytes made for them: each shape is found in each encoding
 * it can lie in a dump in, across the edges of the windows the file is read
 * in, and not where only something like it is - a template, a header without
 * a key, a token without a signature. And whatever is found, the reports
 * name it and count it and never hold it.
 */
class DiscoveryTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Credentials of every shape, made up, each with its detector. */
    private static final Map<String, String> SAMPLES = Map.ofEntries(
            Map.entry("private-key", "-----BEGIN PRIVATE KEY-----\n"
                    + base64(48) + "\n" + base64(48) + "\n-----END PRIVATE KEY-----"),
            Map.entry("jwt", "eyJhbGciOiJSUzI1NiJ9." + "eyJ" + base64url(60) + "."
                    + base64url(64)),
            Map.entry("aws-access-key-id", "AKIA" + "QWERTYUIOPASDFGH".replace('O', '7')),
            Map.entry("aws-secret-access-key", "aws_secret_access_key = "
                    + base64(30).substring(0, 40)),
            Map.entry("vault-token", "hvs." + base64url(40)),
            Map.entry("github-token", "ghp_" + alnum(36)),
            Map.entry("gitlab-token", "glpat-" + alnum(20)),
            Map.entry("slack-token", "xoxb-" + alnum(30)),
            Map.entry("stripe-key", "sk_live_" + alnum(24)),
            Map.entry("google-api-key", "AIza" + alnum(35)),
            Map.entry("npm-token", "npm_" + alnum(36)),
            Map.entry("ai-api-key", "sk-ant-api03-" + alnum(40)),
            Map.entry("azure-storage-key", "DefaultEndpointsProtocol=https;AccountName=acct;"
                    + "AccountKey=" + base64(64) + ";EndpointSuffix=core.windows.net"),
            Map.entry("azure-sas", "https://acct.blob.core.windows.net/c?sv=2024&sig="
                    + alnum(44)),
            Map.entry("url-password", "postgresql://app:" + alnum(18) + "@db.internal:5432/app"),
            Map.entry("url-password-parameter", "jdbc:sqlserver://db;user=app;password="
                    + alnum(16)),
            Map.entry("http-authorization", "Authorization: Basic " + base64(24)));

    private static String base64(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    private static String base64url(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static String alnum(int length) {
        String letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            out.append(letters.charAt(RANDOM.nextInt(letters.length())));
        }
        return out.toString();
    }

    /** Random binary noise around the text, so that runs end where they would in a dump. */
    private static byte[] dump(String encoding, String... texts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String text : texts) {
            byte[] noise = new byte[64 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(noise);
            for (int i = 0; i < noise.length; i++) {
                noise[i] = (byte) (noise[i] | 0x80);     // never printable, never a UTF-16 ASCII pair
            }
            out.writeBytes(noise);
            out.writeBytes(text.getBytes(switch (encoding) {
                case "UTF-16BE" -> StandardCharsets.UTF_16BE;
                case "UTF-16LE" -> StandardCharsets.UTF_16LE;
                default -> StandardCharsets.US_ASCII;
            }));
        }
        byte[] tail = new byte[100];
        java.util.Arrays.fill(tail, (byte) 0xff);
        out.writeBytes(tail);
        return out.toByteArray();
    }

    private static Set<String> detectors(Discovery.Result result) {
        return result.valuesByDetector().keySet();
    }

    @Test
    void everyShapeIsFoundInEveryEncoding() {
        for (String encoding : List.of("ASCII", "UTF-16BE", "UTF-16LE")) {
            for (Map.Entry<String, String> sample : SAMPLES.entrySet()) {
                Discovery.Result result = Discovery.scan(dump(encoding, sample.getValue()),
                        Set.of(), Discovery.CHUNK);
                assertEquals(Set.of(sample.getKey()), detectors(result),
                        sample.getKey() + " in " + encoding);
                assertEquals(1, result.found().size(), sample.getKey() + " in " + encoding);
                assertEquals(1, result.found().get(0).count(),
                        sample.getKey() + " counted twice in " + encoding);
                Discovery.Occurrence at = result.found().get(0).occurrences().get(0);
                assertEquals(encoding, at.encoding());
            }
        }
    }

    /** UTF-16 at an odd offset: a char[] does not start where a byte[] would. */
    @Test
    void utf16IsFoundAtEitherAlignment() {
        byte[] even = dump("UTF-16BE", SAMPLES.get("jwt"));
        byte[] odd = new byte[even.length + 1];
        odd[0] = (byte) 0xff;
        System.arraycopy(even, 0, odd, 1, even.length);
        assertEquals(Set.of("jwt"), detectors(Discovery.scan(odd, Set.of(), Discovery.CHUNK)));
    }

    /** The position is the byte offset in the file, and the length is in bytes. */
    @Test
    void thePositionIsWhereTheMatchStartsInTheFile() {
        String token = SAMPLES.get("vault-token");
        byte[] data = new byte[5000];
        java.util.Arrays.fill(data, (byte) 0xfe);
        byte[] text = token.getBytes(StandardCharsets.UTF_16BE);
        System.arraycopy(text, 0, data, 3001, text.length);
        Discovery.Result result = Discovery.scan(data, Set.of(), Discovery.CHUNK);
        Discovery.Occurrence at = result.found().get(0).occurrences().get(0);
        assertEquals(new Discovery.Occurrence("UTF-16BE", 3001, text.length, 3001,
                text.length), at, "a token is all value");
    }

    /**
     * Small windows, so that tokens fall on every edge: each is found once,
     * not twice where windows overlap and not lost where one ends.
     */
    @Test
    void windowsNeitherLoseNorDoubleAMatch() {
        String[] tokens = new String[200];
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = "ghp_" + alnum(36);
        }
        byte[] data = dump("ASCII", tokens);
        for (int chunk : new int[] {1024, 1500, 4096, 10_000, Discovery.CHUNK}) {
            Discovery.Result result = Discovery.scan(data, Set.of(), chunk);
            assertEquals(200, result.found().size(), "distinct tokens with windows of " + chunk);
            assertTrue(result.found().stream().allMatch(f -> f.count() == 1),
                    "a token counted twice with windows of " + chunk);
        }
    }

    @Test
    void oneValueSeenOftenIsOneFindingWithACount() {
        String jwt = SAMPLES.get("jwt");
        String other = "eyJhbGciOiJFUzI1NiJ9.eyJ" + base64url(40) + "." + base64url(64);
        Discovery.Result result = Discovery.scan(dump("ASCII", jwt, jwt, other, jwt),
                Set.of(), Discovery.CHUNK);
        assertEquals(2, result.found().size());
        assertEquals(1, result.found().get(0).value());
        assertEquals(3, result.found().get(0).count());
        assertEquals(3, result.found().get(0).occurrences().size());
        assertEquals(2, result.found().get(1).value());
        assertEquals(1, result.found().get(1).count());
    }

    /** What looks like a credential and is none. */
    @Test
    void lookalikesAreNotFindings() {
        Discovery.Result result = Discovery.scan(dump("ASCII",
                // a PEM header as a parser holds it, with no key after it
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN PUBLIC KEY-----\n" + base64(48),
                // an unsigned token, and the header of one alone
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
                "eyJhbGciOiJSUzI1NiJ9",
                // templates and masks where a password would be
                "postgresql://app:${DB_PASSWORD}@db:5432/app",
                "jdbc:mysql://db/app?user=app&password=******",
                "redis://user:password@cache:6379",
                "jdbc:postgresql://db/app?password=<secret>",
                // a key id inside a longer run of capitals is no key id
                "XAKIAQWERTYUIOPASDFGHJ",
                // a URL with a user and no password
                "https://user@example.com/path",
                // a version string with a Vault-like prefix but too short
                "hvs.short"), Set.of(), Discovery.CHUNK);
        assertTrue(result.clean(), "found: " + result.valuesByDetector());
    }

    @Test
    void anIgnoredDetectorIsLeftOut() {
        byte[] data = dump("ASCII", SAMPLES.get("jwt"), SAMPLES.get("vault-token"));
        Discovery.Result result = Discovery.scan(data, Set.of("jwt"), Discovery.CHUNK);
        assertEquals(Set.of("vault-token"), detectors(result));
        assertEquals(Set.of("jwt"), result.ignored());
        assertThrows(IllegalArgumentException.class,
                () -> Discovery.scan(data, Set.of("no-such-detector"), Discovery.CHUNK));
    }

    @Test
    void detectorIdsAreUniqueAndStable() {
        List<String> ids = Discovery.ids();
        assertEquals(ids.size(), Set.copyOf(ids).size());
        assertTrue(ids.containsAll(SAMPLES.keySet()) && SAMPLES.keySet().containsAll(ids),
                "a detector without a sample, or a sample without a detector");
        for (String id : ids) {
            assertTrue(id.matches("[a-z0-9-]+"), id);
        }
        assertEquals(Set.copyOf(ids), Discovery.ANCHORS.keySet(),
                "a detector without an anchor would never be tried");
        for (Discovery.Anchor anchor : Discovery.ANCHORS.values()) {
            for (String literal : anchor.literals()) {
                assertTrue(!anchor.ignoreCase() || literal.equals(literal.toLowerCase(
                        java.util.Locale.ROOT)), "an anchor ignoring case is written in "
                        + "lower case: " + literal);
            }
        }
    }

}

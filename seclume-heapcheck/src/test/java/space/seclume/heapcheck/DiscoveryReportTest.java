package space.seclume.heapcheck;

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

import space.seclume.heapdump.Discovery;

/**
 * Discovery as heapcheck reports it: which kind, which number, how often,
 * where - in JSON, Markdown and SARIF - and nothing of any value.
 */
class DiscoveryReportTest {

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

    /** The reports: which kind, which number, how often, where - and nothing of the value. */
    @Test
    void noReportHoldsAValue() {
        String[] all = SAMPLES.values().toArray(String[]::new);
        Discovery.Result result = Discovery.scan(dump("ASCII", all), Set.of("npm-token"));
        assertEquals(SAMPLES.size() - 1, result.found().size());
        AuditReport report = new AuditReport(Instant.parse("2026-10-28T12:00:00Z"), "host",
                new AuditReport.Target(null, null, "app.hprof"),
                new AuditReport.Dump(1, "00", true), List.of(), result);
        String json = report.json();
        String markdown = report.markdown();
        String sarif = report.sarif();
        for (String text : List.of(json, markdown, sarif)) {
            for (String sample : all) {
                String secret = secretPart(sample);
                assertFalse(text.contains(secret), "a report holds a value: " + secret);
            }
        }
        assertFalse(report.clean());
        assertTrue(report.secretsClean());
        assertTrue(json.contains("\"verdict\": \"NOT_FOUND\""), "verdict is the named secrets'");
        assertTrue(json.contains("\"discovery\": {\n    \"verdict\": \"FOUND\""), json);
        assertTrue(json.contains("\"ignored\": [\"npm-token\"]"), json);
        assertTrue(markdown.contains("## Found without being named")
                && markdown.contains("Left out on request: npm-token."), markdown);
        assertTrue(sarif.contains("\"id\": \"SECLUME-HEAP-DISCOVER-JWT\""), sarif);
        assertTrue(sarif.contains("\"fullyQualifiedName\": \"heap dump/jwt/#1\""), sarif);
        assertFalse(sarif.contains("\"position\""), "SARIF carries no heap offsets");
    }

    /**
     * The part of a sample that is the secret - what a report must never
     * contain. Twelve characters of it: enough to be unmistakable, short
     * enough to be in every encoding of it.
     */
    private static String secretPart(String sample) {
        String secret;
        if (sample.startsWith("-----BEGIN")) {
            secret = sample.split("\n")[1];
        } else if (sample.contains("AccountKey=")) {
            int from = sample.indexOf("AccountKey=") + "AccountKey=".length();
            secret = sample.substring(from, sample.indexOf(';', from));
        } else if (sample.contains("://") && sample.indexOf('@') > 0) {
            secret = sample.substring(sample.indexOf(':', sample.indexOf("://") + 3) + 1,
                    sample.indexOf('@'));
        } else if (sample.contains("password=") || sample.contains("sig=")) {
            secret = sample.substring(sample.lastIndexOf('=') + 1);
        } else if (sample.contains(" ")) {
            secret = sample.substring(sample.lastIndexOf(' ') + 1);
        } else {
            secret = sample;
        }
        String middle = secret.length() > 20 ? secret.substring(8) : secret;
        return middle.length() > 12 ? middle.substring(0, 12) : middle;
    }

    @Test
    void aCleanDiscoveryIsReportedAsSuch() {
        Discovery.Result result = Discovery.scan(dump("ASCII", "nothing to see here at all"),
                Set.of());
        AuditReport report = new AuditReport(Instant.now(), "host",
                new AuditReport.Target(null, null, "app.hprof"),
                new AuditReport.Dump(1, "00", true), List.of(), result);
        assertTrue(report.clean());
        assertTrue(report.json().contains("\"discovery\": {\n    \"verdict\": \"NOT_FOUND\""));
        assertTrue(report.markdown().contains("No credential of a known shape is in the dump."));
        assertTrue(report.sarif().contains("\"results\": [\n\n    ]"));
    }
}

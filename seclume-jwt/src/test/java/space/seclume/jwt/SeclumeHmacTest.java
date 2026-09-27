package space.seclume.jwt;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Webhook signatures as GitHub and Stripe make them, computed here by the JDK. */
class SeclumeHmacTest {

    private static final String SECRET = "whsec_0123456789abcdef0123456789abcdef";
    private static final byte[] BODY = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);

    private static byte[] jdkMac(byte[]... parts) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
        for (byte[] part : parts) {
            mac.update(part);
        }
        return mac.doFinal();
    }

    private static SeclumeHmac hmac(Path dir) throws Exception {
        Path key = dir.resolve("whsec");
        Files.writeString(key, SECRET);
        return SeclumeHmac.of("SHA256?provider=file&path=" + key.toString().replace('\\', '/'));
    }

    @Test
    void github(@TempDir Path dir) throws Exception {
        try (SeclumeHmac hmac = hmac(dir)) {
            String header = "sha256=" + HexFormat.of().formatHex(jdkMac(BODY));
            assertTrue(hmac.verifyGitHub(header, BODY));
            assertTrue(hmac.verifyGitHub(header.toUpperCase().replace("SHA256=", "sha256="), BODY));
            assertFalse(hmac.verifyGitHub(header, "{\"action\":\"closed\"}".getBytes()));
            assertFalse(hmac.verifyGitHub("sha1=" + header.substring(7), BODY));
            assertFalse(hmac.verifyGitHub("sha256=zz", BODY));
            assertFalse(hmac.verifyGitHub(null, BODY));
            assertTrue(hmac.verifyBase64(Base64.getEncoder().encodeToString(jdkMac(BODY)), BODY));
        }
    }

    @Test
    void stripe(@TempDir Path dir) throws Exception {
        try (SeclumeHmac hmac = hmac(dir)) {
            hmac.clock(Clock.fixed(Instant.ofEpochSecond(1_700_000_100), ZoneOffset.UTC));
            String t = "1700000000";
            String v1 = HexFormat.of().formatHex(jdkMac((t + ".").getBytes(), BODY));
            String header = "t=" + t + ",v1=deadbeef,v1=" + v1 + ",v0=ignored";
            assertTrue(hmac.verifyStripe(header, BODY, Duration.ofMinutes(5)));
            assertFalse(hmac.verifyStripe(header, BODY, Duration.ofSeconds(30)), "too old");
            assertFalse(hmac.verifyStripe("t=1700000001,v1=" + v1, BODY, Duration.ofMinutes(5)));
            assertFalse(hmac.verifyStripe("v1=" + v1, BODY, Duration.ofMinutes(5)));
        }
    }
}

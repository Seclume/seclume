package space.seclume.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

/**
 * The AWS IAM login body at the sizes it makes room for: a session token of
 * kilobytes full of characters JSON escapes, a long role, a long Vault server
 * id and a long regional STS host - written without running out of room, and
 * signed as AWS's specification computes it with the JDK's crypto. Written
 * against the mutants PIT left alive in this package, which shrank the rooms.
 */
class VaultAwsLoginEdgesTest {

    private static final Instant NOW = Instant.parse("2026-11-06T09:30:00Z");
    private static final String KEY_ID = "AKIAEDGESEXAMPLE0001";
    private static final String SECRET_KEY = "edges/K7MDENG/bPxRfiCYEXAMPLEKEYedges0001";

    private static SecretProvider fixed(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return new CallbackSecretProvider(16_384, target -> {
            MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
            return bytes.length;
        });
    }

    private static Map<String, String> fields(String json) {
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher m = Pattern.compile("\"([^\"]+)\":\"((?:[^\"\\\\]++|\\\\.)*+)\"").matcher(json);
        while (m.find()) {
            fields.put(m.group(1), m.group(2).replace("\\\"", "\"").replace("\\\\", "\\"));
        }
        return fields;
    }

    private static String b64(String encoded) {
        return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String text) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8)));
    }

    private static String expectedAuthorization(Map<String, String> headers, String region) throws Exception {
        TreeMap<String, String> canonical = new TreeMap<>();
        headers.forEach((name, value) -> {
            if (!name.equalsIgnoreCase("Authorization")) {
                canonical.put(name.toLowerCase(Locale.ROOT), value.trim());
            }
        });
        StringBuilder request = new StringBuilder("POST\n/\n\n");
        canonical.forEach((name, value) -> request.append(name).append(':').append(value).append('\n'));
        String signed = String.join(";", canonical.keySet());
        request.append('\n').append(signed).append('\n').append(sha256("Action=GetCallerIdentity&Version=2011-06-15"));
        String date = headers.get("X-Amz-Date");
        String day = date.substring(0, 8);
        String scope = day + "/" + region + "/sts/aws4_request";
        String toSign = "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + sha256(request.toString());
        byte[] key = hmac(("AWS4" + SECRET_KEY).getBytes(StandardCharsets.UTF_8), day);
        key = hmac(key, region);
        key = hmac(key, "sts");
        key = hmac(key, "aws4_request");
        return "AWS4-HMAC-SHA256 Credential=" + KEY_ID + "/" + scope + ", SignedHeaders=" + signed + ", Signature="
                + HexFormat.of().formatHex(hmac(key, toSign));
    }

    private static Map<String, String> body(VaultLoginBody.AwsIam login) {
        try (Arena arena = Arena.ofConfined(); SecretScope written = login.write(arena)) {
            return fields(new String(written.segment().asSlice(0, written.length()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8));
        }
    }

    @Test
    void longTokensRolesServerIdsAndHostsFitTheirRoomAndAreSignedRight() throws Exception {
        String token = "IQoJb3JpZ2luX2Vj\"quoted\\slashed/" .repeat(160);       // 5 KiB, a third of it escaped
        String role = "r".repeat(250);
        String serverId = "vault-" + "s".repeat(500) + ".example.com";
        String host = "sts." + "eu-central-1" + ".amazonaws.com";
        VaultLoginBody.AwsIam login = new VaultLoginBody.AwsIam(role,
                VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY), fixed(token)), host, "eu-central-1",
                serverId, Clock.fixed(NOW, ZoneOffset.UTC));
        Map<String, String> body = body(login);
        assertEquals(role, body.get("role"));
        assertEquals("https://" + host + "/", b64(body.get("iam_request_url")));
        assertEquals("Action=GetCallerIdentity&Version=2011-06-15", b64(body.get("iam_request_body")));
        Map<String, String> headers = fields(b64(body.get("iam_request_headers")));
        assertEquals(token, headers.get("X-Amz-Security-Token"), "the whole token, its escapes undone");
        assertEquals(serverId, headers.get("X-Vault-AWS-IAM-Server-ID"));
        assertEquals(host, headers.get("Host"));
        assertEquals("20261106T093000Z", headers.get("X-Amz-Date"));
        assertEquals(expectedAuthorization(headers, "eu-central-1"), headers.get("Authorization"));
    }

    @Test
    void withoutATokenARoleOrAServerIdTheirFieldsAreNotThere() throws Exception {
        VaultLoginBody.AwsIam login = new VaultLoginBody.AwsIam(null,
                VaultLoginBody.AwsIam.Credentials.of(KEY_ID, fixed(SECRET_KEY), null), "sts.amazonaws.com",
                "us-east-1", "  ", Clock.fixed(NOW, ZoneOffset.UTC));
        Map<String, String> body = body(login);
        assertFalse(body.containsKey("role"));
        Map<String, String> headers = fields(b64(body.get("iam_request_headers")));
        assertFalse(headers.containsKey("X-Amz-Security-Token"));
        assertFalse(headers.containsKey("X-Vault-AWS-IAM-Server-ID"), "a blank server id is none");
        assertEquals(expectedAuthorization(headers, "us-east-1"), headers.get("Authorization"));
    }
}

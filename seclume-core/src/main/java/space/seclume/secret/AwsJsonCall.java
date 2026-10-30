package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.seclume.internal.AwsSigV4;
import space.seclume.internal.CanonicalRequest;
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * One request to an AWS JSON 1.1 API - Secrets Manager, KMS - signed with
 * SigV4: {@code POST /} with the operation in {@code X-Amz-Target}.
 *
 * <p>The secret access key stays inside {@link AwsSigV4#sign}; a session token,
 * which is signed as well as sent, goes into a canonical request assembled in
 * native memory ({@link CanonicalRequest}) and onto the wire from there. After
 * the canonical request's hash everything is public again.
 */
final class AwsJsonCall {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-target";
    /** Alphabetical, so the token sits between the date and the target. */
    private static final String SIGNED_HEADERS_WITH_TOKEN =
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final String region;
    private final String service;
    private final Clock clock;

    AwsJsonCall(String host, int port, boolean verify, int timeoutMillis, String region,
            String service, Clock clock) {
        this.host = host;
        this.port = port;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.region = region;
        this.service = service;
        this.clock = clock;
    }

    String host() {
        return host;
    }

    /**
     * Sends {@code body} as the operation {@code target}, signed with
     * {@code key} for {@code keyId}, and writes the answer into {@code answer}.
     *
     * @param session where the session token comes from, or {@code null} for a
     *                long-term key - read afresh for every request, because a
     *                session token expires and its provider is where a newer one
     *                appears
     */
    SecretFetch.Response send(String target, String body, String keyId, SecretProvider key,
            SecretProvider session, MemorySegment answer) throws IOException {
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);
        try (Arena arena = Arena.ofConfined();
             SecretScope token = session == null ? null : SecretScope.fromProvider(session)) {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", CONTENT_TYPE);
            headers.put("X-Amz-Date", stamp);
            headers.put("X-Amz-Target", target);
            headers.put("Authorization",
                    authorization(arena, target, body, stamp, day, token, keyId, key));
            return SecretFetch.send(host, port, verify, timeoutMillis, "POST", "/", headers,
                    token == null ? List.of() : List.of(new SecretFetch.SecretHeader(
                            "X-Amz-Security-Token", token.secret(), token.length())),
                    body, answer);
        }
    }

    /**
     * The {@code Authorization} header, built the way SigV4 prescribes.
     *
     * <p>Nothing in the canonical request is secret but the session token: it
     * is the request that goes over the wire in the clear. The signing key
     * stays inside {@link AwsSigV4#sign}.
     */
    private String authorization(Arena arena, String target, String body, String stamp,
            String day, SecretScope token, String keyId, SecretProvider key) {
        String scope = AwsSigV4.scope(day, region, service);
        String signedHeaders = token == null ? SIGNED_HEADERS : SIGNED_HEADERS_WITH_TOKEN;

        // Assembled in native memory rather than concatenated, because with
        // temporary credentials one of these lines is the session token -
        // and a token that is signed as well as sent would otherwise spend
        // the request on the heap. Everything after the hash is public
        // again, so only this part has to be careful.
        String canonicalHash;
        try (CanonicalRequest canonical = new CanonicalRequest(arena,
                canonicalCapacity(target, token))) {
            canonical.text("POST\n/\n\n")
                    .text("content-type:" + CONTENT_TYPE + "\n")
                    .text("host:" + host + "\n")
                    .text("x-amz-date:" + stamp + "\n");
            if (token != null) {
                // Alphabetical, which puts it before x-amz-target. Headers
                // out of order sign perfectly cleanly and are rejected by
                // AWS with nothing in the answer that says why.
                canonical.text("x-amz-security-token:");
                canonical.secret(token.secret(), token.length());
                canonical.text("\n");
            }
            canonical.text("x-amz-target:" + target + "\n\n")
                    .text(signedHeaders + "\n")
                    .text(AwsSigV4.sha256Hex(body));
            canonicalHash = canonical.sha256Hex();
        }

        String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n" + canonicalHash;

        MemorySegment signature;
        try {
            signature = AwsSigV4.sign(arena, key::writeSecret, toSign, day, region, service);
        } catch (IllegalStateException empty) {
            throw new SecretUnavailableException("the AWS secret key source gave nothing - "
                    + "the request to " + service + " cannot be signed without it", empty);
        }
        return AwsSigV4.ALGORITHM + " Credential=" + keyId + "/" + scope
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + AwsSigV4.hex(signature);
    }

    /**
     * Room for the canonical request, with the token if there is one.
     *
     * <p>Generous on purpose: running out would mean an exception in the
     * middle of assembling something that has a credential in it, and the
     * memory is freed a few microseconds later either way.
     */
    private int canonicalCapacity(String target, SecretScope token) {
        return 512 + host.length() + target.length()
                + (token == null ? 0 : token.length() + 32);
    }

    /** {@code __type} and {@code message} of an error answer - public text, never a secret. */
    static String reason(MemorySegment body, int length) {
        StringBuilder said = new StringBuilder(); // seclume-allow: an error answer, which holds no secret
        for (String key : new String[] {"__type", "message", "Message"}) {
            try (Arena scratch = Arena.ofConfined()) {
                MemorySegment out = scratch.allocate(300);
                int n = JsonOff.string(body, length, out, key);
                for (int i = 0; i < n; i++) {
                    char c = (char) (out.get(java.lang.foreign.ValueLayout.JAVA_BYTE, i) & 0xff);
                    said.append(c >= 0x20 && c < 0x7f ? c : '?');
                }
                said.append(' ');
            } catch (RuntimeException absent) {
                // not in this answer
            }
        }
        return said.length() == 0 ? "no reason given" : said.toString().trim();
    }
}

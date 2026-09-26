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
import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * A secret from AWS Secrets Manager, read without it becoming a {@code String}.
 *
 * <p>The AWS SDK returns {@code GetSecretValueResponse.secretString()}. That
 * is a {@code String}, built from a {@code byte[]} the SDK decoded from a
 * buffer it read from a socket - three copies of the password on the heap
 * before an application has seen it, and none of them wipeable. The SDK is
 * also forty megabytes of dependency for one HTTPS request.
 *
 * <p>So the request is signed here with {@link AwsSigV4} - the same four HMACs
 * {@link RdsIamSecretProvider} uses, and the same property that the AWS secret
 * key never leaves native memory - and the answer is read by {@link JsonOff}
 * straight out of the buffer it landed in.
 *
 * <h2>{@code SecretString} is usually JSON</h2>
 *
 * <p>The convention AWS itself pushes is to store
 * {@code {"username":"app","password":"..."}} in one secret. So {@code field}
 * says which key of that inner document is wanted; without it the whole
 * {@code SecretString} is the secret, which is right for a secret that holds
 * just a password. The inner document is parsed in the same segment the outer
 * one was unescaped into - no string in between.
 *
 * <h2>Temporary credentials</h2>
 *
 * <p>Session tokens work - STS, IRSA, an instance role - and getting there
 * took a piece of work worth knowing about, because for a while this class
 * said they did not.
 *
 * <p>A session token is not merely sent as {@code X-Amz-Security-Token}, it
 * is <b>signed</b>: it appears inside the canonical request, which was an
 * ordinary concatenated {@code String}. Supporting tokens that way would
 * have put a credential on the heap in the one class whose job is to keep it
 * off, so the gap was documented rather than quietly closed. The answer was
 * to assemble the canonical request in native memory - see
 * {@link space.seclume.internal.CanonicalRequest} - after which its SHA-256
 * is a public hex digest and everything above that line can go back to being
 * text. The token reaches the wire as a {@link SecretFetch.SecretHeader},
 * which was already segment-valued.
 *
 * <p>It is read afresh for every request, because a session token expires
 * and the provider behind it is where a newer one appears.
 */
public final class AwsSecretsManagerSecretProvider implements SecretProvider {

    private static final String SERVICE = "secretsmanager";
    private static final String TARGET = "secretsmanager.GetSecretValue";
    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-target";
    /** Alphabetical, so the token sits between the date and the target. */
    private static final String SIGNED_HEADERS_WITH_TOKEN =
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private final SecretProvider awsSecretKey;
    /**
     * Where the session token comes from, or {@code null} for long-term keys.
     *
     * <p>Read afresh for every request, unlike the access key id beside it:
     * a session token expires, and the point of reading it from a provider
     * is that the file or the agent behind it can hand out a newer one
     * without this object being rebuilt.
     */
    private final SecretProvider sessionToken;
    private final String accessKeyId;
    private final String region;
    private final String secretId;
    private final String field;
    private final String host;
    private final int port;
    private final boolean verify;
    private final int timeoutMillis;
    private final int maxLength;
    private final Clock clock;

    /**
     * @param awsSecretKey where the AWS secret access key comes from
     * @param accessKeyId  the public half; not a secret
     * @param region       for example {@code eu-central-1}
     * @param secretId     the secret's name or ARN
     * @param field        a key inside the secret's JSON, or {@code null} to
     *                     take the whole {@code SecretString}
     */
    public AwsSecretsManagerSecretProvider(SecretProvider awsSecretKey, String accessKeyId,
            String region, String secretId, String field, int maxLength) {
        this(awsSecretKey, null, accessKeyId, region, secretId, field, maxLength);
    }

    /**
     * The same with temporary credentials.
     *
     * @param sessionToken where the session token comes from, or {@code null}
     *                     for a long-term access key. The token is signed as
     *                     well as sent, and it never becomes a Java object on
     *                     either path - see {@link CanonicalRequest}
     */
    public AwsSecretsManagerSecretProvider(SecretProvider awsSecretKey,
            SecretProvider sessionToken, String accessKeyId, String region, String secretId,
            String field, int maxLength) {
        this(awsSecretKey, sessionToken, accessKeyId, region, secretId, field,
                SERVICE + "." + region + ".amazonaws.com", 443, true, 10_000, maxLength,
                Clock.systemUTC());
    }

    /** The same with the endpoint and clock under the caller's control - for tests. */
    public AwsSecretsManagerSecretProvider(SecretProvider awsSecretKey, String accessKeyId,
            String region, String secretId, String field, String host, int port, boolean verify,
            int timeoutMillis, int maxLength, Clock clock) {
        this(awsSecretKey, null, accessKeyId, region, secretId, field, host, port, verify,
                timeoutMillis, maxLength, clock);
    }

    /** The whole of it - for tests and for temporary credentials. */
    public AwsSecretsManagerSecretProvider(SecretProvider awsSecretKey,
            SecretProvider sessionToken, String accessKeyId, String region, String secretId,
            String field, String host, int port, boolean verify, int timeoutMillis,
            int maxLength, Clock clock) {
        this.awsSecretKey = awsSecretKey;
        this.sessionToken = sessionToken;
        this.accessKeyId = accessKeyId;
        this.region = region;
        this.secretId = secretId;
        this.field = field;
        this.host = host;
        this.port = port;
        this.verify = verify;
        this.timeoutMillis = timeoutMillis;
        this.maxLength = maxLength;
        this.clock = clock;
    }

    @Override
    public int maxSecretLength() {
        return maxLength;
    }

    /**
     * The same with the credentials of the EC2 instance's role - see
     * {@link AwsInstanceRole}.
     */
    public AwsSecretsManagerSecretProvider(AwsInstanceRole role, String region, String secretId,
            String field, int maxLength) {
        this(null, null, null, region, secretId, field, maxLength);
        this.role = role;
    }

    /** The instance role the credentials come from, or null for a key pair. */
    private AwsInstanceRole role;

    @Override
    public int writeSecret(MemorySegment target) {
        if (role != null) {
            return role.use((id, key, session) -> fetch(target, id, key, session));
        }
        return fetch(target, accessKeyId, awsSecretKey, sessionToken);
    }

    private int fetch(MemorySegment target, String keyId, SecretProvider key,
                      SecretProvider session) {
        String body = "{\"SecretId\":\"" + escape(secretId) + "\"}";
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);

        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE);
             // Temporary credentials only. Read afresh per request, because a
             // session token expires and the provider behind it is where a
             // newer one appears.
             SecretScope token = session == null ? null
                     : SecretScope.fromProvider(session)) {

            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    "POST", "/", headers(stamp,
                            authorization(arena, body, stamp, day, token, keyId, key)),
                    token == null ? List.of() : List.of(new SecretFetch.SecretHeader(
                            "X-Amz-Security-Token", token.secret(), token.length())),
                    body, answer.segment());
            if (!response.ok()) {
                // An error answer carries no secret, only AWS's reason - and
                // "400" alone hid which one: a signature, a missing secret and
                // a missing right all come back as 400 from this API.
                throw new SecretUnavailableException("AWS Secrets Manager answered "
                        + response.status() + " for " + secretId + ": "
                        + reason(answer.segment(), response.bodyLength()));
            }
            answer.length(response.bodyLength());

            try (SecretScope secretString = SecretScope.in(arena, maxLength)) {
                int length = JsonOff.string(answer.segment(), answer.length(),
                        secretString.segment(), "SecretString");
                secretString.length(length);
                if (field == null || field.isEmpty()) {
                    return copy(secretString, target);
                }
                // SecretString is itself a JSON document, and it is already
                // unescaped in this segment - so the inner parse runs on the
                // same native memory rather than on a String of it.
                return JsonOff.string(secretString.segment(), secretString.length(),
                        target, field);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException(
                    "cannot reach AWS Secrets Manager at " + host + ": " + e.getMessage(), e);
        } catch (JsonOff.NotFound e) {
            throw new SecretUnavailableException(
                    "AWS Secrets Manager answered, but not in a shape this understands: "
                    + e.getMessage(), e);
        }
    }

    /** {@code __type} and {@code message} of an error answer - public text, never a secret. */
    private static String reason(MemorySegment body, int length) {
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

    private static int copy(SecretScope from, MemorySegment target) {
        if (from.length() > target.byteSize()) {
            throw new SecretUnavailableException("the secret is " + from.length()
                    + " bytes and does not fit into the " + target.byteSize() + " provided");
        }
        MemorySegment.copy(from.segment(), 0, target, 0, from.length());
        return from.length();
    }

    private Map<String, String> headers(String stamp, String authorization) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", CONTENT_TYPE);
        headers.put("X-Amz-Date", stamp);
        headers.put("X-Amz-Target", TARGET);
        headers.put("Authorization", authorization);
        return headers;
    }

    /**
     * The {@code Authorization} header, built the way SigV4 prescribes.
     *
     * <p>Nothing in the canonical request is secret: it is the request that
     * goes over the wire in the clear. The only secret involved is the signing
     * key, and it stays inside {@link AwsSigV4#sign}.
     */
    private String authorization(Arena arena, String body, String stamp, String day,
            SecretScope token, String keyId, SecretProvider key) {
        String scope = AwsSigV4.scope(day, region, SERVICE);
        String signedHeaders = token == null ? SIGNED_HEADERS : SIGNED_HEADERS_WITH_TOKEN;

        // Assembled in native memory rather than concatenated, because with
        // temporary credentials one of these lines is the session token -
        // and a token that is signed as well as sent would otherwise spend
        // the request on the heap. Everything after the hash is public
        // again, so only this part has to be careful.
        String canonicalHash;
        try (space.seclume.internal.CanonicalRequest canonical =
                new space.seclume.internal.CanonicalRequest(arena, canonicalCapacity(token))) {
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
            canonical.text("x-amz-target:" + TARGET + "\n\n")
                    .text(signedHeaders + "\n")
                    .text(AwsSigV4.sha256Hex(body));
            canonicalHash = canonical.sha256Hex();
        }

        String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n" + canonicalHash;

        MemorySegment signature;
        try {
            signature = AwsSigV4.sign(arena, key::writeSecret, toSign, day, region, SERVICE);
        } catch (IllegalStateException empty) {
            throw new SecretUnavailableException("the AWS secret key source gave nothing - "
                    + "the request to Secrets Manager cannot be signed without it", empty);
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
    private int canonicalCapacity(SecretScope token) {
        return 512 + host.length() + TARGET.length()
                + (token == null ? 0 : token.length() + 32);
    }

    /** A secret's name may contain a slash or a colon, never a quote - but check. */
    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void close() {
        try {
            if (awsSecretKey != null) {
                awsSecretKey.close();       // null with an instance role
            }
        } finally {
            if (sessionToken != null) {
                sessionToken.close();
            }
        }
    }
}

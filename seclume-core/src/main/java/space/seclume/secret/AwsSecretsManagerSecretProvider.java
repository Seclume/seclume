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
 * <h2>What it does not do, and why</h2>
 *
 * <p><b>No session tokens</b> - only long-term access keys. A session token
 * (STS, IRSA, an instance role) has to be sent as {@code X-Amz-Security-Token}
 * <i>and</i> named in the signed headers, which means the token itself is part
 * of the canonical request: a string that is built, hashed and concatenated.
 * There is no way to sign it without putting it on the heap, and doing that
 * quietly would give up the guarantee in the one class whose job is to keep
 * it. Where only a session token is available, the honest answer today is
 * {@code rds-iam} for RDS, or a sidecar that writes the secret to a file this
 * library can read.
 */
public final class AwsSecretsManagerSecretProvider implements SecretProvider {

    private static final String SERVICE = "secretsmanager";
    private static final String TARGET = "secretsmanager.GetSecretValue";
    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-target";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private final SecretProvider awsSecretKey;
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
        this(awsSecretKey, accessKeyId, region, secretId, field,
                SERVICE + "." + region + ".amazonaws.com", 443, true, 10_000, maxLength,
                Clock.systemUTC());
    }

    /** The same with the endpoint and clock under the caller's control - for tests. */
    public AwsSecretsManagerSecretProvider(SecretProvider awsSecretKey, String accessKeyId,
            String region, String secretId, String field, String host, int port, boolean verify,
            int timeoutMillis, int maxLength, Clock clock) {
        this.awsSecretKey = awsSecretKey;
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

    @Override
    public int writeSecret(MemorySegment target) {
        String body = "{\"SecretId\":\"" + escape(secretId) + "\"}";
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);

        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {

            SecretFetch.Response response = SecretFetch.send(host, port, verify, timeoutMillis,
                    "POST", "/", headers(stamp, authorization(arena, body, stamp, day)),
                    List.of(), body, answer.segment());
            if (!response.ok()) {
                throw new SecretUnavailableException("AWS Secrets Manager answered "
                        + response.status() + " for " + secretId + ". 400 usually means the "
                        + "secret does not exist, 403 that the key may not read it");
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
    private String authorization(Arena arena, String body, String stamp, String day) {
        String scope = AwsSigV4.scope(day, region, SERVICE);
        String canonical = "POST\n/\n\n"
                + "content-type:" + CONTENT_TYPE + "\n"
                + "host:" + host + "\n"
                + "x-amz-date:" + stamp + "\n"
                + "x-amz-target:" + TARGET + "\n\n"
                + SIGNED_HEADERS + "\n"
                + AwsSigV4.sha256Hex(body);
        String toSign = AwsSigV4.ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                + AwsSigV4.sha256Hex(canonical);

        MemorySegment signature;
        try {
            signature = AwsSigV4.sign(arena, awsSecretKey::writeSecret, toSign, day, region,
                    SERVICE);
        } catch (IllegalStateException empty) {
            throw new SecretUnavailableException("the AWS secret key source gave nothing - "
                    + "the request to Secrets Manager cannot be signed without it", empty);
        }
        return AwsSigV4.ALGORITHM + " Credential=" + accessKeyId + "/" + scope
                + ", SignedHeaders=" + SIGNED_HEADERS
                + ", Signature=" + AwsSigV4.hex(signature);
    }

    /** A secret's name may contain a slash or a colon, never a quote - but check. */
    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void close() {
        awsSecretKey.close();
    }
}

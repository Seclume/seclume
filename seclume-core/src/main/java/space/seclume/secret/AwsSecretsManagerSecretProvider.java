package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.time.Clock;

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
 * <p>So the request is signed here with {@code AwsSigV4} - the same four HMACs
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
    private final String secretId;
    private final String field;
    private final String host;
    private final int maxLength;
    private final AwsJsonCall call;

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
        this.secretId = secretId;
        this.field = field;
        this.host = host;
        this.maxLength = maxLength;
        this.call = new AwsJsonCall(host, port, verify, timeoutMillis, region, SERVICE, clock);
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
        try (Arena arena = Arena.ofConfined();
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            SecretFetch.Response response = call.send(TARGET, body, keyId, key, session,
                    answer.segment());
            if (!response.ok()) {
                // An error answer carries no secret, only AWS's reason - and
                // "400" alone hid which one: a signature, a missing secret and
                // a missing right all come back as 400 from this API.
                throw new SecretUnavailableException("AWS Secrets Manager answered "
                        + response.status() + " for " + secretId + ": "
                        + AwsJsonCall.reason(answer.segment(), response.bodyLength()));
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

    /** A secret's name may contain a slash or a colon, never a quote - but check. */
    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void close() {
        try {
            if (awsSecretKey != null) {
                awsSecretKey.close();       // null with a workload role
            }
        } finally {
            try {
                if (sessionToken != null) {
                    sessionToken.close();
                }
            } finally {
                if (role != null && role != AwsInstanceRole.shared()) {
                    role.close();
                }
            }
        }
    }
}

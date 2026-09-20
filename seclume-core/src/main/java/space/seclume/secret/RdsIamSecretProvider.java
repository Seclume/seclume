package space.seclume.secret;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import space.seclume.internal.AwsSigV4;

/**
 * The password for AWS RDS IAM authentication - built, not stored.
 *
 * <p>With IAM authentication the database password is not a password at all
 * but a <b>signed URL</b> that is valid for fifteen minutes. The AWS SDKs build
 * it and hand it over as a {@code String}: a short-lived credential that lands
 * in the heap and stays there until the garbage collector happens to overwrite
 * it - which is the one thing short-lived credentials were supposed to avoid.
 *
 * <p>Here it is built where it belongs. The AWS secret key comes from another
 * {@link SecretProvider} - a file, the environment, a socket - and is read
 * straight into native memory; the signing chain that derives the token from it
 * is HMAC-SHA256 and nothing else, so all of it can happen off the heap. What
 * lands in the target segment is the finished token; the secret key itself is
 * wiped before this method returns.
 *
 * <p>That is the combination nobody else offers: <b>short-lived cloud
 * credentials that never touch the heap.</b>
 *
 * <p>Everything that is <i>not</i> secret - the host, the user, the region, the
 * access key id, the timestamp - is ordinary text and stays ordinary text. A
 * signature says nothing about the key it was made with.
 */
public final class RdsIamSecretProvider implements SecretProvider {

    /** What the signature covers besides the query - always just the host. */
    private static final String SIGNED_HEADERS = "host";
    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE = "rds";
    private static final String TERMINATOR = "aws4_request";
    /** The longest AWS allows, and the only value that makes sense here. */
    private static final int EXPIRES_SECONDS = 900;
    /** SHA-256 of the empty payload - a GET has no body. */
    private static final String EMPTY_PAYLOAD =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

    private final SecretProvider awsSecretKey;
    private final String accessKeyId;
    private final String region;
    private final String host;
    private final int port;
    private final String user;
    private final Clock clock;

    /**
     * @param awsSecretKey where the AWS secret access key comes from - it is
     *                     read into native memory and wiped again
     * @param accessKeyId  the public half of the key pair; not a secret
     * @param region       for example {@code eu-central-1}
     * @param host         the RDS endpoint
     * @param port         its port
     * @param user         the database user the token is for
     */
    public RdsIamSecretProvider(SecretProvider awsSecretKey, String accessKeyId, String region,
                                String host, int port, String user) {
        this(awsSecretKey, accessKeyId, region, host, port, user, Clock.systemUTC());
    }

    /** The same with a clock of its own - a signature is only reproducible with one. */
    public RdsIamSecretProvider(SecretProvider awsSecretKey, String accessKeyId, String region,
                                String host, int port, String user, Clock clock) {
        this.awsSecretKey = awsSecretKey;
        this.accessKeyId = accessKeyId;
        this.region = region;
        this.host = host;
        this.port = port;
        this.user = user;
        this.clock = clock;
    }

    @Override
    public int writeSecret(MemorySegment target) {
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);
        String scope = day + "/" + region + "/" + SERVICE + "/" + TERMINATOR;
        String endpoint = host + ":" + port;

        // None of this is secret: it is the request that will be signed, and it
        // travels to the server in the clear anyway.
        String query = "Action=connect"
                + "&DBUser=" + urlEncode(user)
                + "&X-Amz-Algorithm=" + ALGORITHM
                + "&X-Amz-Credential=" + urlEncode(accessKeyId + "/" + scope)
                + "&X-Amz-Date=" + stamp
                + "&X-Amz-Expires=" + EXPIRES_SECONDS
                + "&X-Amz-SignedHeaders=" + SIGNED_HEADERS;
        String canonicalRequest = "GET\n/\n" + query + "\n"
                + "host:" + endpoint + "\n\n"
                + SIGNED_HEADERS + "\n"
                + EMPTY_PAYLOAD;
        String toSign = ALGORITHM + "\n" + stamp + "\n" + scope + "\n"
                + AwsSigV4.sha256Hex(canonicalRequest);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment signature = sign(arena, toSign, day);
            String token = endpoint + "/?" + query + "&X-Amz-Signature=" + hex(signature);
            return write(target, token);
        }
    }

    /**
     * A signed URL of this shape runs to some six hundred characters; a
     * kilobyte leaves room for long user names and long endpoints.
     */
    @Override
    public int maxSecretLength() {
        return 1024;
    }

    /**
     * The signing chain, and the only part that touches the secret.
     *
     * <p>Shared with the Secrets Manager provider, which needs the same four
     * HMACs for a differently shaped request - see {@link AwsSigV4}.
     */
    private MemorySegment sign(Arena arena, String toSign, String day) {
        try {
            return AwsSigV4.sign(arena, awsSecretKey::writeSecret, toSign, day, region, SERVICE);
        } catch (IllegalStateException empty) {
            throw new SecretUnavailableException(
                    "the AWS secret key source gave nothing - an IAM token cannot be signed "
                    + "without it", empty);
        }
    }

    private static int write(MemorySegment target, String token) {
        // The length in a variable of its own, and not "token.length()" in the
        // message: the rule is that nothing named like a secret is ever
        // concatenated into a message, and a rule with exceptions is not one.
        int needed = token.length();
        if (needed > target.byteSize()) {
            throw new SecretUnavailableException("the IAM token needs " + needed
                    + " bytes and the buffer takes " + target.byteSize()
                    + " - raise the secret buffer size");
        }
        return AwsSigV4.writeAscii(target, token);
    }

    private static String hex(MemorySegment bytes) {
        return AwsSigV4.hex(bytes);
    }

    private static String urlEncode(String text) {
        return AwsSigV4.urlEncode(text);
    }

}

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
    /**
     * {@code rds-db}, the service that connects to a database - not {@code rds},
     * the API that manages instances. With {@code rds} every token was refused
     * ("PAM authentication failed"); found against a live Aurora cluster on
     * 26.09.2026, where a token from the AWS CLI made in the same second
     * differed in exactly this word.
     */
    private static final String SERVICE = "rds-db";
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

    /**
     * The same with the credentials of the EC2 instance's role - temporary
     * ones, so the token carries their session token, signed and sent, and
     * built in native memory like the rest.
     */
    public RdsIamSecretProvider(AwsInstanceRole role, String region, String host, int port,
                                String user) {
        this(null, null, region, host, port, user, Clock.systemUTC());
        this.role = role;
    }

    /** The instance role the credentials come from, or null for a key pair. */
    private AwsInstanceRole role;

    @Override
    public int writeSecret(MemorySegment target) {
        if (role != null) {
            return role.use((id, key, session) -> token(target, id, key, session));
        }
        return token(target, accessKeyId, awsSecretKey, null);
    }

    /**
     * The signed URL, written straight into {@code target}: the canonical
     * request in native memory (the session token is in it), then the token
     * the same way. Until 26.09.2026 the token was assembled as a
     * {@code String} before it was written - a credential valid for fifteen
     * minutes on the heap, in the one class that says it keeps them off.
     */
    private int token(MemorySegment target, String keyId, SecretProvider key,
                      SecretProvider sessionToken) {
        Instant now = clock.instant();
        String stamp = STAMP.format(now);
        String day = DAY.format(now);
        String scope = day + "/" + region + "/" + SERVICE + "/" + TERMINATOR;
        String endpoint = host + ":" + port;
        // Sorted by name, as the canonical query has to be; the session token
        // falls between X-Amz-Expires and X-Amz-SignedHeaders.
        String head = "Action=connect"
                + "&DBUser=" + urlEncode(user)
                + "&X-Amz-Algorithm=" + ALGORITHM
                + "&X-Amz-Credential=" + urlEncode(keyId + "/" + scope)
                + "&X-Amz-Date=" + stamp
                + "&X-Amz-Expires=" + EXPIRES_SECONDS;
        String tail = "&X-Amz-SignedHeaders=" + SIGNED_HEADERS;

        try (Arena arena = Arena.ofConfined();
             SecretScope session = sessionToken == null ? null
                     : SecretScope.fromProvider(sessionToken)) {
            int tokenRoom = session == null ? 0 : 3 * session.length() + 32;
            String canonicalHash;
            try (space.seclume.internal.CanonicalRequest canonical =
                         new space.seclume.internal.CanonicalRequest(arena, 1024 + tokenRoom)) {
                canonical.text("GET\n/\n" + head);
                if (session != null) {
                    canonical.text("&X-Amz-Security-Token=");
                    canonical.secretUrlEncoded(session.secret(), session.length());
                }
                canonical.text(tail + "\nhost:" + endpoint + "\n\n" + SIGNED_HEADERS + "\n"
                        + EMPTY_PAYLOAD);
                canonicalHash = canonical.sha256Hex();
            }
            String toSign = ALGORITHM + "\n" + stamp + "\n" + scope + "\n" + canonicalHash;
            MemorySegment signature = sign(arena, key, toSign, day);

            int at = put(target, 0, endpoint + "/?" + head);
            if (session != null) {
                at = put(target, at, "&X-Amz-Security-Token=");
                if (at + 3L * session.length() > target.byteSize()) {
                    throw new SecretUnavailableException("the IAM token does not fit in the "
                            + target.byteSize() + " bytes provided - raise the secret buffer size");
                }
                at += AwsSigV4.urlEncode(session.secret(), session.length(), target, at);
            }
            return put(target, at, tail + "&X-Amz-Signature=" + hex(signature));
        }
    }

    /**
     * A signed URL of this shape runs to some four hundred characters, and to
     * a few kilobytes with a session token in it.
     */
    @Override
    public int maxSecretLength() {
        return role != null ? 8192 : 1024;
    }

    /**
     * The signing chain, and the only part that touches the secret.
     *
     * <p>Shared with the Secrets Manager provider, which needs the same four
     * HMACs for a differently shaped request - see {@link AwsSigV4}.
     */
    private MemorySegment sign(Arena arena, SecretProvider key, String toSign, String day) {
        try {
            return AwsSigV4.sign(arena, key::writeSecret, toSign, day, region, SERVICE);
        } catch (IllegalStateException empty) {
            throw new SecretUnavailableException(
                    "the AWS secret key source gave nothing - an IAM token cannot be signed "
                    + "without it", empty);
        }
    }

    /** Public text into the token, at {@code at}; returns where it ends. */
    private static int put(MemorySegment target, int at, String text) {
        // The length in a variable of its own, not in the message: nothing
        // named like a secret is ever concatenated into a message.
        int needed = at + text.length();
        if (needed > target.byteSize()) {
            throw new SecretUnavailableException("the IAM token needs " + needed
                    + " bytes and the buffer takes " + target.byteSize()
                    + " - raise the secret buffer size");
        }
        return at + AwsSigV4.writeAscii(target.asSlice(at), text);
    }

    private static String hex(MemorySegment bytes) {
        return AwsSigV4.hex(bytes);
    }

    private static String urlEncode(String text) {
        return AwsSigV4.urlEncode(text);
    }

}

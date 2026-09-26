package space.seclume.secret;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import space.seclume.internal.JsonOff;
import space.seclume.internal.SecretFetch;

/**
 * The AWS credentials of the EC2 instance this runs on - its instance role,
 * fetched from the instance metadata service (IMDSv2) - instead of a key pair
 * written into a file.
 *
 * <pre>
 *   provider=rds-iam&amp;credentials=instance&amp;region=...&amp;host=...&amp;port=...&amp;db-user=...
 *   provider=aws-secrets-manager&amp;credentials=instance&amp;region=...&amp;secret-id=...
 * </pre>
 *
 * <p>That is how applications on AWS are meant to be given credentials: none
 * stored anywhere, short-lived ones handed out by the platform and renewed
 * behind the application's back. What the metadata service hands out is an
 * access key id (public), a secret access key and a session token. The
 * last two are read straight into native memory and never become Java
 * objects - the session token is the more dangerous of them, valid for
 * hours and for every AWS API the role may call. The metadata service's own
 * session token travels the same way.
 *
 * <p>Kept until five minutes before they expire, then fetched again. One per
 * process: every connection of every pool uses the same role.
 */
public final class AwsInstanceRole {

    /** The metadata service's address; link-local, it answers only on this machine. */
    static final String HOST = "169.254.169.254";
    private static final long MARGIN_SECONDS = 300;
    private static final int TOKEN_ROOM = 4096;

    private static final AwsInstanceRole SHARED = new AwsInstanceRole(HOST, 80, 2000);

    private final String host;
    private final int port;
    private final int timeoutMillis;

    private String accessKeyId;
    private SecretScope secretKey;
    private SecretScope sessionToken;
    private Instant expires = Instant.EPOCH;

    AwsInstanceRole(String host, int port, int timeoutMillis) {
        this.host = host;
        this.port = port;
        this.timeoutMillis = timeoutMillis;
    }

    /** The role of the instance this process runs on. */
    public static AwsInstanceRole shared() {
        return SHARED;
    }

    /** What the credentials are used for, while they are valid - see {@link #use}. */
    @FunctionalInterface
    public interface Use<T> {
        T with(String accessKeyId, SecretProvider secretKey, SecretProvider sessionToken);
    }

    /**
     * Runs {@code use} with the current credentials, fetching them first if
     * they are missing or about to expire. The two providers it is given read
     * from this object's native memory and are good only during the call.
     */
    public synchronized <T> T use(Use<T> use) {
        if (secretKey == null || Instant.now().isAfter(expires.minusSeconds(MARGIN_SECONDS))) {
            refresh();
        }
        return use.with(accessKeyId, view(secretKey), view(sessionToken));
    }

    private static SecretProvider view(SecretScope scope) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (scope.length() > target.byteSize()) {
                    throw new SecretUnavailableException("the instance role's credential is "
                            + scope.length() + " bytes and does not fit");
                }
                MemorySegment.copy(scope.segment(), 0, target, 0, scope.length());
                return scope.length();
            }

            @Override
            public int maxSecretLength() {
                return scope.length();
            }
        };
    }

    private void refresh() {
        try (Arena arena = Arena.ofConfined();
             SecretScope imdsToken = SecretScope.in(arena, 256);
             SecretScope answer = SecretScope.in(arena, SecretFetch.MAX_RESPONSE)) {
            // IMDSv2: a session with the metadata service first. The token it
            // gives is sent back as a header on every question - and it too
            // stays out of the heap.
            SecretFetch.Response session = SecretFetch.sendLinkLocal(host, port, timeoutMillis,
                    "PUT", "/latest/api/token",
                    Map.of("X-aws-ec2-metadata-token-ttl-seconds", "300", "Content-Length", "0"),
                    imdsToken.segment());
            if (!session.ok()) {
                throw new SecretUnavailableException("the instance metadata service refused a "
                        + "session (" + session.status() + ") - is this an EC2 instance with "
                        + "IMDSv2 reachable from here?");
            }
            imdsToken.length(session.bodyLength());
            List<SecretFetch.SecretHeader> asked = List.of(new SecretFetch.SecretHeader(
                    "X-aws-ec2-metadata-token", imdsToken.secret(), imdsToken.length()));

            String base = "/latest/meta-data/iam/security-credentials/";
            SecretFetch.Response roles = SecretFetch.sendLinkLocal(host, port, timeoutMillis,
                    "GET", base, Map.of(), asked, answer.segment());
            if (!roles.ok() || roles.bodyLength() == 0) {
                throw new SecretUnavailableException("this instance has no role attached ("
                        + roles.status() + ") - attach one, or configure a key");
            }
            String role = ascii(answer.segment(), roles.bodyLength()).lines().findFirst()
                    .orElse("").trim();
            if (!role.matches("[A-Za-z0-9+=,.@_-]+")) {
                throw new SecretUnavailableException("the metadata service named no usable role");
            }

            answer.segment().fill((byte) 0);
            SecretFetch.Response credentials = SecretFetch.sendLinkLocal(host, port,
                    timeoutMillis, "GET", base + role, Map.of(), asked, answer.segment());
            if (!credentials.ok()) {
                throw new SecretUnavailableException("the metadata service did not hand out the "
                        + "credentials of " + role + " (" + credentials.status() + ")");
            }
            int length = credentials.bodyLength();
            SecretScope key = SecretScope.allocateShared(128);
            SecretScope token = SecretScope.allocateShared(TOKEN_ROOM);
            try {
                key.length(JsonOff.string(answer.segment(), length, key.segment(),
                        "SecretAccessKey"));
                token.length(JsonOff.string(answer.segment(), length, token.segment(), "Token"));
                String id = text(answer.segment(), length, "AccessKeyId");
                Instant until = Instant.parse(text(answer.segment(), length, "Expiration"));
                close();
                accessKeyId = id;
                secretKey = key;
                sessionToken = token;
                expires = until;
            } catch (RuntimeException e) {
                key.close();
                token.close();
                throw new SecretUnavailableException("the metadata service's answer for " + role
                        + " was not what was expected: " + e.getMessage(), e);
            }
        } catch (IOException e) {
            throw new SecretUnavailableException("cannot reach the instance metadata service at "
                    + host + ": " + e.getMessage(), e);
        }
    }

    /** A public field of the answer - the key id, the expiry. */
    private static String text(MemorySegment json, int length, String field) {
        try (Arena scratch = Arena.ofConfined()) {
            MemorySegment out = scratch.allocate(256);
            return ascii(out, JsonOff.string(json, length, out, field));
        }
    }

    private static String ascii(MemorySegment bytes, int length) {
        StringBuilder text = new StringBuilder(length); // seclume-allow: a role name, a key id or a date - public
        for (int i = 0; i < length; i++) {
            text.append((char) (bytes.get(ValueLayout.JAVA_BYTE, i) & 0x7f));
        }
        return text.toString();
    }

    /** Wipes what is kept. */
    synchronized void close() {
        if (secretKey != null) {
            secretKey.close();
            sessionToken.close();
            secretKey = null;
            sessionToken = null;
        }
    }
}

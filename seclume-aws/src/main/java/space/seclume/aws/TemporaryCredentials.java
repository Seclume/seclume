package space.seclume.aws;

import java.lang.foreign.MemorySegment;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat; // seclume-allow: a random nonce for the placeholder - public
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretScope;
import space.seclume.secret.SecretUnavailableException;

/**
 * Temporary AWS credentials - an access key id, a secret key and a session
 * token that expire together - held in native memory, and fetched again five
 * minutes before they expire.
 *
 * <p>Each set is a <b>generation</b> with a placeholder of its own. The SDK
 * holds the placeholder where the session token would be; the signer hashes
 * the real token into the canonical request, and {@link SessionTokenSocket}
 * writes it into the request's header - both find the generation by its
 * placeholder. A request signed a moment before a refresh is therefore sent
 * with the token it was signed with, not the new one; the last few
 * generations are kept for that.
 *
 * <p><b>Not asked more often than every few seconds.</b> A source may answer
 * with a set that is already inside those five minutes - the instance
 * metadata service hands out the old one until it has the next, a clock runs
 * ahead - and asked again for every request, each answer would be a new
 * generation and push out the one a request signed a moment ago is about to
 * be sent with. So whatever a source answered is lived with for
 * {@value #RETRY_SECONDS} seconds; and when it cannot be reached, the set at
 * hand is used for as long as it is valid.
 */
abstract class TemporaryCredentials {

    static final String TOKEN_PREFIX = "seclume-aws-session-token-";
    private static final long MARGIN_SECONDS = 300;
    private static final int KEPT = 3;
    /** How long a source is left alone after it was asked. */
    static final long RETRY_SECONDS = 5;
    private static final System.Logger LOG =
            System.getLogger(TemporaryCredentials.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String NONCE = HexFormat.of().formatHex(nonce()); // seclume-allow: a random nonce for the placeholder - public
    private static final Map<String, Generation> BY_PLACEHOLDER = new ConcurrentHashMap<>();

    private final Deque<Generation> generations = new ArrayDeque<>();
    private long next;
    /** The source is not asked again before this, whatever it answered. */
    private Instant askAgain = Instant.MIN;

    /** One set of credentials. */
    static final class Generation implements AutoCloseable {

        final String accessKeyId;
        final String placeholder;
        final Instant expires;
        final SecretScope secretKey;
        final SecretScope token;

        Generation(String accessKeyId, String placeholder, Instant expires, SecretScope secretKey,
                   SecretScope token) {
            this.accessKeyId = accessKeyId;
            this.placeholder = placeholder;
            this.expires = expires;
            this.secretKey = secretKey;
            this.token = token;
        }

        SecretProvider secretKeyProvider() {
            return view(secretKey);
        }

        @Override
        public void close() {
            BY_PLACEHOLDER.remove(placeholder);
            secretKey.close();
            token.close();
        }
    }

    /** What a source fetches: the three parts, the two secret ones in native memory. */
    record Fetched(String accessKeyId, Instant expires, SecretScope secretKey,
                   SecretScope token) {
    }

    /** Fetches a fresh set; the caller owns the scopes. */
    abstract Fetched fetch();

    /** A short name for messages and events - {@code instance}, {@code web-identity}. */
    abstract String name();

    /** The time - a test's, where it has one. */
    Instant now() {
        return Instant.now();
    }

    /** The current generation, fetched first if there is none or it is about to expire. */
    synchronized Generation current() {
        Instant now = now();
        Generation latest = generations.peekLast();
        boolean due = latest == null
                || now.isAfter(latest.expires.minusSeconds(MARGIN_SECONDS));
        if (!due || (latest != null && now.isBefore(askAgain))) {
            return latest;
        }
        Fetched fetched;
        try {
            fetched = fetch();
        } catch (RuntimeException e) {
            if (latest == null || !now.isBefore(latest.expires)) {
                throw e;
            }
            // What is at hand is good for a while yet: a request need not
            // fail because its successor could not be fetched this time.
            askAgain = now.plusSeconds(RETRY_SECONDS);
            LOG.log(System.Logger.Level.WARNING, "the next " + name() + " credentials could "
                    + "not be fetched; the current ones are used until " + latest.expires
                    + ": " + e.getMessage());
            return latest;
        }
        askAgain = now.plusSeconds(RETRY_SECONDS);
        String placeholder = TOKEN_PREFIX + NONCE + "-" + (++next) + "-"
                + System.identityHashCode(this);
        latest = new Generation(fetched.accessKeyId(), placeholder, fetched.expires(),
                fetched.secretKey(), fetched.token());
        BY_PLACEHOLDER.put(placeholder, latest);
        generations.addLast(latest);
        while (generations.size() > KEPT) {
            generations.removeFirst().close();
        }
        return latest;
    }

    /** The generation a placeholder names, or {@code null}. */
    static Generation byPlaceholder(String placeholder) {
        return BY_PLACEHOLDER.get(placeholder);
    }

    static SecretProvider view(SecretScope scope) {
        return new SecretProvider() {
            @Override
            public int writeSecret(MemorySegment target) {
                if (scope.length() > target.byteSize()) {
                    throw new SecretUnavailableException("a temporary AWS credential of "
                            + scope.length() + " bytes does not fit");
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

    private static byte[] nonce() {
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

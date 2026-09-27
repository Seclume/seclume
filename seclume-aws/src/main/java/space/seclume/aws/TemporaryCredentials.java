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
 */
abstract class TemporaryCredentials {

    static final String TOKEN_PREFIX = "seclume-aws-session-token-";
    private static final long MARGIN_SECONDS = 300;
    private static final int KEPT = 3;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String NONCE = HexFormat.of().formatHex(nonce()); // seclume-allow: a random nonce for the placeholder - public
    private static final Map<String, Generation> BY_PLACEHOLDER = new ConcurrentHashMap<>();

    private final Deque<Generation> generations = new ArrayDeque<>();
    private long next;

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

    /** The current generation, fetched first if there is none or it is about to expire. */
    synchronized Generation current() {
        Generation latest = generations.peekLast();
        if (latest == null || Instant.now().isAfter(latest.expires.minusSeconds(MARGIN_SECONDS))) {
            Fetched fetched = fetch();
            String placeholder = TOKEN_PREFIX + NONCE + "-" + (++next) + "-"
                    + System.identityHashCode(this);
            latest = new Generation(fetched.accessKeyId(), placeholder, fetched.expires(),
                    fetched.secretKey(), fetched.token());
            BY_PLACEHOLDER.put(placeholder, latest);
            generations.addLast(latest);
            while (generations.size() > KEPT) {
                generations.removeFirst().close();
            }
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

package space.seclume.kafka;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat; // seclume-allow: a random nonce for placeholders - public
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.secret.SecretScope;

/**
 * The secrets waiting to go out, each under the placeholder that stands for
 * it in what Kafka was given: {@code seclume-kafka-<nonce>-<n>}, a random
 * nonce per process - nobody can guess one and have a secret written into a
 * request of their making - and a number per login.
 *
 * <p>A secret is taken once, by the engine that encrypts the request, and
 * closed there; the login that registered it closes it too, should the
 * request never have gone.
 */
final class SaslPlaceholders {

    private static final SecureRandom RANDOM = new SecureRandom();

    static final byte[] PREFIX = "seclume-kafka-".getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder prefix, no secret
    private static final String NONCE = HexFormat.of().formatHex(nonce()); // seclume-allow: a random nonce - public
    private static final AtomicLong NEXT = new AtomicLong();
    private static final Map<String, SecretScope> WAITING = new ConcurrentHashMap<>();

    private SaslPlaceholders() {
    }

    /** Puts {@code secret} under a new placeholder, which is returned. */
    static String register(SecretScope secret) {
        String placeholder = new String(PREFIX, StandardCharsets.US_ASCII) + NONCE + "-" // seclume-allow: the placeholder, not the secret
                + NEXT.incrementAndGet();
        WAITING.put(placeholder, secret);
        return placeholder;
    }

    /** The secret under {@code placeholder}, taken out; null when there is none. */
    static SecretScope take(String placeholder) {
        return WAITING.remove(placeholder);
    }

    /** Whether {@code c} can follow the prefix in a placeholder. */
    static boolean placeholderChar(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-';
    }

    private static byte[] nonce() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

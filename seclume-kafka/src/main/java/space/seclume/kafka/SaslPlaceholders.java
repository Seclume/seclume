package space.seclume.kafka;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat; // seclume-allow: a random nonce for placeholders - public
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    static final byte[] PREFIX = "seclume-kafka-".getBytes(StandardCharsets.US_ASCII); // seclume-allow: the placeholder prefix, no secret
    private static final Map<String, SecretScope> WAITING = new ConcurrentHashMap<>();

    private SaslPlaceholders() {
    }

    /** Puts {@code secret} under a new placeholder, which is returned. */
    static String register(SecretScope secret) {
        // Random each, not a process nonce and a count: one placeholder seen
        // in a log named every one after it, and whoever could put text where
        // the rewriter looks could have prepared the next login's.
        String placeholder;
        do {
            placeholder = new String(PREFIX, StandardCharsets.US_ASCII) // seclume-allow: the placeholder, not the secret
                    + HexFormat.of().formatHex(nonce());
        } while (WAITING.putIfAbsent(placeholder, secret) != null);
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
        byte[] bytes = new byte[16];
        space.seclume.internal.Entropy.fill(bytes);
        return bytes;
    }
}

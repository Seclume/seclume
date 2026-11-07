package space.seclume.http;

import java.security.SecureRandom;
import java.util.HexFormat; // seclume-allow: a random nonce for placeholders - public
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import space.seclume.secret.SecretProvider;

/**
 * Placeholders that stand for secrets in what an HTTP client is given - a
 * bearer token, an API key, the password of a Basic login - and the providers
 * {@link CredentialSocket} reads the real ones from when it writes the request.
 *
 * <p>A placeholder is {@code seclume-cred-<nonce>-<n>}: a random nonce per
 * process, so that nobody can guess one and have a secret written into a
 * request of their making, and a number per registration.
 */
final class CredentialPlaceholders {

    static final String PREFIX = "seclume-cred-";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String NONCE = HexFormat.of().formatHex(nonce()); // seclume-allow: a random nonce - public
    private static final AtomicLong NEXT = new AtomicLong();
    private static final Map<String, SecretProvider> PROVIDERS = new ConcurrentHashMap<>();

    private CredentialPlaceholders() {
    }

    static String register(SecretProvider provider) {
        String placeholder = PREFIX + NONCE + "-" + NEXT.incrementAndGet();
        PROVIDERS.put(placeholder, provider);
        return placeholder;
    }

    static SecretProvider provider(String placeholder) {
        return PROVIDERS.get(placeholder);
    }

    /** Whether {@code c} can be part of a placeholder after its prefix. */
    static boolean placeholderChar(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-';
    }

    private static byte[] nonce() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}

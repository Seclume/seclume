package space.seclume.http;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HexFormat; // seclume-allow: a random nonce for placeholders - public
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import space.seclume.secret.SecretProvider;

/**
 * Placeholders that stand for secrets in what an HTTP client is given - a
 * bearer token, an API key, the password of a Basic login - and the providers
 * {@link CredentialSocket} reads the real ones from when it writes the request.
 *
 * <p>A placeholder is {@code seclume-cred-<nonce>-<n>}: a random nonce per
 * process, so that nobody can guess one and have a secret written into a
 * request of their making, and a number per registration.
 *
 * <p><b>A placeholder is good for one server.</b> The socket writes a secret
 * into whatever request carries its placeholder, and a client sends its
 * credentials where it is led: JGit to a submodule's host or after a
 * redirect, any client to a URL someone else chose. So a placeholder is bound
 * to the host and port it is first written for - or, given them at
 * registration, to a fixed set (a cluster's nodes) - and on a connection to
 * any other it goes out as it is, the placeholder and not the secret, and
 * that server refuses it.
 */
final class CredentialPlaceholders {

    static final String PREFIX = "seclume-cred-";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String NONCE = HexFormat.of().formatHex(nonce()); // seclume-allow: a random nonce - public
    private static final AtomicLong NEXT = new AtomicLong();
    private static final Map<String, Registration> PROVIDERS = new ConcurrentHashMap<>();

    /** A provider, and the servers its secret may go to. */
    private record Registration(SecretProvider provider, Set<String> servers,
            AtomicReference<String> first) {

        /** Whether the secret goes to {@code server}; the first one asked binds it. */
        boolean goesTo(String server) {
            if (!servers.isEmpty()) {
                return servers.contains(server);
            }
            String bound = first.get();
            if (bound == null && first.compareAndSet(null, server)) {
                return true;
            }
            return first.get().equals(server);
        }
    }

    private CredentialPlaceholders() {
    }

    /** A placeholder bound to the first server it is written for. */
    static String register(SecretProvider provider) {
        return register(provider, Set.of());
    }

    /**
     * A placeholder for {@code servers} only - {@code host:port} each, see
     * {@link #server} - or, when empty, for the first server it is written for.
     */
    static String register(SecretProvider provider, Collection<String> servers) {
        Set<String> normal = new java.util.LinkedHashSet<>();
        for (String server : servers) {
            normal.add(normalize(server));
        }
        String placeholder = PREFIX + NONCE + "-" + NEXT.incrementAndGet();
        PROVIDERS.put(placeholder, new Registration(provider, Set.copyOf(normal),
                new AtomicReference<>()));
        return placeholder;
    }

    /**
     * The provider of {@code placeholder} on a connection to {@code server},
     * or null where its secret does not go: the placeholder is written as it
     * is there.
     *
     * @throws IOException for a placeholder this process did not hand out
     */
    static SecretProvider provider(String placeholder, String server) throws IOException {
        Registration registration = PROVIDERS.get(placeholder);
        if (registration == null) {
            throw new IOException("a credential placeholder this process did not hand out");
        }
        return registration.goesTo(normalize(server)) ? registration.provider() : null;
    }

    /** {@code host:port} as the servers are compared: lower case, IPv6 in brackets. */
    static String server(String host, int port) {
        String name = host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
        return name.toLowerCase(Locale.ROOT) + ":" + port;
    }

    private static String normalize(String server) {
        int colon = server.lastIndexOf(':');
        if (colon <= 0 || colon == server.length() - 1) {
            throw new IllegalArgumentException("a server is host:port, not " + server);
        }
        String port = server.substring(colon + 1);
        for (int i = 0; i < port.length(); i++) {
            if (port.charAt(i) < '0' || port.charAt(i) > '9') {
                throw new IllegalArgumentException("a server is host:port, not " + server);
            }
        }
        return server.toLowerCase(Locale.ROOT);
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

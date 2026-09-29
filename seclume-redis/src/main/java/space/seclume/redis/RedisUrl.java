package space.seclume.redis;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * A {@code redis://} or {@code rediss://} URL as Jedis and Lettuce take it
 * here: host and port, {@code user}, {@code tlsRootCert} or {@code tlsPin},
 * {@code connectTimeout} and {@code timeout} in milliseconds - and the rest
 * the secret provider's options, as in a seclume JDBC URL. A password in the
 * URL is refused.
 */
record RedisUrl(String host, int port, String user, boolean tls, TrustChoice.Choice trust,
                int connectTimeout, int timeout, SecretProvider secret) {

    static RedisUrl parse(String url) {
        URI uri = URI.create(url);
        boolean tls = switch (String.valueOf(uri.getScheme())) {
            case "redis" -> false;
            case "rediss" -> true;
            default -> throw new IllegalArgumentException(
                    "a Redis URL begins with redis:// or rediss://");
        };
        if (uri.getRawUserInfo() != null) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider= and path=");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("a Redis URL names a host: redis://host:port?...");
        }
        Map<String, String> options = new LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)), decode(pair.substring(equals + 1)));
                }
            }
        }
        String user = options.remove("user");
        String rootCert = options.remove(TrustChoice.ROOT_CERT);
        String pin = options.remove(TrustChoice.PIN);
        int connectTimeout = Integer.parseInt(options.getOrDefault("connectTimeout", "5000"));
        int timeout = Integer.parseInt(options.getOrDefault("timeout", "2000"));
        options.remove("connectTimeout");
        options.remove("timeout");
        TrustChoice.Choice trust = null;
        if (rootCert != null || pin != null) {
            Properties named = new Properties();
            if (rootCert != null) {
                named.setProperty(TrustChoice.ROOT_CERT, rootCert);
            }
            if (pin != null) {
                named.setProperty(TrustChoice.PIN, pin);
            }
            try {
                trust = TrustChoice.of(null, named);
            } catch (SQLException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        return new RedisUrl(uri.getHost(), uri.getPort() < 0 ? 6379 : uri.getPort(), user, tls,
                trust, connectTimeout, timeout, SecretProviders.of(options));
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }
}

package space.seclume.redis;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import space.seclume.internal.TrustChoice;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * A {@code redis://}, {@code rediss://}, {@code redis-sentinel://} or
 * {@code rediss-sentinel://} URL as Jedis and Lettuce take it here: one or
 * more {@code host:port} nodes separated by commas, {@code user},
 * {@code sentinelMasterId} (with optional {@code sentinelUser} and
 * {@code sentinel-*} secret provider settings when Sentinel itself takes a
 * login), {@code tlsRootCert} or {@code tlsPin}, {@code connectTimeout} and
 * {@code timeout} in milliseconds - and the rest the secret provider's
 * options, as in a seclume JDBC URL. A password in the URL is refused.
 */
record RedisUrl(List<Node> nodes, String user, String sentinelMasterId, String sentinelUser,
                SecretProvider sentinelSecret, boolean tls, TrustChoice.Choice trust,
                int connectTimeout, int timeout, SecretProvider secret) {

    record Node(String host, int port) {
    }

    String host() {
        return nodes.get(0).host();
    }

    int port() {
        return nodes.get(0).port();
    }

    static RedisUrl parse(String url) {
        if (url == null) {
            throw new IllegalArgumentException(
                    "a Redis URL begins with redis://, rediss://, redis-sentinel:// or rediss-sentinel://");
        }
        int schemeEnd = url.indexOf("://");
        if (schemeEnd <= 0) {
            throw new IllegalArgumentException(
                    "a Redis URL begins with redis://, rediss://, redis-sentinel:// or rediss-sentinel://");
        }
        String scheme = url.substring(0, schemeEnd);
        boolean tls;
        boolean sentinelScheme;
        switch (scheme) {
            case "redis" -> {
                tls = false;
                sentinelScheme = false;
            }
            case "rediss" -> {
                tls = true;
                sentinelScheme = false;
            }
            case "redis-sentinel" -> {
                tls = false;
                sentinelScheme = true;
            }
            case "rediss-sentinel" -> {
                tls = true;
                sentinelScheme = true;
            }
            default -> throw new IllegalArgumentException(
                    "a Redis URL begins with redis://, rediss://, redis-sentinel:// or rediss-sentinel://");
        }
        String rest = url.substring(schemeEnd + 3);
        int question = rest.indexOf('?');
        String authorityAndPath = question < 0 ? rest : rest.substring(0, question);
        String query = question < 0 ? null : rest.substring(question + 1);
        if (authorityAndPath.contains("@")) {
            throw new IllegalArgumentException("a user or password in front of the host is not "
                    + "taken: the password would be a String for the life of the application. "
                    + "Name the user with user= and the secret with provider= and path=");
        }
        String authority = authorityAndPath.endsWith("/")
                ? authorityAndPath.substring(0, authorityAndPath.length() - 1)
                : authorityAndPath;
        if (authority.isEmpty() || authority.contains("/")) {
            throw new IllegalArgumentException("a Redis URL names a host: redis://host:port?...");
        }
        Map<String, String> options = new LinkedHashMap<>();
        if (query != null) {
            for (String pair : query.split("&")) {
                int equals = pair.indexOf('=');
                if (equals > 0) {
                    options.put(decode(pair.substring(0, equals)), decode(pair.substring(equals + 1)));
                }
            }
        }
        String sentinelMasterId = removeFirst(options, "sentinelMasterId", "sentinel-master-id",
                "sentinelMaster");
        if (sentinelMasterId != null && sentinelMasterId.isBlank()) {
            throw new IllegalArgumentException(
                    "sentinelMasterId in the Redis URL is empty; set sentinelMasterId=<name>");
        }
        if (sentinelScheme && sentinelMasterId == null) {
            throw new IllegalArgumentException(
                    "a Sentinel URL needs sentinelMasterId=<name> in the query to name the master");
        }
        int defaultPort = sentinelMasterId != null ? 26379 : 6379;
        List<Node> nodes = parseNodes(authority, defaultPort);
        String user = options.remove("user");
        String sentinelUser = removeFirst(options, "sentinelUser", "sentinel-user");
        String sentinelAuth = removeFirst(options, "sentinelAuth", "sentinel-auth");
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
        Map<String, String> sentinelOptions = new LinkedHashMap<>();
        var iterator = options.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, String> entry = iterator.next();
            if (entry.getKey().startsWith("sentinel-")) {
                sentinelOptions.put(entry.getKey().substring("sentinel-".length()),
                        entry.getValue());
                iterator.remove();
            } else if (entry.getKey().equals("sentinelPassword")) {
                sentinelOptions.put("password", entry.getValue());
                iterator.remove();
            }
        }
        SecretProvider secret = SecretProviders.of(options);
        SecretProvider sentinelSecret = null;
        if (!sentinelOptions.isEmpty()) {
            sentinelSecret = SecretProviders.of(sentinelOptions);
        } else if (sentinelUser != null || "true".equalsIgnoreCase(sentinelAuth)) {
            sentinelSecret = secret;
        }
        return new RedisUrl(List.copyOf(nodes), user, sentinelMasterId, sentinelUser,
                sentinelSecret, tls, trust, connectTimeout, timeout, secret);
    }

    private static List<Node> parseNodes(String authority, int defaultPort) {
        String[] parts = authority.split(",", -1);
        List<Node> nodes = new ArrayList<>(parts.length);
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                throw new IllegalArgumentException(
                        "a Redis URL names a host: redis://host:port?...");
            }
            URI single = URI.create("redis://" + trimmed);
            String host = single.getHost();
            if (host == null || (single.getPath() != null && !single.getPath().isEmpty())) {
                throw new IllegalArgumentException(
                        "a Redis URL names a host: redis://host:port?...");
            }
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            int port = single.getPort() < 0 ? defaultPort : single.getPort();
            nodes.add(new Node(host, port));
        }
        return nodes;
    }

    private static String removeFirst(Map<String, String> options, String... keys) {
        for (String key : keys) {
            String value = options.remove(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String decode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }
}


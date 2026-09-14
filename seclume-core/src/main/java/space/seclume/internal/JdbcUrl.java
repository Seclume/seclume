package space.seclume.internal;

import space.seclume.internal.jdbc.HostList;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * The common shape of the seclume JDBC URLs.
 *
 * <p>{@code jdbc:seclume:<database>://host:port/name?key=value&...}
 *
 * <p>Every driver brings its own prefix and interprets the options itself;
 * taking the URL apart is the same for all of them and therefore lives here.
 * That way {@code provider=file} means the same in every URL of this library -
 * and a {@code password=} is refused the same way everywhere, because the same
 * {@code SecretProviders} sits behind all of them.
 */
public final class JdbcUrl {

    /** What a URL says, before any driver interprets it. */
    public record Parsed(String host, int port, String database, Map<String, String> options,
                         HostList hosts) {

        /** One server, as every URL without a comma in it names. */
        public Parsed(String host, int port, String database, Map<String, String> options) {
            this(host, port, database, options, HostList.of(host, port));
        }

        /** A value, even when the URL spelled it with a hyphen. */
        public String option(String key) {
            String direct = options.get(key);
            if (direct != null) {
                return direct;
            }
            for (Map.Entry<String, String> entry : options.entrySet()) {
                if (entry.getKey().replace("-", "").equalsIgnoreCase(key.replace("-", ""))) {
                    return entry.getValue();
                }
            }
            return null;
        }

        public String option(String key, String fallback) {
            String value = option(key);
            return value == null ? fallback : value;
        }

        /** A size, which may well be larger than an int - bytes usually are. */
        public long size(String key, long fallback) {
            String value = option(key);
            if (value == null) {
                return fallback;
            }
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(key + " must be a number: " + value);
            }
        }

        public int number(String key, int fallback) {
            String value = option(key);
            if (value == null) {
                return fallback;
            }
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(key + " must be a number: " + value);
            }
        }

        public boolean flag(String key, boolean fallback) {
            String value = option(key);
            return value == null ? fallback : Boolean.parseBoolean(value.trim());
        }
    }

    private JdbcUrl() {
    }

    /**
     * Takes URL and {@link Properties} apart.
     *
     * <p>Values from the {@code Properties} win over the URL: that way a
     * connection pool can take the URL from configuration and override
     * individual points deliberately.
     *
     * @param prefix       the driver prefix, for example {@code jdbc:seclume:mysql:}
     * @param defaultPort  the port to use when the URL names none
     * @throws IllegalArgumentException if the URL does not belong to this
     *         driver or names no database
     */
    public static Parsed parse(String url, Properties properties, String prefix, int defaultPort) {
        if (url == null || !url.startsWith(prefix)) {
            throw new IllegalArgumentException(
                    "not a seclume URL for this driver: " + url + " - expected "
                    + prefix + "//host:port/database");
        }
        String rest = url.substring(prefix.length());
        if (!rest.startsWith("//")) {
            throw new IllegalArgumentException(
                    "malformed seclume URL - expected " + prefix + "//host:port/database");
        }
        rest = rest.substring(2);

        Map<String, String> options = new LinkedHashMap<>();
        int question = rest.indexOf('?');
        if (question >= 0) {
            parseQuery(rest.substring(question + 1), options);
            rest = rest.substring(0, question);
        }
        if (properties != null) {
            for (String name : properties.stringPropertyNames()) {
                options.put(name, properties.getProperty(name));
            }
        }

        String hostPort = rest;
        String database = "";
        int slash = rest.indexOf('/');
        if (slash >= 0) {
            hostPort = rest.substring(0, slash);
            database = rest.substring(slash + 1);
        }
        // Several servers, separated by commas, are allowed here: that is how
        // failover is configured, and the same spelling other drivers use.
        HostList hosts = HostList.parse(
                hostPort.isEmpty() ? "127.0.0.1" : hostPort, defaultPort);
        if (database.isEmpty()) {
            database = options.getOrDefault("database", "");
        }
        return new Parsed(hosts.first().host(), hosts.first().port(), database, options, hosts);
    }

    private static void parseQuery(String query, Map<String, String> into) {
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String key = equals < 0 ? pair : pair.substring(0, equals);
            String value = equals < 0 ? "" : pair.substring(equals + 1);
            into.put(decode(key), decode(value));
        }
    }

    private static String decode(String text) {
        return URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    /** Lower case without locale surprises - for comparing keys. */
    public static String normalize(String key) {
        return key.replace("-", "").toLowerCase(Locale.ROOT);
    }
}

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
                    "not a seclume URL for this driver: " + redact(url) + " - expected "
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
                hostPort.isEmpty() ? "127.0.0.1" : hostPort, defaultPort)
                // targetServerType=primary|secondary|any, the name pgjdbc
                // uses. It belongs on the list rather than on the connection:
                // it says which of these servers to take, and with one server
                // it changes nothing and costs nothing.
                .looking(space.seclume.internal.jdbc.TargetServer.of(
                        options.get("targetServerType")))
                // hostSelection=ordered|quality: the list as written, or the
                // best measured server first - see HostQuality.
                .selecting(space.seclume.internal.jdbc.HostSelection.of(
                        options.get("hostSelection")))
                // patroni=http://db1:8008,...: the cluster says where its leader
                // is now - see PatroniTopology.
                .discovering(space.seclume.internal.jdbc.PatroniTopology.of(
                        options.get("patroni")));
        // aurora=true: the instances an Aurora cluster reported, remembered
        // for the next connect - see AuroraTopology.
        space.seclume.internal.jdbc.AuroraTopology aurora =
                space.seclume.internal.jdbc.AuroraTopology.of(options.get("aurora"),
                        options.get("auroraInstanceHost"), hosts.hosts());
        if (aurora != null) {
            hosts = hosts.discovering(aurora);
        }
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

    /**
     * A URL fit to put in a message, with the values of its options removed.
     *
     * <p><b>The case this is for is a URL that is not ours.</b> A seclume URL
     * carries a provider and a path and no credential - that is the whole
     * design. But the message that names a wrong URL is precisely the message
     * that gets a <i>vendor's</i> URL, and those routinely read
     * {@code ...?user=app&amp;password=hunter2}. Echoing it back puts the
     * password in the application's log, at the moment somebody is already
     * confused and reading logs.
     *
     * <p>So the shape is kept - scheme, host, port, database, and which
     * options were given - and every value after an {@code =} becomes
     * {@code ?}. That is enough to see what is wrong with a URL, which is the
     * only reason to print one.
     *
     * <p>Not a parser: this runs on strings that are malformed by definition,
     * so it does the one textual thing it can do correctly.
     */
    public static String redact(String url) {
        if (url == null) {
            return "null";
        }
        int question = url.indexOf('?');
        if (question < 0) {
            return url;
        }
        StringBuilder out = new StringBuilder(url.length());
        out.append(url, 0, question + 1);
        String[] pairs = url.substring(question + 1).split("&", -1);
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                out.append('&');
            }
            int equals = pairs[i].indexOf('=');
            if (equals < 0) {
                out.append(pairs[i]);
            } else {
                out.append(pairs[i], 0, equals + 1).append('?');
            }
        }
        return out.toString();
    }
}

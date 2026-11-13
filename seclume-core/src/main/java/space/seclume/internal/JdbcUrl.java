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
        // //user:password@host is how most vendors' URLs carry a login. Taken
        // as a host it became "user:password", the password a port: refused
        // with the password in the message ("app:hunter2 has no usable port"),
        // or, with a port after the host, a server named "app:hunter2@db" in
        // every connect failure. A seclume URL names its user in user= and its
        // password nowhere, so whatever stands before an @ is refused - and
        // the message shows the URL with it masked.
        if (hostPort.indexOf('@') >= 0) {
            throw new IllegalArgumentException("a seclume URL has nothing before its host - "
                    + "no user@ and no user:password@: " + redact(url) + ". The user goes in "
                    + "user=, the password in a secret provider (provider=file&path=...).");
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
     * that gets a <i>vendor's</i> URL, and those carry passwords in four
     * spellings: {@code ?user=app&amp;password=hunter2} (PostgreSQL, MySQL),
     * {@code ;user=sa;password=hunter2} (SQL Server, a value with a {@code ;}
     * in braces), {@code //app:hunter2@db} (MySQL, MariaDB, MongoDB) and
     * {@code thin:scott/tiger@db} (Oracle), and MySQL's key-value hosts
     * {@code (host=db,password=hunter2)}. Echoing one back puts the password
     * in the application's log, at the moment somebody is already confused
     * and reading logs.
     *
     * <p>So the shape is kept - scheme, host, port, database, and which
     * options were given - and every value after an {@code =} becomes
     * {@code ?}, as does the password of a {@code user:password@} or a
     * {@code user/password@}. That is enough to see what is wrong with a URL,
     * which is the only reason to print one.
     *
     * <p>Not a parser: this runs on strings that are malformed by definition,
     * so it does textual things that hold for any input. One it cannot know:
     * a {@code user:password@} whose password has a {@code ?} in it that is
     * not %-encoded - no URL may have one there.
     */
    public static String redact(String url) {
        if (url == null) {
            return "null";
        }
        // What is hidden is marked first and replaced after: the login's
        // password and the values of options overlap where a value has an @
        // in it or a password an =, and either may then only be cut out
        // whole. Each run of hidden characters becomes one ?.
        boolean[] hidden = new boolean[url.length()];
        hideLoginPassword(url, hidden);
        hideValues(url, hidden);
        StringBuilder out = new StringBuilder(url.length());
        for (int i = 0; i < url.length(); i++) {
            if (!hidden[i]) {
                out.append(url.charAt(i));
            } else if (i == 0 || !hidden[i - 1]) {
                out.append('?');
            }
        }
        return out.toString();
    }

    /**
     * {@code //app:hunter2@db} and Oracle's {@code thin:scott/tiger@db}: the
     * password between the {@code :} or {@code /} and the {@code @}. For the
     * first, the authority ends where RFC 3986 ends it - at the first
     * {@code / ? #} - and its last {@code @} ends the login; for Oracle the
     * first {@code @} outside quotes does, before any {@code //}, as its
     * password may be quoted and have one.
     */
    private static void hideLoginPassword(String url, boolean[] hidden) {
        int authority = url.indexOf("//");
        int oracleAt = firstOutsideQuotes(url, '@');
        if (oracleAt >= 0 && (authority < 0 || oracleAt < authority)) {
            int slash = url.indexOf('/');
            if (slash >= 0 && slash < oracleAt) {
                java.util.Arrays.fill(hidden, slash + 1, oracleAt, true);
                return;
            }
            // No user/password before that @: Oracle's EZConnect "thin:@//"
            // with a user:password@ typed into its authority. Returning here
            // showed that password in the message (JdbcUrlRedactEdgeTest) -
            // the authority's rule below applies to it as to any other URL.
        }
        if (authority < 0) {
            return;
        }
        int end = url.length();
        for (int i = authority + 2; i < url.length(); i++) {
            if ("/?#".indexOf(url.charAt(i)) >= 0) {
                end = i;
                break;
            }
        }
        int at = url.lastIndexOf('@', end - 1);
        int colon = url.indexOf(':', authority + 2);
        if (at > authority && colon >= 0 && colon < at) {
            java.util.Arrays.fill(hidden, colon + 1, at, true);
        }
    }

    private static int firstOutsideQuotes(String text, char wanted) {
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (c == wanted && !quoted) {
                return i;
            }
        }
        return -1;
    }

    /**
     * The value of every {@code key=value}. Before the query - SQL Server's
     * {@code ;password=}, MySQL's {@code (password=)}, an Oracle descriptor's
     * {@code (HOST=)} - a value ends at {@code ; , ( )} or, in braces, at the
     * brace that closes them ({@code }}} being a brace inside), and a
     * {@code ?} in it is part of it: SQL Server's values may have one. The
     * query starts at the first {@code ?} outside a value and outside quotes;
     * there a value ends at {@code &}. An {@code =} in the login's password
     * starts a value too: with SQL Server's {@code ;password=a@b?c} the
     * login rule takes {@code a@b} for a login, and only the value hides it
     * all.
     */
    private static void hideValues(String url, boolean[] hidden) {
        boolean[] loginHidden = hidden.clone();
        int i = 0;
        boolean quoted = false;
        while (i < url.length()) {
            char c = url.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            }
            // A ? in the login's password is the password's, not the query's.
            if (quoted || (c != '=' && c != '?') || (c == '?' && loginHidden[i])) {
                i++;
                continue;
            }
            if (c == '?') {
                break;
            }
            int end = i + 1;
            if (end < url.length() && url.charAt(end) == '{') {
                end++;
                while (end < url.length()) {
                    if (url.charAt(end) == '}') {
                        if (end + 1 < url.length() && url.charAt(end + 1) == '}') {
                            end += 2;
                            continue;
                        }
                        end++;
                        break;
                    }
                    end++;
                }
            } else {
                while (end < url.length() && ";,()".indexOf(url.charAt(end)) < 0) {
                    end++;
                }
            }
            java.util.Arrays.fill(hidden, i + 1, end, true);
            i = end;
        }
        // The query's values are hidden from its first ? on even where a
        // value before it ran over that ? - a password ending in = before an
        // @ makes one do that, and it ended at a ; in the query, not at the end.
        boolean inQuotes = false;
        for (int q = 0; q < url.length(); q++) {
            char c = url.charAt(q);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == '?' && !inQuotes && !loginHidden[q]) {
                hideQueryValues(url, q + 1, hidden);
                return;
            }
        }
    }

    private static void hideQueryValues(String url, int from, boolean[] hidden) {
        boolean inValue = false;
        for (int i = from; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '&') {
                inValue = false;
            } else if (inValue) {
                hidden[i] = true;
            } else if (c == '=') {
                inValue = true;
            }
        }
    }

}

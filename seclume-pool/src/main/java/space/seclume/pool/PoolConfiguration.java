package space.seclume.pool;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.logging.Logger;

import javax.sql.DataSource;

/**
 * A pool from configuration - the same keys whatever reads them: Micronaut's
 * {@code application.yml}, Helidon's {@code Config}, plain properties.
 *
 * <pre>
 *   url                     jdbc:seclume:postgresql://db/app?user=app&amp;provider=file&amp;path=/run/secrets/db
 *   pool.maximum-pool-size  10
 *   pool.minimum-idle       2
 *   pool.connection-timeout 30s
 *   pool.idle-timeout       10m
 *   pool.max-lifetime       30m
 *   pool.keepalive-time     0
 *   pool.validation-timeout 5s
 *   pool.leak-detection-threshold 0
 *   pool.shutdown-timeout   10s
 *   pool.statement-cache-size 64
 *   pool.warmup             false
 * </pre>
 *
 * <p>The URL names where the secret comes from - a provider, as every seclume
 * URL does - and the driver reads it into native memory at each login. There
 * is no {@code password} key, and a URL with {@code password=} in it is
 * refused: whatever a framework keeps as configuration it keeps as a
 * {@code String}, for the life of the application.
 */
public final class PoolConfiguration {

    static final List<String> KEYS = List.of("maximum-pool-size", "minimum-idle",
            "connection-timeout", "idle-timeout", "max-lifetime", "keepalive-time",
            "validation-timeout", "leak-detection-threshold", "shutdown-timeout",
            "statement-cache-size", "warmup");

    private PoolConfiguration() {
    }

    /**
     * Settings from {@code pool.*} keys, without the prefix - {@code maximum-pool-size}
     * and so on; the rest at their defaults. An unknown key is refused with the list.
     */
    public static PoolSettings settings(String name, Map<String, String> pool) {
        PoolSettings settings = new PoolSettings();
        settings.setName(name);
        for (Map.Entry<String, String> entry : pool.entrySet()) {
            // maximum-pool-size, maximum_pool_size, MAXIMUM_POOL_SIZE and maximumPoolSize alike.
            String key = entry.getKey().trim().replaceAll("([a-z0-9])([A-Z])", "$1-$2")
                    .toLowerCase(Locale.ROOT).replace('_', '-');
            String value = entry.getValue() == null ? "" : entry.getValue().trim();
            switch (key) {
                case "maximum-pool-size" -> settings.setMaximumPoolSize(number(key, value));
                case "minimum-idle" -> settings.setMinimumIdle(number(key, value));
                case "connection-timeout" -> settings.setConnectionTimeout(duration(key, value));
                case "idle-timeout" -> settings.setIdleTimeout(duration(key, value));
                case "max-lifetime" -> settings.setMaxLifetime(duration(key, value));
                case "keepalive-time" -> settings.setKeepaliveTime(duration(key, value));
                case "validation-timeout" -> settings.setValidationTimeout(duration(key, value));
                case "leak-detection-threshold" -> settings.setLeakDetectionThreshold(duration(key, value));
                case "shutdown-timeout" -> settings.setShutdownTimeout(duration(key, value));
                case "statement-cache-size" -> settings.setStatementCacheSize(number(key, value));
                case "warmup" -> settings.setWarmup(bool(key, value));
                default -> throw new IllegalArgumentException("no pool setting '" + entry.getKey()
                        + "' - the settings are " + new TreeSet<>(KEYS));
            }
        }
        return settings;
    }

    /**
     * A pool over the seclume driver the URL names, through
     * {@link DriverManager}. Nothing connects yet - see {@link SeclumePool#warmup()}.
     */
    public static SeclumePool pool(String name, String url, Map<String, String> pool) {
        if (url == null || !url.startsWith("jdbc:seclume:")) {
            throw new IllegalArgumentException("data source " + name + ": a seclume URL "
                    + "(jdbc:seclume:postgresql://..., mysql, sqlserver, oracle) is needed, not "
                    + (url == null ? "none" : scheme(url) + "..."));
        }
        String inline = inlineSecret(url);
        if (inline != null) {
            throw new IllegalArgumentException("data source " + name + ": the URL carries a "
                    + inline + " - it would stay a String in the configuration for the life of the "
                    + "application. Name where it comes from instead: provider=file&path=/run/secrets/db, "
                    + "provider=vault&..., provider=kms-decrypt&...");
        }
        return new SeclumePool(new UrlDataSource(url), settings(name, pool));
    }

    /**
     * What of a secret the URL holds itself, or {@code null}: a {@code password},
     * {@code secret} or {@code value} parameter - the keys the drivers refuse
     * at the first login, refused here at the start - or a password in its user
     * information ({@code //user:password@host}).
     */
    static String inlineSecret(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        java.util.regex.Matcher parameter = java.util.regex.Pattern
                .compile("[?&;]\\s*(password|secret|value)\\s*=").matcher(lower);
        if (parameter.find()) {
            return parameter.group(1).equals("password") ? "password" : parameter.group(1) + " parameter";
        }
        int authority = url.indexOf("//");
        if (authority >= 0) {
            int end = authority + 2;
            while (end < url.length() && "/?;".indexOf(url.charAt(end)) < 0) {
                end++;
            }
            String hosts = url.substring(authority + 2, end);
            int at = hosts.lastIndexOf('@');
            if (at >= 0 && hosts.substring(0, at).indexOf(':') >= 0) {
                return "password in its user information (user:password@)";
            }
        }
        return null;
    }

    /** {@code jdbc:mysql:} of {@code jdbc:mysql://root:secret@db/app} - never more of a URL that is refused. */
    static String scheme(String url) {
        int first = url.indexOf(':');
        int second = first < 0 ? -1 : url.indexOf(':', first + 1);
        if (first < 0 || second < 0 || second - first > 32) {
            return "something that is no JDBC URL";
        }
        return url.substring(0, second + 1);
    }

    static int number(String key, String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("pool." + key + " is a whole number, not '" + value + "'", e);
        }
    }

    static boolean bool(String key, String value) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "true", "yes", "on" -> true;
            case "false", "no", "off" -> false;
            default -> throw new IllegalArgumentException("pool." + key + " is true or false, not '" + value + "'");
        };
    }

    /** {@code 30s}, {@code 250ms}, {@code 10m}, {@code 1h}, {@code 0}, or ISO-8601 ({@code PT30S}). */
    static Duration duration(String key, String value) {
        String v = value.toLowerCase(Locale.ROOT);
        try {
            if (v.equals("0")) {
                return Duration.ZERO;
            }
            if (v.startsWith("pt") || v.startsWith("p")) {
                return Duration.parse(value.toUpperCase(Locale.ROOT));
            }
            if (v.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(v.substring(0, v.length() - 2)));
            }
            long amount = Long.parseLong(v.substring(0, v.length() - 1));
            return switch (v.charAt(v.length() - 1)) {
                case 's' -> Duration.ofSeconds(amount);
                case 'm' -> Duration.ofMinutes(amount);
                case 'h' -> Duration.ofHours(amount);
                case 'd' -> Duration.ofDays(amount);
                default -> throw new NumberFormatException(v);
            };
        } catch (NumberFormatException | DateTimeParseException | StringIndexOutOfBoundsException e) {
            throw new IllegalArgumentException("pool." + key + " is a duration - 30s, 250ms, 10m, 1h or "
                    + "PT30S - not '" + value + "'", e);
        }
    }

    /** A connection per call from {@link DriverManager}: the URL is all the driver needs. */
    static final class UrlDataSource implements DataSource {

        private final String url;
        private int loginTimeout;

        UrlDataSource(String url) {
            this.url = url;
        }

        @Override
        public Connection getConnection() throws SQLException {
            return DriverManager.getConnection(url);
        }

        @Override
        public Connection getConnection(String user, String password) throws SQLException {
            throw new SQLFeatureNotSupportedException("the URL names the user and where the secret "
                    + "comes from - a password is not passed in");
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
            // nothing is logged this way
        }

        @Override
        public void setLoginTimeout(int seconds) {
            this.loginTimeout = seconds;
        }

        @Override
        public int getLoginTimeout() {
            return loginTimeout;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("no parent logger");
        }

        @Override
        public <T> T unwrap(Class<T> type) throws SQLException {
            if (type.isInstance(this)) {
                return type.cast(this);
            }
            throw new SQLException("not a wrapper for " + type.getName());
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return type.isInstance(this);
        }

        @Override
        public String toString() {
            // ? for most drivers, ; for SQL Server's settings - neither is shown.
            int query = url.length();
            for (char separator : new char[] {'?', ';'}) {
                int at = url.indexOf(separator);
                if (at >= 0 && at < query) {
                    query = at;
                }
            }
            return "UrlDataSource[" + url.substring(0, query) + "]";
        }
    }
}

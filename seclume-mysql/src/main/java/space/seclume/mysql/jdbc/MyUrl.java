package space.seclume.mysql.jdbc;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;

import space.seclume.internal.JdbcUrl;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.mysql.MySession;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * The JDBC URL of the MySQL driver.
 *
 * <p>Shape: {@code jdbc:seclume:mysql://host:port/database?user=...&provider=...}
 *
 * <p>{@code mariadb} is accepted as a spelling too - it is the same protocol,
 * and whoever talks to a MariaDB server should be allowed to say so in the
 * URL.
 *
 * <p>No {@code password}: the URL says <b>where</b> the password comes from. A
 * {@code password=} leads to an abort with a reason.
 */
final class MyUrl {

    static final String PREFIX = "jdbc:seclume:mysql:";
    static final String MARIADB_PREFIX = "jdbc:seclume:mariadb:";
    static final int DEFAULT_PORT = 3306;

    private MyUrl() {
    }

    static boolean accepts(String url) {
        return url != null && (url.startsWith(PREFIX) || url.startsWith(MARIADB_PREFIX));
    }

    /** {@code loadDataLocal=true}: the session offers LOCAL INFILE - see MySession#loadData. */
    static boolean loadDataLocal(String url, java.util.Properties properties) {
        try {
            return JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT)
                    .flag("loadDataLocal", false);
        } catch (RuntimeException e) {
            return false;                     // reported by settings() already
        }
    }

    /**
     * {@code rewriteBatchedInserts=true}: a batch of {@code INSERT ... VALUES (?, ...)}
     * goes as multi-row inserts - see MyPreparedStatement#executeLargeBatch.
     */
    static boolean rewriteBatchedInserts(String url, java.util.Properties properties) {
        try {
            return JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT)
                    .flag("rewriteBatchedInserts", false);
        } catch (RuntimeException e) {
            return false;                     // reported by settings() already
        }
    }

    static MySession.Settings settings(String url, Properties properties) throws SQLException {
        String prefix = url != null && url.startsWith(MARIADB_PREFIX) ? MARIADB_PREFIX : PREFIX;
        JdbcUrl.Parsed parsed;
        try {
            parsed = JdbcUrl.parse(url, properties, prefix, DEFAULT_PORT);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        String user = parsed.option("user");
        if (user == null || user.isBlank()) {
            throw new SQLException("no 'user' - seclume does not guess the database user");
        }

        SecretProvider secret;
        try {
            secret = SecretProviders.of(new HashMap<>(parsed.options()));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        try {
            return new MySession.Settings(parsed.host(), parsed.port(), parsed.database(), user,
                    secret, parsed.option("applicationName", "seclume"),
                    parsed.number("connectTimeout", 10_000),
                    parsed.flag("allowPublicKeyRetrieval", false), parsed.hosts(),
                    ResultLimit.of(parsed.size("maxResultBytes", 0),
                            parsed.size("maxResultRows", 0)),
                    space.seclume.internal.jdbc.TlsMode.of(
                            parsed.option("tls", null)),
                    space.seclume.internal.jdbc.TlsStack.of(
                            parsed.option("tlsStack", null)),
                    // A client certificate, when one is configured. Building
                    // it here rather than per connection is deliberate - see
                    // ClientIdentities: the key is loaded once and shared.
                    space.seclume.tls.ClientIdentities.of(parsed.options()),
                    // On by default, as in Connector/J: a tinyint(1) is a
                    // boolean to every ORM that writes one. tinyInt1isBit=false
                    // gives back the integer for whoever wants the raw column.
                    parsed.flag("tinyInt1isBit", true));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
    }
}

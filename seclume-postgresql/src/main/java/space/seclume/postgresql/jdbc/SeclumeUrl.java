package space.seclume.postgresql.jdbc;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;

import space.seclume.internal.JdbcUrl;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.postgresql.PgSession;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * The JDBC URL of this driver.
 *
 * <p>Shape: {@code jdbc:seclume:postgresql://host:port/database?user=...&provider=...}
 *
 * <p>What stands out is what is missing: no {@code password}. Anyone who does
 * pass one gets a message instead of a connection - see
 * {@link SecretProviders}. Instead the URL says where the password comes from,
 * and the driver fetches it there, straight into native memory, every time
 * afresh.
 */
final class SeclumeUrl {

    static final String PREFIX = "jdbc:seclume:postgresql:";
    static final int DEFAULT_PORT = 5432;

    private SeclumeUrl() {
    }

    static boolean accepts(String url) {
        return url != null && url.startsWith(PREFIX);
    }

    /** Takes URL and {@link Properties} apart into connection settings. */
    static PgSession.Settings settings(String url, Properties properties) throws SQLException {
        JdbcUrl.Parsed parsed;
        try {
            parsed = JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        if (parsed.database().isEmpty()) {
            throw new SQLException(
                    "no database in the URL - expected " + PREFIX + "//host:port/database");
        }
        String user = parsed.option("user");
        if (user == null || user.isBlank()) {
            throw new SQLException("no 'user' - seclume does not guess the database user");
        }

        SecretProvider secret;
        try {
            secret = SecretProviders.of(new HashMap<>(parsed.options()));
        } catch (IllegalArgumentException e) {
            // The DriverManager only passes SQLException on; the caller still
            // has to be able to read the reason.
            throw new SQLException(e.getMessage(), "08001", e);
        }
        try {
            return new PgSession.Settings(parsed.host(), parsed.port(), parsed.database(), user,
                    secret, parsed.option("applicationName", "seclume"),
                    parsed.number("connectTimeout", 10_000), parsed.hosts(),
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
                    // tlsNegotiation=direct (libpq's sslnegotiation=direct):
                    // PostgreSQL 17 and later, one round trip fewer per connect.
                    directTls(parsed.option("tlsNegotiation",
                            parsed.option("sslnegotiation", "postgres"))));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
    }

    /**
     * How many server-side plans one connection keeps for reuse; 0 switches it
     * off.
     *
     * <p>Not part of {@link PgSession.Settings} on purpose: the session knows
     * nothing about JDBC statements, and this is a JDBC-level concern.
     */
    static int statementCacheSize(String url, java.util.Properties properties) {
        try {
            return JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT)
                    .number("statementCacheSize", DEFAULT_STATEMENT_CACHE);
        } catch (RuntimeException e) {
            // The URL is parsed properly a line earlier and its errors reported
            // there; a second failure here must not turn into a different one.
            return DEFAULT_STATEMENT_CACHE;
        }
    }

    /**
     * {@code proxyMode=transaction}: a transaction pooler (PgBouncer in
     * transaction mode, RDS Proxy) sits in front, so the server session is
     * shared between clients from one transaction to the next. See
     * PgConnection#transactionPooler.
     */
    static boolean transactionPooler(String url, java.util.Properties properties)
            throws SQLException {
        String value;
        try {
            value = JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT).option("proxyMode", "none");
        } catch (RuntimeException e) {
            return false;                     // reported by settings() already
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "none", "session", "off" -> false;
            case "transaction" -> true;
            default -> throw new SQLException("proxyMode=" + value
                    + " - it is none or transaction", "08001");
        };
    }

    /** Enough for the statements one request touches, small enough to forget. */
    static final int DEFAULT_STATEMENT_CACHE = 32;

    /** {@code direct} or {@code postgres} (the SSLRequest first, the default). */
    private static boolean directTls(String value) throws SQLException {
        return switch (value.toLowerCase(java.util.Locale.ROOT)) {
            case "direct" -> true;
            case "postgres", "postgresql" -> false;
            default -> throw new SQLException("tlsNegotiation is direct or postgres, not '"
                    + value + "'", "08001");
        };
    }
}

package space.seclume.oracle.jdbc;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;

import space.seclume.internal.JdbcUrl;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.oracle.OracleSession;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;

/**
 * The JDBC URL of the Oracle driver.
 *
 * <p>Shape:
 * {@code jdbc:seclume:oracle://host:1521/service?user=...&provider=file&path=...}
 *
 * <p>The same shape as the other three drivers, and deliberately not Oracle's
 * own {@code thin:@//host:port/service} - one syntax for all four is worth more
 * than being familiar to one of them. What follows the port is the
 * <b>service name</b>, not a database: Oracle has no catalogs.
 *
 * <p>No {@code password}: the URL says <b>where</b> the password comes from. A
 * {@code password=} leads to an abort with a reason.
 */
final class OraUrl {

    static final String PREFIX = "jdbc:seclume:oracle:";
    static final int DEFAULT_PORT = 1521;

    private OraUrl() {
    }

    static boolean accepts(String url) {
        return url != null && url.startsWith(PREFIX);
    }

    static OracleSession.Settings settings(String url, Properties properties)
            throws SQLException {
        JdbcUrl.Parsed parsed;
        try {
            parsed = JdbcUrl.parse(url, properties, PREFIX, DEFAULT_PORT);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        String user = parsed.option("user");
        if (user == null || user.isBlank()) {
            throw new SQLException("no 'user' - seclume does not guess the database user");
        }
        if (parsed.database().isEmpty()) {
            throw new SQLException("no service name - it goes after the port, as in "
                    + PREFIX + "//host:1521/FREEPDB1", "08001");
        }

        SecretProvider secret;
        try {
            secret = SecretProviders.of(new HashMap<>(parsed.options()));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        try {
            return new OracleSession.Settings(parsed.host(), parsed.port(),
                    parsed.database(), user, secret,
                    parsed.number("connectTimeout", 10_000), parsed.hosts(),
                    ResultLimit.of(parsed.size("maxResultBytes", 0),
                            parsed.size("maxResultRows", 0)));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
    }
}

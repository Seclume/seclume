package space.seclume.sqlserver.jdbc;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Properties;

import space.seclume.internal.JdbcUrl;
import space.seclume.internal.jdbc.ResultLimit;
import space.seclume.secret.SecretProvider;
import space.seclume.secret.SecretProviders;
import space.seclume.sqlserver.tds.TdsSession;

/**
 * The JDBC URL of the SQL Server driver.
 *
 * <p>Shape:
 * {@code jdbc:seclume:sqlserver://host:1433/database?user=...&provider=file&path=...}
 *
 * <p>Deliberately the same shape as the other seclume drivers, and not
 * Microsoft's {@code ;key=value} form - one syntax for all four is worth more
 * than being familiar to one of them.
 *
 * <p>No {@code password}: the URL says <b>where</b> the password comes from. A
 * {@code password=} leads to an abort with a reason.
 */
final class TdsUrl {

    static final String PREFIX = "jdbc:seclume:sqlserver:";
    static final String MSSQL_PREFIX = "jdbc:seclume:mssql:";
    static final int DEFAULT_PORT = 1433;

    private TdsUrl() {
    }

    static boolean accepts(String url) {
        return url != null && (url.startsWith(PREFIX) || url.startsWith(MSSQL_PREFIX));
    }

    static TdsSession.Settings settings(String url, Properties properties) throws SQLException {
        String prefix = url != null && url.startsWith(MSSQL_PREFIX) ? MSSQL_PREFIX : PREFIX;
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
            return new TdsSession.Settings(parsed.host(), parsed.port(),
                    parsed.database().isEmpty() ? "master" : parsed.database(), user, secret,
                    parsed.option("applicationName", "seclume"),
                    parsed.number("connectTimeout", 10_000),
                    parsed.flag("trustServerCertificate", false), parsed.hosts(),
                    ResultLimit.of(parsed.size("maxResultBytes", 0),
                            parsed.size("maxResultRows", 0)),
                    space.seclume.sqlserver.tds.TdsVersion.of(parsed.option("tds", null)),
                    space.seclume.internal.jdbc.TlsStack.of(parsed.option("tlsStack", null)),
                    space.seclume.tls.ClientIdentities.of(parsed.options()));
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
    }
}

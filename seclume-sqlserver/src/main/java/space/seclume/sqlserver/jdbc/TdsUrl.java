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

    /**
     * {@code varcharParameters}: {@code auto} (the default) sends ASCII text
     * as varchar where the server compares it with a varchar column,
     * {@code off} sends every text as nvarchar - see VarcharParameters.
     */
    static boolean varcharParameters(String url, Properties properties) throws SQLException {
        String prefix = url != null && url.startsWith(MSSQL_PREFIX) ? MSSQL_PREFIX : PREFIX;
        String value;
        try {
            value = JdbcUrl.parse(url, properties, prefix, DEFAULT_PORT)
                    .option("varcharParameters", "auto");
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "auto", "on", "true" -> true;
            case "off", "false" -> false;
            default -> throw new SQLException("varcharParameters=" + value
                    + " - it is auto or off", "08001");
        };
    }

    /**
     * {@code authentication}: {@code password} (the default), or {@code token}
     * - the secret provider delivers a Microsoft Entra access token, which
     * goes in LOGIN7's FEDAUTH feature (Azure SQL). mssql-jdbc's names for
     * the managed-identity login mean the same here, with the token coming
     * from {@code provider=azure-managed-identity}.
     */
    static boolean accessToken(String authentication) throws SQLException {
        return switch (authentication.toLowerCase(java.util.Locale.ROOT)) {
            case "password", "sqlpassword", "kerberos", "integrated" -> false;
            case "token", "accesstoken", "activedirectorymanagedidentity",
                 "activedirectorymsi", "activedirectorydefault" -> true;
            default -> throw new SQLException("authentication=" + authentication
                    + " is not known - password, token (a Microsoft Entra access token "
                    + "from the secret provider) or kerberos", "08001");
        };
    }

    /**
     * {@code authentication=kerberos} - or mssql-jdbc's
     * {@code integratedSecurity=true} - logs in with a Kerberos ticket the
     * process already holds; no user, no password, no provider. The service
     * principal is {@code MSSQLSvc/<host>:<port>} unless {@code serverSpn}
     * names another; the host should be the name the SPN was registered for.
     */
    static boolean kerberos(JdbcUrl.Parsed parsed) throws SQLException {
        String authentication = parsed.option("authentication", "password")
                .toLowerCase(java.util.Locale.ROOT);
        String scheme = parsed.option("authenticationScheme", "JavaKerberos");
        boolean integrated = authentication.equals("kerberos")
                || authentication.equals("integrated")
                || parsed.flag("integratedSecurity", false);
        if (integrated && !scheme.equalsIgnoreCase("JavaKerberos")
                && !scheme.equalsIgnoreCase("NativeAuthentication")) {
            throw new SQLException("authenticationScheme=" + scheme + " is not offered - "
                    + "an integrated login here is Kerberos", "08001");
        }
        return integrated;
    }

    static TdsSession.Settings settings(String url, Properties properties) throws SQLException {
        String prefix = url != null && url.startsWith(MSSQL_PREFIX) ? MSSQL_PREFIX : PREFIX;
        JdbcUrl.Parsed parsed;
        try {
            parsed = JdbcUrl.parse(url, properties, prefix, DEFAULT_PORT);
        } catch (IllegalArgumentException e) {
            throw new SQLException(e.getMessage(), "08001", e);
        }
        boolean token = accessToken(parsed.option("authentication", "password"));
        boolean kerberos = kerberos(parsed);
        String user = parsed.option("user");
        if ((token || kerberos) && user == null) {
            user = "";                            // the token says who it is
        } else if (user == null || user.isBlank()) {
            throw new SQLException("no 'user' - seclume does not guess the database user");
        }

        SecretProvider secret;
        try {
            if (kerberos) {
                String spn = parsed.option("serverSpn",
                        "MSSQLSvc/" + parsed.host() + ":" + parsed.port());
                secret = space.seclume.sqlserver.tds.Kerberos.of(spn);
            } else {
                secret = SecretProviders.of(new HashMap<>(parsed.options()));
            }
            if (token) {
                secret = space.seclume.sqlserver.tds.AccessToken.of(secret);
            }
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

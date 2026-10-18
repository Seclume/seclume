package space.seclume.r2dbc;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryOptions;
import io.r2dbc.spi.ConnectionFactoryProvider;
import io.r2dbc.spi.Option;

/**
 * {@code r2dbc:seclume:<database>://user@host:port/name?provider=...} -
 * found by {@code ConnectionFactories} and by Spring Boot's
 * {@code spring.r2dbc.url}.
 *
 * <p>The query options are the seclume JDBC driver's own and go to it
 * unchanged: the secret provider ({@code provider}, {@code path}, ...), the
 * TLS settings, everything the driver's URL takes. <b>R2DBC's
 * {@code password} option is refused</b>: it is a {@code CharSequence} the
 * application holds and passes along, on the heap for as long as the
 * factory lives - the leak seclume is there to close.
 */
public final class SeclumeConnectionFactoryProvider implements ConnectionFactoryProvider {

    /** {@code DRIVER} of the URL: {@code r2dbc:seclume:...}. */
    public static final String DRIVER = "seclume";

    private static final Set<String> DATABASES =
            Set.of("postgresql", "postgres", "mysql", "mariadb", "sqlserver", "mssql", "oracle");

    /**
     * The seclume JDBC options passed on when they are in the URL. R2DBC hands
     * a provider the options it asks for by name, not a list of what is
     * there, so the names are spelled out here; {@code options} carries any
     * other ones as a raw query string ({@code a=1&b=2}).
     */
    private static final List<String> PASSED_ON = List.of(
            "provider", "path", "env", "secret", "vault", "region", "key", "role", "audience",
            "tls", "sslmode", "tlsStack", "tlsRootCert", "tlsPin", "trustServerCertificate",
            "clientCert", "clientKey", "clientCertSubject", "applicationName", "connectTimeout",
            "socketTimeout", "rewriteBatchedInserts", "currentSchema", "encrypt", "tds",
            "nativeEncryption", "legacyVerifier11g", "service", "databaseName", "options");

    /** For the ServiceLoader. */
    public SeclumeConnectionFactoryProvider() {
    }

    @Override
    public ConnectionFactory create(ConnectionFactoryOptions options) {
        return SeclumeConnectionFactory.forUrl(jdbcUrl(options), protocol(options));
    }

    /** The seclume JDBC URL the options describe. */
    static String jdbcUrl(ConnectionFactoryOptions options) {
        if (options.hasOption(ConnectionFactoryOptions.PASSWORD)) {
            throw new IllegalArgumentException("seclume takes no password option - it would be a "
                    + "String on the heap for as long as the factory lives. Name a secret "
                    + "provider instead, as with the JDBC driver: ?provider=file&path=/run/secrets/db, "
                    + "provider=env, provider=vault ...");
        }
        String protocol = protocol(options);
        String host = String.valueOf(options.getRequiredValue(ConnectionFactoryOptions.HOST));
        Object port = options.getValue(ConnectionFactoryOptions.PORT);
        Object database = options.getValue(ConnectionFactoryOptions.DATABASE);
        StringBuilder url = new StringBuilder("jdbc:seclume:")
                .append(jdbcName(protocol)).append("://").append(host);
        if (port != null) {
            url.append(':').append(port);
        }
        url.append('/');
        if (database != null) {
            url.append(database);
        }
        char separator = '?';
        Object user = options.getValue(ConnectionFactoryOptions.USER);
        if (user != null) {
            url.append(separator).append("user=").append(encode(user));
            separator = '&';
        }
        Object ssl = options.getValue(ConnectionFactoryOptions.SSL);
        if (Boolean.FALSE.equals(ssl) || "false".equals(String.valueOf(ssl))) {
            url.append(separator).append("tls=off");
            separator = '&';
        }
        for (String name : PASSED_ON) {
            Object value = options.getValue(Option.valueOf(name));
            if (value == null) {
                continue;
            }
            if (name.equals("options")) {
                url.append(separator).append(value);
            } else {
                url.append(separator).append(name).append('=').append(encode(value));
            }
            separator = '&';
        }
        return url.toString();
    }

    @Override
    public boolean supports(ConnectionFactoryOptions options) {
        Object driver = options.getValue(ConnectionFactoryOptions.DRIVER);
        Object protocol = options.getValue(ConnectionFactoryOptions.PROTOCOL);
        return DRIVER.equals(driver) && protocol != null
                && DATABASES.contains(String.valueOf(protocol).toLowerCase(Locale.ROOT));
    }

    @Override
    public String getDriver() {
        return DRIVER;
    }

    private static String protocol(ConnectionFactoryOptions options) {
        String protocol = String.valueOf(options.getRequiredValue(ConnectionFactoryOptions.PROTOCOL))
                .toLowerCase(Locale.ROOT);
        if (!DATABASES.contains(protocol)) {
            throw new IllegalArgumentException("no seclume driver for '" + protocol + "' - one of "
                    + DATABASES);
        }
        return protocol;
    }

    /** The JDBC URL's name for the database. */
    private static String jdbcName(String protocol) {
        return switch (protocol) {
            case "postgres" -> "postgresql";
            case "mssql" -> "sqlserver";
            default -> protocol;
        };
    }

    private static String encode(Object value) {
        return URLEncoder.encode(String.valueOf(value), StandardCharsets.UTF_8);
    }
}

package space.seclume.spring;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.jdbc.autoconfigure.JdbcConnectionDetails;
import org.springframework.context.annotation.Bean;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.secret.SecretProvider;

/**
 * A seclume pool for the database that Testcontainers' {@code @ServiceConnection}
 * or Spring Boot's Docker Compose support started - the standard way to wire a
 * test or a development database today.
 *
 * <p>Both hand over a {@link JdbcConnectionDetails}: the container's JDBC URL,
 * user and password. When there is one and no {@code seclume.datasources} is
 * configured, the URL is turned into seclume's ({@code jdbc:postgresql:} into
 * {@code jdbc:seclume:postgresql:}, and the MySQL, MariaDB, SQL Server and
 * Oracle forms the containers use) and becomes the application's pool.
 *
 * <p><b>The password arrives as a {@code String}</b> - that is how the
 * containers report it, and it is on the heap before seclume sees it. It is
 * copied into native memory for each login like any secret, and the log says
 * plainly that this path is for tests and development: a production
 * configuration names a secret provider, and there this class does nothing.
 */
@AutoConfiguration(
        beforeName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration"},
        afterName = {
            "space.seclume.spring.SeclumeAutoConfiguration",
            "org.springframework.boot.testcontainers.service.connection.ServiceConnectionAutoConfiguration"})
@ConditionalOnClass({JdbcConnectionDetails.class, SeclumePool.class})
public class SeclumeConnectionDetailsAutoConfiguration {

    private static final System.Logger LOG =
            System.getLogger(SeclumeConnectionDetailsAutoConfiguration.class.getName());

    @Bean(destroyMethod = "close")
    @ConditionalOnBean(JdbcConnectionDetails.class)
    @ConditionalOnMissingBean(DataSource.class)
    SeclumePool dataSource(JdbcConnectionDetails details) {
        String url = translate(details.getJdbcUrl());
        LOG.log(System.Logger.Level.INFO, "seclume: a pool for " + space.seclume.internal
                .JdbcUrl.redact(url) + " from a container's connection details - its "
                + "password came as a String, which is fine for a test or development "
                + "database and why a production configuration names a secret provider");
        DataSource source = SeclumeDataSources.forUrl("main",
                SeclumeDataSources.withResultLimit("main", url, Runtime.getRuntime().maxMemory()),
                details.getUsername(), new Given(details.getPassword()));
        PoolSettings settings = new PoolSettings();
        settings.setName("seclume-main");
        return new SeclumePool(source, settings);
    }

    /**
     * A container's JDBC URL in seclume's form. Its query options are the
     * vendor driver's and are dropped; what the containers need instead is
     * added - a public key over an unencrypted MySQL connection, and trust in
     * the self-signed certificate a SQL Server container makes.
     */
    static String translate(String url) {
        String lower = url.toLowerCase(Locale.ROOT);
        if (lower.startsWith("jdbc:postgresql:")) {
            return "jdbc:seclume:postgresql:" + withoutQuery(url.substring("jdbc:postgresql:".length()));
        }
        if (lower.startsWith("jdbc:mysql:") || lower.startsWith("jdbc:mariadb:")) {
            String rest = url.substring(url.indexOf(':', 5) + 1);
            return "jdbc:seclume:mysql:" + withoutQuery(rest) + "?allowPublicKeyRetrieval=true";
        }
        if (lower.startsWith("jdbc:sqlserver:")) {
            String[] parts = url.substring("jdbc:sqlserver:".length()).split(";");
            String database = "master";
            for (String part : parts) {
                int equals = part.indexOf('=');
                if (equals > 0 && part.substring(0, equals).trim().equalsIgnoreCase("databaseName")) {
                    database = part.substring(equals + 1).trim();
                }
            }
            return "jdbc:seclume:sqlserver:" + parts[0] + "/" + database
                    + "?trustServerCertificate=true";
        }
        if (lower.startsWith("jdbc:oracle:thin:@")) {
            String address = url.substring("jdbc:oracle:thin:@".length());
            if (!address.startsWith("//")) {
                address = "//" + address;
            }
            return "jdbc:seclume:oracle:" + withoutQuery(address);
        }
        if (lower.startsWith("jdbc:seclume:")) {
            return url;
        }
        throw new IllegalStateException("seclume cannot use the container's URL "
                + space.seclume.internal.JdbcUrl.redact(url) + " - it reads PostgreSQL, "
                + "MySQL, MariaDB, SQL Server and Oracle");
    }

    private static String withoutQuery(String address) {
        int question = address.indexOf('?');
        return question < 0 ? address : address.substring(0, question);
    }

    /** The container's password, written into native memory for each login. */
    private record Given(String password) implements SecretProvider {

        @Override
        public int maxSecretLength() {
            return password.length() * 4;
        }

        @Override
        public int writeSecret(MemorySegment target) {
            byte[] bytes = password.getBytes(StandardCharsets.UTF_8); // seclume-allow: a container's test password, a String before seclume sees it
            try {
                MemorySegment.copy(bytes, 0, target, ValueLayout.JAVA_BYTE, 0, bytes.length);
                return bytes.length;
            } finally {
                java.util.Arrays.fill(bytes, (byte) 0);
            }
        }
    }
}

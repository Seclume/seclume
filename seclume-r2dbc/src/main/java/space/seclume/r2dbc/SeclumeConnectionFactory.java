package space.seclume.r2dbc;

import java.sql.DriverManager;
import java.util.Objects;

import javax.sql.DataSource;

import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.ConnectionFactoryMetadata;
import reactor.core.publisher.Mono;

/**
 * R2DBC over seclume: each connection a seclume JDBC connection, its calls on
 * a virtual thread of its own.
 *
 * <p><b>Why over JDBC.</b> Everything that makes seclume what it is - the
 * protocols, its own TLS, the secret providers, the password never on the
 * heap, the session reset on every return - is in the JDBC drivers and the
 * pool. An R2DBC driver of its own would be all of that again. Over JDBC on
 * virtual threads, a blocked read costs a virtual thread, not one of the
 * few threads a reactive application runs on.
 *
 * <p>From a URL - {@code r2dbc:seclume:postgresql://app@host/db?provider=file&path=...},
 * through {@code ConnectionFactories} and {@link SeclumeConnectionFactoryProvider} - or
 * over any DataSource, a {@code SeclumePool} included:
 *
 * <pre>
 * ConnectionFactory factory = SeclumeConnectionFactory.over(pool, "postgresql");
 * </pre>
 */
public final class SeclumeConnectionFactory implements ConnectionFactory {

    private final DataSource source;
    private final Placeholders.Dialect dialect;

    private SeclumeConnectionFactory(DataSource source, Placeholders.Dialect dialect) {
        this.source = source;
        this.dialect = dialect;
    }

    /**
     * Connections from {@code source} - a seclume driver's DataSource or a
     * {@code SeclumePool} over one - with the placeholders of {@code database}:
     * postgresql, mysql, mariadb, sqlserver or oracle.
     */
    public static SeclumeConnectionFactory over(DataSource source, String database) {
        return new SeclumeConnectionFactory(Objects.requireNonNull(source, "source"),
                Placeholders.Dialect.of(database));
    }

    /**
     * Connections from {@code source}, with the placeholders of whichever
     * database each connection turns out to be on - for a pool whose URL is
     * configured elsewhere, as Spring Boot's is.
     */
    public static SeclumeConnectionFactory over(DataSource source) {
        return new SeclumeConnectionFactory(Objects.requireNonNull(source, "source"), null);
    }

    /** Connections to a seclume JDBC URL ({@code jdbc:seclume:postgresql://...}). */
    static SeclumeConnectionFactory forUrl(String jdbcUrl, String database) {
        return new SeclumeConnectionFactory(new UrlSource(jdbcUrl),
                Placeholders.Dialect.of(database));
    }

    @Override
    public Mono<Connection> create() {
        return Mono.defer(() -> {
            Lane lane = new Lane();
            return lane.call(() -> {
                java.sql.Connection jdbc = source.getConnection();
                try {
                    Placeholders.Dialect spoken = dialect != null ? dialect
                            : Placeholders.Dialect.ofProduct(
                                    jdbc.getMetaData().getDatabaseProductName());
                    return (Connection) new SeclumeConnection(jdbc, lane, spoken);
                } catch (java.sql.SQLException | RuntimeException e) {
                    jdbc.close();
                    throw e;
                }
            }).doOnError(failure -> lane.close());
        });
    }

    @Override
    public ConnectionFactoryMetadata getMetadata() {
        return () -> "seclume";
    }

    /** DriverManager for one URL - the driver is found by its prefix. */
    private record UrlSource(String url) implements DataSource {

        @Override
        public java.sql.Connection getConnection() throws java.sql.SQLException {
            return DriverManager.getConnection(url);
        }

        @Override
        public java.sql.Connection getConnection(String user, String password)
                throws java.sql.SQLException {
            throw new java.sql.SQLFeatureNotSupportedException(
                    "a password as a String is what seclume exists to avoid");
        }

        @Override
        public java.io.PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(java.io.PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public java.util.logging.Logger getParentLogger() {
            return java.util.logging.Logger.getLogger("space.seclume.r2dbc");
        }

        @Override
        public <T> T unwrap(Class<T> type) throws java.sql.SQLException {
            throw new java.sql.SQLException("this DataSource stands for a seclume JDBC URL and wraps nothing - there is no "
                    + type.getName() + " behind it");
        }

        @Override
        public boolean isWrapperFor(Class<?> type) {
            return false;
        }

        @Override
        public String toString() {
            // The URL names a secret provider and a path, never a secret.
            return "DriverManager(" + url + ")";
        }
    }
}

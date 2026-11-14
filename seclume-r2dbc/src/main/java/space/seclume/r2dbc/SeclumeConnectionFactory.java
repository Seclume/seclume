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
            // A pool with a connection ready lends it without waiting for
            // anything: taken on the subscriber's thread, it saves the hop to
            // a virtual thread of its own - a carrier woken and parked again
            // for a borrow that blocks on nothing (R2dbcPoolBenchmark under
            // JFR: ForkJoinPool.deactivate was the top frame, 16 %).
            // Anything that could wait - no free connection, a reset not yet
            // answered, a validation due - is the lane's, as before.
            if (dialect != null && source instanceof space.seclume.ImmediateBorrow ready) {
                java.sql.Connection jdbc;
                try {
                    jdbc = ready.getConnectionIfReady();
                } catch (java.sql.SQLException | RuntimeException e) {
                    return Mono.error(Errors.translate(e));
                }
                if (jdbc != null) {
                    return describe(jdbc);
                }
            }
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

    /**
     * The R2DBC connection over one already borrowed. SeclumeConnection asks
     * it for its auto-commit, isolation and server version: seclume's
     * PostgreSQL and MySQL drivers answer all three from what they hold, so
     * that is done here, on the subscriber's thread. Any other driver may ask
     * the server - SQL Server's and Oracle's do for the version, pgJDBC for
     * the isolation - and is asked on the lane.
     */
    private Mono<Connection> describe(java.sql.Connection jdbc) {
        Lane lane = new Lane();
        try {
            boolean answersLocally = (dialect == Placeholders.Dialect.POSTGRESQL
                    || dialect == Placeholders.Dialect.MYSQL)
                    && jdbc.isWrapperFor(space.seclume.SessionReset.class);
            if (answersLocally) {
                return Mono.just((Connection) new SeclumeConnection(jdbc, lane, dialect));
            }
        } catch (java.sql.SQLException | RuntimeException e) {
            lane.close();
            closeQuietly(jdbc);
            return Mono.error(Errors.translate(e));
        }
        return lane.call(() -> {
            try {
                return (Connection) new SeclumeConnection(jdbc, lane, dialect);
            } catch (java.sql.SQLException | RuntimeException e) {
                jdbc.close();
                throw e;
            }
        }).doOnError(failure -> lane.close());
    }

    private static void closeQuietly(java.sql.Connection jdbc) {
        try {
            jdbc.close();
        } catch (java.sql.SQLException ignored) {
            // The borrow failed already; that is what the subscriber hears.
        }
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

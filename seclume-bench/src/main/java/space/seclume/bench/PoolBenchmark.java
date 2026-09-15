package space.seclume.bench;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.infra.Blackhole;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * Borrowing and returning a connection - the operation an application does
 * most often and thinks about least.
 *
 * <p>Three combinations, and the third is the point:
 *
 * <ul>
 *   <li>{@code hikari-vendor} - what almost everybody runs today.</li>
 *   <li>{@code seclume-vendor} - this pool over the vendor driver, so that
 *       the pool alone is compared.</li>
 *   <li>{@code seclume-seclume} - the combination this library offers.</li>
 * </ul>
 *
 * <p>Measured with several threads, because a pool that is fast without
 * contention says nothing: the whole difficulty is the handover between
 * threads.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@Threads(8)
@State(Scope.Benchmark)
public class PoolBenchmark {

    /** Which pool over which driver. */
    @Param({"hikari-vendor", "seclume-vendor", "seclume-seclume"})
    public String combination;

    /** How large the pool may grow. */
    @Param({"16"})
    public int size;

    private BenchDatabase database;
    private DataSource pool;
    private String selectOne;

    @Setup(Level.Trial)
    public void open() throws SQLException {
        database = BenchDatabase.fromSystemProperties();
        selectOne = database.selectOne();
        pool = switch (combination) {
            case "hikari-vendor" -> hikari();
            case "seclume-vendor" -> seclume(vendorDataSource());
            case "seclume-seclume" -> seclume(database.seclume());
            default -> throw new IllegalArgumentException("unknown combination: " + combination);
        };
        // Fill the pool before measuring; otherwise the first iterations
        // measure logins.
        try (Connection connection = pool.getConnection()) {
            connection.getCatalog();
        }
    }

    private DataSource hikari() throws SQLException {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(database.vendorUrl());
        config.setUsername(database.user());
        config.setPassword(database.vendorPassword());
        config.setMaximumPoolSize(size);
        config.setMinimumIdle(size);
        config.setPoolName("hikari-bench");
        return new HikariDataSource(config);
    }

    private DataSource vendorDataSource() throws SQLException {
        String url = database.vendorUrl();
        java.util.Properties properties = database.vendorProperties();
        // The plainest possible DataSource over DriverManager, so that the
        // vendor pool and this pool see exactly the same driver.
        return new DriverManagerDataSource(url, properties);
    }

    private DataSource seclume(DataSource source) {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(size);
        settings.setWarmup(true);
        settings.setName("seclume-bench");
        // Only when asked: otherwise the pool's own default is what gets
        // measured, which is the number a user actually gets.
        Integer cache = Integer.getInteger("bench.statementCache");
        if (cache != null) {
            settings.setStatementCacheSize(cache);
        }
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return new SeclumePool(source, settings);
    }

    @TearDown(Level.Trial)
    public void close() throws Exception {
        if (pool instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    @Benchmark
    public void borrowAndReturn(Blackhole hole) throws SQLException {
        try (Connection connection = pool.getConnection()) {
            hole.consume(connection);
        }
    }

    /**
     * Borrow, prepare, execute, return - what a framework actually does.
     *
     * <p>{@link #borrowQueryReturn} uses a plain {@code Statement}, and that
     * turns out to measure the one path applications almost never take:
     * Hibernate and Spring Data prepare every statement, always. The two
     * shapes are not interchangeable either - the prepared one is where a
     * statement cache in the pool can do something, and where a driver that
     * stops re-describing its results on every execution shows up.
     *
     * <p>The statement is prepared inside the borrow on purpose. Hoisting it
     * out would measure a connection nobody gives back, which is not a pool.
     */
    @Benchmark
    public void borrowPreparedReturn(Blackhole hole) throws SQLException {
        try (Connection connection = pool.getConnection();
             java.sql.PreparedStatement statement = connection.prepareStatement(selectOne);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }

    @Benchmark
    public void borrowQueryReturn(Blackhole hole) throws SQLException {
        try (Connection connection = pool.getConnection();
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(selectOne)) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }
}

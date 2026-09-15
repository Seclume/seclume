package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * The tail, not the mean.
 *
 * <p>Every other measurement in this project reports an average, and on the
 * ordinary query shape the averages are level: one round trip is the floor,
 * and the work above it is already under a microsecond. What is <b>not</b>
 * level is allocation - 440 bytes per operation against 832 for HikariCP over
 * pgjdbc - and the claim that has been made from it is that fewer young
 * objects mean fewer and shorter garbage collections.
 *
 * <p>That claim is invisible in a mean. It lives in the tail: the operation
 * that was unlucky enough to be running when a collection happened. So this
 * benchmark reports <b>percentiles</b> ({@code Mode.SampleTime}) instead, and
 * runs with enough threads that the collector actually has something to do.
 *
 * <p>It is deliberately the same operation as
 * {@code PoolBenchmark.borrowPreparedReturn} - borrow, prepare, execute,
 * return - because that is what a framework does, and because a claim about
 * allocation has to be tested on the shape that allocates.
 *
 * <p>Run it with a small heap and several threads, or the collector never
 * runs and the tail measures nothing:
 *
 * <pre>
 * java -jar seclume-bench.jar TailBenchmark -t 16 \
 *      -jvmArgs "-Xmx256m --enable-native-access=ALL-UNNAMED" -prof gc
 * </pre>
 */
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED", "-Xmx256m"})
@Warmup(iterations = 3, time = 3)
@Measurement(iterations = 5, time = 5)
@State(Scope.Benchmark)
public class TailBenchmark {

    /** Which pool over which driver - the same three as everywhere else. */
    @Param({"hikari-vendor", "seclume-seclume"})
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
        // Fill the pool before measuring: a connection opened during the
        // measurement is a login in the tail, and that would be measuring the
        // warm-up rather than the steady state.
        try (Connection connection = pool.getConnection()) {
            connection.getCatalog();
        }
    }

    @TearDown(Level.Trial)
    public void close() throws Exception {
        if (pool instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    /** Borrow, prepare, execute, return - what a framework does all day. */
    @Benchmark
    public void borrowPreparedReturn(Blackhole hole) throws SQLException {
        try (Connection connection = pool.getConnection();
             PreparedStatement statement = connection.prepareStatement(selectOne);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }

    private DataSource hikari() throws SQLException {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(database.vendorUrl());
        config.setDataSourceProperties(database.vendorProperties());
        config.setMaximumPoolSize(size);
        config.setMinimumIdle(size);
        config.setPoolName("hikari-tail");
        return new HikariDataSource(config);
    }

    private DataSource vendorDataSource() throws SQLException {
        return new DriverManagerDataSource(database.vendorUrl(), database.vendorProperties());
    }

    private DataSource seclume(DataSource source) {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(size);
        settings.setWarmup(true);
        settings.setName("seclume-tail");
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return new SeclumePool(source, settings);
    }
}

package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
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
 * What the statement cache is worth - the shape a framework actually produces.
 *
 * <p>Borrow, prepare, execute, close, give back: that is what Spring Data and
 * Hibernate do per operation. Without the cache every one of those makes the
 * server parse the same text again; with it the plan stays in the session.
 *
 * <p>Measured against the same server either way, so the difference is the
 * cache and nothing else.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Threads(8)
@State(Scope.Benchmark)
public class StatementCacheBenchmark {

    /** How many statements a connection keeps; 0 is the old behaviour. */
    @Param({"0", "32"})
    public int cache;

    private BenchDatabase database;
    private SeclumePool pool;
    private String selectOne;

    @Setup(Level.Trial)
    public void open() throws SQLException {
        database = BenchDatabase.fromSystemProperties();
        selectOne = database.selectOne();
        PoolSettings settings = new PoolSettings();
        settings.setName("statement-cache-bench");
        settings.setMaximumPoolSize(16);
        settings.setMinimumIdle(16);
        settings.setWarmup(true);
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        settings.setStatementCacheSize(cache);
        pool = new SeclumePool(database.seclume(), settings);
    }

    @TearDown(Level.Trial)
    public void close() {
        pool.close();
    }

    @Benchmark
    public void borrowPrepareExecuteReturn(Blackhole hole) throws SQLException {
        try (Connection connection = pool.getConnection();
             PreparedStatement query = connection.prepareStatement(selectOne);
             ResultSet result = query.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }
}

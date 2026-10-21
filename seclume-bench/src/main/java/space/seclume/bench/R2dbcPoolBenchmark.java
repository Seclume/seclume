package space.seclume.bench;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
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

import io.r2dbc.pool.ConnectionPool;
import io.r2dbc.pool.ConnectionPoolConfiguration;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Mono;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.r2dbc.SeclumeConnectionFactory;

/**
 * Borrow, one prepared query, give back - from eight threads, as
 * {@link PoolBenchmark} does with JDBC.
 *
 * <p>seclume's side borrows from {@code SeclumePool}, which resets the
 * session on every return; r2dbc-postgresql's from r2dbc-pool, which by
 * default resets nothing. So the {@code seclume} row pays for a reset the
 * other one does not make, as it does against HikariCP in PoolBenchmark.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Threads(8)
@State(Scope.Benchmark)
public class R2dbcPoolBenchmark {

    private static final Duration WAIT = Duration.ofSeconds(30);

    @Param({"seclume", "r2dbc-pool"})
    public String pool;

    @Param({"16"})
    public int size;

    private ConnectionFactory factory;
    private AutoCloseable closing;

    @Setup(Level.Trial)
    public void open() throws Exception {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        if (pool.equals("seclume")) {
            PoolSettings settings = new PoolSettings();
            settings.setMaximumPoolSize(size);
            settings.setMinimumIdle(size);
            settings.setWarmup(true);
            settings.setName("seclume-r2dbc-bench");
            settings.setConnectionTimeout(Duration.ofSeconds(10));
            SeclumePool seclume = new SeclumePool(database.seclume(), settings);
            closing = seclume;
            factory = SeclumeConnectionFactory.over(seclume, "postgresql");
        } else {
            ConnectionPool vendor = new ConnectionPool(ConnectionPoolConfiguration
                    .builder(R2dbcBenchmark.vendor(database))
                    .initialSize(size)
                    .maxSize(size)
                    .build());
            Mono.from(vendor.warmup()).block(WAIT);
            closing = vendor::dispose;
            factory = vendor;
        }
        // The first borrow outside the measurement.
        Mono.from(factory.create()).flatMap(c -> Mono.from(c.close())).block(WAIT);
    }

    @TearDown(Level.Trial)
    public void close() throws Exception {
        closing.close();
    }

    @Benchmark
    public void borrowPreparedReturn(Blackhole hole) {
        // Reactive all the way through: r2dbc-postgresql answers on Netty's
        // threads, where blocking is refused.
        Mono.usingWhen(factory.create(),
                c -> reactor.core.publisher.Flux.from(
                                c.createStatement(R2dbcBenchmark.ROW).bind(0, 1).execute())
                        .concatMap(r -> r.map((row, meta) -> {
                            hole.consume(row.get(0, Integer.class));
                            hole.consume(row.get(1, String.class));
                            return row.get(2);
                        }))
                        .doOnNext(hole::consume)
                        .then(),
                Connection::close).block(WAIT);
    }
}

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
import org.openjdk.jmh.infra.Blackhole;

import io.r2dbc.pool.ConnectionPool;
import io.r2dbc.pool.ConnectionPoolConfiguration;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.r2dbc.SeclumeConnectionFactory;

/**
 * Many more requests than connections: a batch of {@code requests} queries
 * subscribed at once against a pool of 16, all of them waiting for a
 * connection, from one thread - what a reactive service under load does.
 *
 * <p>This is where a driver that waits on a virtual thread per connection
 * would show a cost against one that waits on Netty's event loop, if there
 * were one to show: the requests queue at the pool either way, and the time
 * of a batch is the pool's hand-over plus the statements. One operation is a
 * whole batch; divide by {@code requests} for a statement. As in
 * {@link R2dbcPoolBenchmark}, seclume's pool resets the session on every
 * return and r2dbc-pool resets nothing.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@State(Scope.Benchmark)
public class R2dbcContentionBenchmark {

    private static final Duration WAIT = Duration.ofMinutes(2);
    private static final int SIZE = 16;

    @Param({"seclume", "r2dbc-pool"})
    public String pool;

    @Param({"64", "512"})
    public int requests;

    private ConnectionFactory factory;
    private AutoCloseable closing;

    @Setup(Level.Trial)
    public void open() throws Exception {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        if (pool.equals("seclume")) {
            PoolSettings settings = new PoolSettings();
            settings.setMaximumPoolSize(SIZE);
            settings.setMinimumIdle(SIZE);
            settings.setWarmup(true);
            settings.setName("seclume-r2dbc-contention");
            settings.setConnectionTimeout(Duration.ofSeconds(60));
            SeclumePool seclume = new SeclumePool(database.seclume(), settings);
            closing = seclume;
            factory = SeclumeConnectionFactory.over(seclume, "postgresql");
        } else {
            ConnectionPool vendor = new ConnectionPool(ConnectionPoolConfiguration
                    .builder(R2dbcBenchmark.vendor(database))
                    .initialSize(SIZE)
                    .maxSize(SIZE)
                    .maxAcquireTime(Duration.ofSeconds(60))
                    .build());
            Mono.from(vendor.warmup()).block(WAIT);
            closing = vendor::dispose;
            factory = vendor;
        }
        Mono.from(factory.create()).flatMap(c -> Mono.from(c.close())).block(WAIT);
    }

    @TearDown(Level.Trial)
    public void close() throws Exception {
        closing.close();
    }

    @Benchmark
    public long batch(Blackhole hole) {
        Long rows = Flux.range(0, requests)
                .flatMap(i -> Mono.usingWhen(factory.create(),
                        c -> Flux.from(c.createStatement(R2dbcBenchmark.ROW).bind(0, 1).execute())
                                .concatMap(r -> r.map((row, meta) -> row.get(1, String.class)))
                                .doOnNext(hole::consume)
                                .count(),
                        Connection::close), requests)
                .reduce(0L, Long::sum)
                .block(WAIT);
        if (rows == null || rows != requests) {
            throw new IllegalStateException(requests + " rows were expected, not " + rows);
        }
        return rows;
    }
}

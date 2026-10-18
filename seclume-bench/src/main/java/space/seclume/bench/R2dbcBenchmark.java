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

import io.r2dbc.postgresql.PostgresqlConnectionConfiguration;
import io.r2dbc.postgresql.PostgresqlConnectionFactory;
import io.r2dbc.postgresql.client.SSLMode;
import io.r2dbc.spi.Connection;
import io.r2dbc.spi.ConnectionFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import space.seclume.r2dbc.SeclumeConnectionFactory;

/**
 * R2DBC on PostgreSQL: seclume's, which is the seclume JDBC driver on a
 * virtual thread per connection, against r2dbc-postgresql, which is Netty.
 *
 * <p>One connection per benchmark thread, held for the whole trial, so this
 * is what a statement costs and not what a connection does - for the pool,
 * see {@link R2dbcPoolBenchmark}. Both encrypt or neither ({@code -Dbench.tls}),
 * and both bind with {@code $1}.
 *
 * <pre>  -Dbench.db=postgresql ... R2dbcBenchmark</pre>
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@State(Scope.Thread)
public class R2dbcBenchmark {

    static final Duration WAIT = Duration.ofSeconds(30);
    static final String ONE = "select 1";
    static final String ROW = "select 1, 'text', 1.5 where 1 = $1";
    static final String ROWS = "select i, 'text-' || i, i * 1.5 from generate_series(1, 1000) i";

    @Param({"seclume", "r2dbc-postgresql"})
    public String driver;

    private ConnectionFactory factory;
    private Connection connection;

    @Setup(Level.Trial)
    public void open() throws Exception {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        if (database.kind() != BenchDatabase.Kind.POSTGRESQL) {
            throw new IllegalStateException("R2DBC is compared on PostgreSQL only");
        }
        factory = driver.equals("seclume")
                ? SeclumeConnectionFactory.over(database.seclume(), "postgresql")
                : vendor(database);
        connection = Mono.from(factory.create()).block(WAIT);
    }

    /** r2dbc-postgresql, set up as its documentation shows - password as a String. */
    static ConnectionFactory vendor(BenchDatabase database) throws Exception {
        return new PostgresqlConnectionFactory(PostgresqlConnectionConfiguration.builder()
                .host(database.host())
                .port(database.port())
                .database(database.database())
                .username(database.user())
                .password(database.vendorPassword())
                .sslMode(database.tls() ? SSLMode.REQUIRE : SSLMode.DISABLE)
                .build());
    }

    @TearDown(Level.Trial)
    public void close() {
        if (connection != null) {
            Mono.from(connection.close()).block(WAIT);
        }
    }

    static void selectOne(Connection connection, Blackhole hole) {
        Flux.from(connection.createStatement(ONE).execute())
                .concatMap(r -> r.map((row, meta) -> row.get(0, Integer.class)))
                .doOnNext(hole::consume)
                .blockLast(WAIT);
    }

    static void selectRow(Connection connection, Blackhole hole) {
        Flux.from(connection.createStatement(ROW).bind(0, 1).execute())
                .concatMap(r -> r.map((row, meta) -> {
                    hole.consume(row.get(0, Integer.class));
                    hole.consume(row.get(1, String.class));
                    return row.get(2);
                }))
                .doOnNext(hole::consume)
                .blockLast(WAIT);
    }

    @Benchmark
    public void selectOne(Blackhole hole) {
        selectOne(connection, hole);
    }

    @Benchmark
    public void selectRow(Blackhole hole) {
        selectRow(connection, hole);
    }

    @Benchmark
    public void selectManyRows(Blackhole hole) {
        Flux.from(connection.createStatement(ROWS).execute())
                .concatMap(r -> r.map((row, meta) -> {
                    hole.consume(row.get(0, Integer.class));
                    hole.consume(row.get(1, String.class));
                    return row.get(2);
                }))
                .doOnNext(hole::consume)
                .blockLast(WAIT);
    }
}

package space.seclume.bench;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.TimeUnit;

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
import org.openjdk.jmh.infra.Blackhole;

/**
 * One transaction with one statement - the shape of most of the world's
 * database traffic.
 *
 * <p>A method annotated {@code @Transactional} that writes one row does
 * exactly this: switch auto-commit off, run a statement, commit. What it costs
 * is not the statement but the <b>number of round trips</b> a driver needs for
 * the three steps. A driver that sends {@code BEGIN} on its own, and another
 * one after every commit, needs four where two are enough - and over a network
 * that is the whole difference.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@State(Scope.Benchmark)
public class TransactionBenchmark {

    /** Which driver this run measures. */
    @Param({"seclume", "vendor"})
    public String driver;

    private BenchDatabase database;
    private Connection connection;
    private PreparedStatement insert;

    @Setup(Level.Trial)
    public void open() throws SQLException {
        database = BenchDatabase.fromSystemProperties();
        connection = "seclume".equals(driver)
                ? database.seclume().getConnection()
                : DriverManager.getConnection(database.vendorUrl(),
                        database.vendorProperties());
        connection.setAutoCommit(true);
        try (Statement statement = connection.createStatement()) {
            try {
                statement.execute("drop table zl_bench_tx");
            } catch (SQLException ignored) {
                // It was not there, which is the normal case.
            }
            statement.execute(database.createInsertTable().replace("zl_bench_insert",
                    "zl_bench_tx"));
        }
        insert = connection.prepareStatement("insert into zl_bench_tx (n, t) values (?, ?)");
    }

    @Setup(Level.Iteration)
    public void empty() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("delete from zl_bench_tx");
        }
    }

    @TearDown(Level.Trial)
    public void close() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop table zl_bench_tx");
        } catch (SQLException ignored) {
            // The measurement is over; a leftover table is not worth an abort.
        }
        if (insert != null) {
            insert.close();
        }
        connection.close();
    }

    @Benchmark
    public void oneStatementPerTransaction(Blackhole hole) throws SQLException {
        connection.setAutoCommit(false);
        try {
            insert.setInt(1, 1);
            insert.setString(2, "one");
            hole.consume(insert.executeUpdate());
            connection.commit();
        } finally {
            connection.setAutoCommit(true);
        }
    }
}

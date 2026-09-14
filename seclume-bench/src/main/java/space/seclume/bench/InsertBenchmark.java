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
 * Writing - one row at a time and as a batch.
 *
 * <p>The batch is the interesting one, and not because of microseconds: a
 * driver that sends every row of a batch on its own and waits for the answer
 * pays a full round trip per row. One that pipelines them pays one per group.
 * At five hundred rows that is not a percentage, it is a factor - which is why
 * this benchmark exists separately from the query ones.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@State(Scope.Benchmark)
public class InsertBenchmark {

    /** Which driver this run measures. */
    @Param({"seclume", "vendor"})
    public String driver;

    /** How many rows go into one batch. */
    @Param({"500"})
    public int rows;

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
                statement.execute("drop table zl_bench_insert");
            } catch (SQLException ignored) {
                // It was not there, which is the normal case.
            }
            statement.execute(database.createInsertTable());
        }
        insert = connection.prepareStatement(
                "insert into zl_bench_insert (n, t) values (?, ?)");
    }

    /**
     * Empties the table between iterations - a table that grows through the
     * whole run would measure the table, not the driver.
     */
    @Setup(Level.Iteration)
    public void empty() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("delete from zl_bench_insert");
        }
    }

    @TearDown(Level.Trial)
    public void close() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop table zl_bench_insert");
        } catch (SQLException ignored) {
            // The measurement is over; a leftover table is not worth an abort.
        }
        if (insert != null) {
            insert.close();
        }
        connection.close();
    }

    @Benchmark
    public void oneRow(Blackhole hole) throws SQLException {
        insert.setInt(1, 1);
        insert.setString(2, "one");
        hole.consume(insert.executeUpdate());
    }

    /**
     * A batch inside one transaction - the way a batch is actually used.
     *
     * <p>With autocommit on, every single row is a durable commit, and the
     * server's {@code fsync} drowns out everything the driver does: a batch
     * then measures the disk, not the protocol. One transaction around it is
     * what any application that inserts five hundred rows does, and it leaves
     * exactly the cost this benchmark is about - the round trips.
     */
    @Benchmark
    public void batch(Blackhole hole) throws SQLException {
        connection.setAutoCommit(false);
        try {
            for (int i = 0; i < rows; i++) {
                insert.setInt(1, i);
                insert.setString(2, "row-" + i);
                insert.addBatch();
            }
            hole.consume(insert.executeBatch().length);
            connection.commit();
        } finally {
            connection.setAutoCommit(true);
        }
    }
}

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

import space.seclume.Pipeline;

/**
 * A unit of work as a service writes one: an order, its three items, a
 * counter, in one transaction - four statements of three different texts,
 * then the commit.
 *
 * <p>Each side does its best with JDBC as it is: the items as one
 * {@code executeBatch}, the rest one by one - an order, a batch, an update
 * and a commit are four round trips for any driver, because each call
 * returns its count before the next is sent. {@code seclume-pipeline} makes
 * the same calls inside a {@link Pipeline}, where a write nobody waits for
 * is held back and the commit sends them together.
 *
 * <p>On localhost a round trip is tens of microseconds and the server's work
 * weighs as much; across a network each is a fraction of a millisecond or
 * more, and the ratio grows with the distance. PostgreSQL and MySQL bundle;
 * on SQL Server and Oracle the block saves nothing (see {@link Pipeline}).
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@State(Scope.Benchmark)
public class UnitOfWorkBenchmark {

    /** {@code vendor}, {@code seclume}, and seclume with the calls in a {@link Pipeline}. */
    @Param({"seclume-pipeline", "seclume", "vendor"})
    public String driver;

    private Connection connection;
    private PreparedStatement order;
    private PreparedStatement item;
    private PreparedStatement counter;
    private int next;

    @Setup(Level.Trial)
    public void open() throws SQLException {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        connection = driver.startsWith("seclume")
                ? database.seclume().getConnection()
                : DriverManager.getConnection(database.vendorUrl(), database.vendorProperties());
        connection.setAutoCommit(true);
        String table = database.createInsertTable();
        try (Statement statement = connection.createStatement()) {
            for (String name : new String[] {"zl_bench_uow_order", "zl_bench_uow_item",
                    "zl_bench_uow_counter"}) {
                try {
                    statement.execute("drop table " + name);
                } catch (SQLException ignored) {
                    // It was not there, which is the normal case.
                }
                statement.execute(table.replace("zl_bench_insert", name));
            }
            statement.execute("insert into zl_bench_uow_counter (n, t) values (0, 'orders')");
        }
        order = connection.prepareStatement("insert into zl_bench_uow_order (n, t) values (?, ?)");
        item = connection.prepareStatement("insert into zl_bench_uow_item (n, t) values (?, ?)");
        counter = connection.prepareStatement(
                "update zl_bench_uow_counter set n = n + 1 where t = 'orders'");
        // One transaction per operation, and auto-commit off throughout:
        // switching it per operation is a round trip of its own on MySQL,
        // for both drivers, and would be measured instead of the work.
        connection.setAutoCommit(false);
    }

    /** Empties the tables between iterations, so that they do not grow through the run. */
    @Setup(Level.Iteration)
    public void empty() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("delete from zl_bench_uow_order");
            statement.execute("delete from zl_bench_uow_item");
        }
        connection.commit();
    }

    @TearDown(Level.Trial)
    public void close() throws SQLException {
        connection.setAutoCommit(true);
        try (Statement statement = connection.createStatement()) {
            for (String name : new String[] {"zl_bench_uow_order", "zl_bench_uow_item",
                    "zl_bench_uow_counter"}) {
                statement.execute("drop table " + name);
            }
        } catch (SQLException ignored) {
            // The measurement is over; a leftover table is not worth an abort.
        }
        order.close();
        item.close();
        counter.close();
        connection.close();
    }

    private void writeTheOrder(Blackhole hole) throws SQLException {
        int id = next++;
        order.setInt(1, id);
        order.setString(2, "order-" + id);
        hole.consume(order.executeUpdate());
        for (int i = 0; i < 3; i++) {
            item.setInt(1, id);
            item.setString(2, "item-" + i);
            item.addBatch();
        }
        hole.consume(item.executeBatch());
        hole.consume(counter.executeUpdate());
    }

    @Benchmark
    public void orderWithItems(Blackhole hole) throws SQLException {
        if (driver.equals("seclume-pipeline")) {
            try (Pipeline unit = Pipeline.open(connection)) {
                writeTheOrder(hole);
            }
        } else {
            writeTheOrder(hole);
        }
        connection.commit();
    }
}

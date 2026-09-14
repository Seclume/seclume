package space.seclume.bench;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
 * Statements over one open connection - seclume against the vendor driver.
 *
 * <p>Three sizes, because they measure different things:
 *
 * <ul>
 *   <li>{@code selectOne} is almost pure round trip. Whoever is faster here is
 *       faster at writing and reading a message, and the network is the same
 *       for both.</li>
 *   <li>{@code selectRow} adds a bind variable and three typed columns - the
 *       shape of nearly every statement an application runs.</li>
 *   <li>{@code selectManyRows} is row decoding: a thousand rows of three
 *       columns, where the per-row cost is all that is left.</li>
 * </ul>
 *
 * <p>The connection is opened once and reused, deliberately: the login is
 * measured separately in {@link ConnectBenchmark}. Mixing the two would hide
 * whichever of them is the smaller.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Measurement(iterations = 5, time = 3)
@State(Scope.Benchmark)
public class QueryBenchmark {

    /** Which driver this run measures. */
    @Param({"seclume", "vendor"})
    public String driver;

    /** How many rows the large query produces. */
    @Param({"1000"})
    public int rows;

    private BenchDatabase database;
    private Connection connection;
    private Statement statement;
    private PreparedStatement one;
    private PreparedStatement many;

    @Setup(Level.Trial)
    public void open() throws SQLException {
        database = BenchDatabase.fromSystemProperties();
        connection = "seclume".equals(driver)
                ? database.seclume().getConnection()
                : DriverManager.getConnection(database.vendorUrl(),
                        database.vendorProperties());
        connection.setAutoCommit(true);
        statement = connection.createStatement();
        one = connection.prepareStatement(database.selectWithParameter());
        many = connection.prepareStatement(database.selectRows(rows));
    }

    @TearDown(Level.Trial)
    public void close() throws SQLException {
        for (AutoCloseable closeable : new AutoCloseable[] {many, one, statement, connection}) {
            try {
                if (closeable != null) {
                    closeable.close();
                }
            } catch (Exception e) {
                throw new SQLException(e);
            }
        }
    }

    @Benchmark
    public void selectOne(Blackhole hole) throws SQLException {
        try (ResultSet result = statement.executeQuery(database.selectOne())) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }

    @Benchmark
    public void selectRow(Blackhole hole) throws SQLException {
        one.setInt(1, 1);
        try (ResultSet result = one.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
                hole.consume(result.getString(2));
                hole.consume(result.getDouble(3));
            }
        }
    }

    @Benchmark
    public void selectManyRows(Blackhole hole) throws SQLException {
        try (ResultSet result = many.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
                hole.consume(result.getString(2));
                hole.consume(result.getDouble(3));
            }
        }
    }
}

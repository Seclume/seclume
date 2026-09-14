package space.seclume.bench;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;

import javax.sql.DataSource;

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
import org.openjdk.jmh.annotations.Warmup;

/**
 * Opening a connection - handshake, login, everything.
 *
 * <p>Its own benchmark because it is the one operation where seclume does
 * <b>more</b> work than the others: the password is derived off-heap with this
 * library's own hashes rather than with the JCA. If that cost showed anywhere,
 * it would show here - which is exactly why it is measured on its own instead
 * of being hidden inside a query benchmark.
 *
 * <p>Few iterations and a long time each: a login is expensive on every driver
 * and the server does most of the work.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
@Warmup(iterations = 2, time = 3)
@Measurement(iterations = 3, time = 5)
@State(Scope.Benchmark)
public class ConnectBenchmark {

    /** Which driver this run measures. */
    @Param({"seclume", "vendor"})
    public String driver;

    private BenchDatabase database;
    private DataSource seclume;

    @Setup(Level.Trial)
    public void prepare() throws SQLException {
        database = BenchDatabase.fromSystemProperties();
        seclume = database.seclume();
        // One connection up front so that class loading and the driver's own
        // one-time work do not land in the first measurement.
        try (Connection warmup = connect()) {
            warmup.getMetaData().getDatabaseProductName();
        }
    }

    private Connection connect() throws SQLException {
        return "seclume".equals(driver)
                ? seclume.getConnection()
                : DriverManager.getConnection(database.vendorUrl(), database.vendorProperties());
    }

    @Benchmark
    public String openAndClose() throws SQLException {
        try (Connection connection = connect()) {
            return connection.getCatalog();
        }
    }
}

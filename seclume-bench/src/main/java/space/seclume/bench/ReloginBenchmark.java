package space.seclume.bench;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;

import space.seclume.SessionReset;

/**
 * The pool's reset of an Oracle session, alone: log off and log in again on
 * the same connection ({@code OraConnection.resetSessionState}, then
 * {@code settleReset}), as the pool does at a return and before the next
 * borrow. One connection per thread, so a thread never waits for another's
 * login - what is left is the login itself, and with more threads, whether
 * it scales or meets a limit (the client's CPU, the server's).
 *
 * <p>{@link Pbkdf2Benchmark} {@code SHA_512} is the client's PBKDF2 inside
 * each of these; a statement on the new session ({@code resetThenQuery}) is
 * what the next borrower adds.
 *
 * <p>Oracle only. {@code java -Dbench.db=oracle ... -jar seclume-bench.jar ReloginBenchmark}
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
public class ReloginBenchmark {

    private Connection connection;
    private SessionReset reset;

    @Setup(Level.Trial)
    public void connect() throws SQLException {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        if (database.kind() != BenchDatabase.Kind.ORACLE) {
            throw new IllegalStateException("ReloginBenchmark measures Oracle's reset, not "
                    + database.kind());
        }
        connection = database.seclume().getConnection();
        reset = connection.unwrap(SessionReset.class);
    }

    @TearDown(Level.Trial)
    public void close() throws SQLException {
        connection.close();
    }

    private void logInAgain() throws SQLException {
        if (!reset.resetSessionState()) {
            throw new IllegalStateException("this session cannot log in again");
        }
        reset.settleReset();
    }

    @Benchmark
    public void reset() throws SQLException {
        logInAgain();
    }

    @Benchmark
    @Threads(4)
    public void resetFourThreads() throws SQLException {
        logInAgain();
    }

    @Benchmark
    public void resetThenQuery() throws SQLException {
        logInAgain();
        try (Statement statement = connection.createStatement()) {
            statement.execute("select 1 from dual");
        }
    }

    @Benchmark
    public void queryAlone() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("select 1 from dual");
        }
    }
}

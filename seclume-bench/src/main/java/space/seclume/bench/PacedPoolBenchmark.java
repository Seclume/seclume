package space.seclume.bench;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.infra.Blackhole;

/**
 * The pool as an application meets it: requests with time in between, not
 * a loop that never lets go.
 *
 * <p>{@link PoolBenchmark} drives the pool flat out, which measures its
 * throughput limit. Most applications never reach that, and what they feel
 * is the latency of each borrow at an ordinary load. That differs where a
 * reset takes time: Oracle's new session is a login, made while the
 * connection waits in the pool - with time between requests it is done
 * before anybody needs the connection, flat out it is not.
 *
 * <p>Each thread pauses {@code thinkMicros} between its requests, outside
 * the measured time, and the latency of every request is sampled: the
 * percentiles say whether a borrower ever waited for a login.
 *
 * <pre>  PacedPoolBenchmark.pacedPreparedReturn -p thinkMicros=2000</pre>
 */
@BenchmarkMode(Mode.SampleTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Threads(4)
public class PacedPoolBenchmark extends PoolBenchmark {

    /** The pause between one thread's requests - per thread, outside the measurement. */
    @State(Scope.Thread)
    public static class Pace {

        @Param({"2000"})
        public int thinkMicros;

        @Setup(Level.Invocation)
        public void pause() {
            LockSupport.parkNanos(thinkMicros * 1_000L);
        }
    }

    @Benchmark
    public void pacedPreparedReturn(Pace pace, Blackhole hole) throws SQLException {
        try (Connection connection = pool().getConnection();
             java.sql.PreparedStatement statement = connection.prepareStatement(selectOne());
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                hole.consume(result.getInt(1));
            }
        }
    }
}

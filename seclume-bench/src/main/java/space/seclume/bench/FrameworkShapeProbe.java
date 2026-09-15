package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import javax.sql.DataSource;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import space.seclume.RoundTrips;
import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * What a framework actually does per request, measured where it matters.
 *
 * <p>Every other measurement in this project runs {@code select 1} against a
 * server on the same machine, and on that shape the drivers are within a few
 * percent of each other: one round trip is the floor, and a loopback round trip
 * is twenty microseconds, so there is almost nothing above it to win or lose.
 *
 * <p>That is not what an application does. A {@code @Transactional} method
 * borrows a connection, turns autocommit off, sets an isolation level, may mark
 * the transaction read-only, runs its statement, commits, and puts the
 * connection back the way it found it. Each of those settings is a statement,
 * and a driver that sends each one on its own pays a full round trip for it -
 * in which the database does nothing at all.
 *
 * <p>This driver rides them along with the statement that follows. On loopback
 * that saves microseconds nobody notices. Over a network, where a round trip is
 * hundreds of microseconds, it is the difference between one wait and five.
 *
 * <pre>
 * java -Dbench.host=... -Dbench.port=... -Dbench.password.file=... \
 *      -cp seclume-bench.jar space.seclume.bench.FrameworkShapeProbe \
 *      seclume 8 2000
 * </pre>
 */
public final class FrameworkShapeProbe {

    private FrameworkShapeProbe() {
    }

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0] : "seclume";
        int threads = args.length > 1 ? Integer.parseInt(args[1]) : 8;
        int perThread = args.length > 2 ? Integer.parseInt(args[2]) : 2_000;

        BenchDatabase database = BenchDatabase.fromSystemProperties();
        String sql = database.selectOne();
        DataSource pool = "hikari".equals(which) ? hikari(database) : seclume(database);

        long[][] times = new long[threads][perThread];
        long roundTrips = -1;

        // Warm up, and let every connection be opened before anything is timed.
        for (int i = 0; i < 50; i++) {
            request(pool, sql);
        }
        if (!"hikari".equals(which)) {
            roundTrips = countRoundTrips(pool, sql);
        }

        CountDownLatch start = new CountDownLatch(1);
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int index = t;
            workers[t] = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        long began = System.nanoTime();
                        request(pool, sql);
                        times[index][i] = System.nanoTime() - began;
                    }
                } catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }

        long[] all = new long[threads * perThread];
        for (int t = 0; t < threads; t++) {
            System.arraycopy(times[t], 0, all, t * perThread, perThread);
        }
        Arrays.sort(all);
        System.out.printf("%-9s %2d threads  p50 %8.1f  p99 %9.1f  p99.9 %9.1f us%s%n",
                which, threads, at(all, 0.50), at(all, 0.99), at(all, 0.999),
                roundTrips < 0 ? "" : "   round trips per request: " + roundTrips);

        if (pool instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    /**
     * One request, the way a framework issues it.
     *
     * <p>Deliberately every step, including putting the connection back the way
     * it was found - a pool hands the same connection to the next request, and
     * a driver that left the isolation level changed would be a bug rather than
     * an optimisation.
     */
    private static void request(DataSource pool, String sql) throws Exception {
        try (Connection connection = pool.getConnection()) {
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setReadOnly(true);
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    rows.getInt(1);
                }
            }
            connection.commit();
            connection.setReadOnly(false);
            connection.setAutoCommit(true);
        }
    }

    /** The same request once more, counting waits instead of measuring time. */
    private static long countRoundTrips(DataSource pool, String sql) throws Exception {
        try (Connection connection = pool.getConnection()) {
            long before = RoundTrips.of(connection);
            if (before < 0) {
                return -1;
            }
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setReadOnly(true);
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    rows.getInt(1);
                }
            }
            connection.commit();
            connection.setReadOnly(false);
            connection.setAutoCommit(true);
            return RoundTrips.of(connection) - before;
        }
    }

    private static double at(long[] sorted, double quantile) {
        return sorted[Math.min((int) (sorted.length * quantile), sorted.length - 1)] / 1000.0;
    }

    private static DataSource hikari(BenchDatabase database) throws Exception {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(database.vendorUrl());
        config.setDataSourceProperties(database.vendorProperties());
        config.setMaximumPoolSize(16);
        config.setMinimumIdle(16);
        config.setPoolName("hikari-shape");
        return new HikariDataSource(config);
    }

    private static DataSource seclume(BenchDatabase database) throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(16);
        settings.setMinimumIdle(16);
        settings.setWarmup(true);
        settings.setName("seclume-shape");
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return new SeclumePool(database.seclume(), settings);
    }
}

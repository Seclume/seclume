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

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;

/**
 * Which phase of borrow-prepare-execute-return produces the tail.
 *
 * <p>{@code TailBenchmark} says p99.9 is eleven microseconds worse than
 * HikariCP over pgjdbc, and says it reproducibly: six forks, a spread of two
 * microseconds. What it cannot say is <b>where</b> those microseconds are
 * spent, because it times the whole operation as one.
 *
 * <p>So this times the four phases separately and asks the question that
 * settled the last tail: not how long on average, but <b>which phase is the
 * slow one when an operation is slow</b>. An outlier that collects in the
 * borrow is the pool's; one that collects in the execution is the network's or
 * the server's, and no amount of work on the pool would move it.
 *
 * <pre>
 * java -cp seclume-bench.jar --enable-native-access=ALL-UNNAMED \
 *      space.seclume.bench.PhaseTailProbe seclume 16 100000
 * </pre>
 */
public final class PhaseTailProbe {

    private PhaseTailProbe() {
    }

    private static final String[] PHASES = {"borrow  ", "prepare ", "execute ", "return  "};

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0] : "seclume";
        int threads = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        int perThread = args.length > 2 ? Integer.parseInt(args[2]) : 100_000;

        BenchDatabase database = BenchDatabase.fromSystemProperties();
        String sql = database.selectOne();
        DataSource pool = "hikari".equals(which) ? hikari(database, 16) : seclume(database, 16);

        // One warm-up pass, thrown away: the first borrow of each connection
        // logs in, and a login in the tail would be measuring the start-up.
        run(pool, sql, threads, 2_000, new long[threads][][]);

        long[][][] times = new long[threads][][];
        run(pool, sql, threads, perThread, times);

        System.out.println(which + ", " + threads + " threads, "
                + (threads * perThread) + " operations");
        long[][] byPhase = new long[PHASES.length][];
        for (int phase = 0; phase < PHASES.length; phase++) {
            byPhase[phase] = merge(times, phase);
            Arrays.sort(byPhase[phase]);
            report(PHASES[phase], byPhase[phase]);
        }
        blame(times, byPhase);

        if (pool instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    /** Runs the load and fills {@code into[thread][phase][operation]}. */
    private static void run(DataSource pool, String sql, int threads, int perThread,
            long[][][] into) throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int index = t;
            workers[t] = new Thread(() -> {
                long[][] mine = new long[PHASES.length][perThread];
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        long a = System.nanoTime();
                        Connection connection = pool.getConnection();
                        long b = System.nanoTime();
                        PreparedStatement statement = connection.prepareStatement(sql);
                        long c = System.nanoTime();
                        try (ResultSet rows = statement.executeQuery()) {
                            while (rows.next()) {
                                rows.getInt(1);
                            }
                        }
                        long d = System.nanoTime();
                        statement.close();
                        connection.close();
                        long e = System.nanoTime();
                        mine[0][i] = b - a;
                        mine[1][i] = c - b;
                        mine[2][i] = d - c;
                        mine[3][i] = e - d;
                    }
                } catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
                if (index < into.length) {
                    into[index] = mine;
                }
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }
    }

    private static long[] merge(long[][][] times, int phase) {
        int total = 0;
        for (long[][] thread : times) {
            total += thread[phase].length;
        }
        long[] all = new long[total];
        int at = 0;
        for (long[][] thread : times) {
            System.arraycopy(thread[phase], 0, all, at, thread[phase].length);
            at += thread[phase].length;
        }
        return all;
    }

    private static void report(String name, long[] sorted) {
        System.out.printf("  %s p50 %7.2f  p99 %8.2f  p99.9 %9.2f  max %10.1f us%n",
                name, at(sorted, 0.50), at(sorted, 0.99), at(sorted, 0.999),
                sorted[sorted.length - 1] / 1000.0);
    }

    /**
     * For the slowest operations as a whole, which phase held them up.
     *
     * <p>The percentiles above are per phase and independent of each other - a
     * phase can have a bad tail without ever being the reason an <b>operation</b>
     * was slow. This asks the other question: take the worst thousandth of the
     * operations, and count where their time actually went.
     */
    private static void blame(long[][][] times, long[][] byPhase) {
        int operations = 0;
        for (long[][] thread : times) {
            operations += thread[0].length;
        }
        long[] totals = new long[operations];
        int at = 0;
        for (long[][] thread : times) {
            for (int i = 0; i < thread[0].length; i++) {
                totals[at++] = thread[0][i] + thread[1][i] + thread[2][i] + thread[3][i];
            }
        }
        long[] sorted = totals.clone();
        Arrays.sort(sorted);
        long threshold = sorted[(int) (sorted.length * 0.999)];

        long[] spent = new long[PHASES.length];
        int[] worst = new int[PHASES.length];
        int counted = 0;
        for (long[][] thread : times) {
            for (int i = 0; i < thread[0].length; i++) {
                long whole = thread[0][i] + thread[1][i] + thread[2][i] + thread[3][i];
                if (whole < threshold) {
                    continue;
                }
                counted++;
                int slowest = 0;
                for (int phase = 0; phase < PHASES.length; phase++) {
                    spent[phase] += thread[phase][i];
                    if (thread[phase][i] > thread[slowest][i]) {
                        slowest = phase;
                    }
                }
                worst[slowest]++;
            }
        }
        System.out.printf("  the slowest %d operations (over %.1f us) spent their time:%n",
                counted, threshold / 1000.0);
        for (int phase = 0; phase < PHASES.length; phase++) {
            System.out.printf("    %s %6.1f us each on average, slowest phase in %5d of them%n",
                    PHASES[phase], spent[phase] / 1000.0 / Math.max(counted, 1), worst[phase]);
        }
        // Silence the unused warning while keeping the parameter meaningful.
        assert byPhase.length == PHASES.length;
    }

    private static double at(long[] sorted, double quantile) {
        return sorted[Math.min((int) (sorted.length * quantile), sorted.length - 1)] / 1000.0;
    }

    private static DataSource hikari(BenchDatabase database, int size) throws Exception {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(database.vendorUrl());
        config.setDataSourceProperties(database.vendorProperties());
        config.setMaximumPoolSize(size);
        config.setMinimumIdle(size);
        config.setPoolName("hikari-phase");
        return new HikariDataSource(config);
    }

    private static DataSource seclume(BenchDatabase database, int size) throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setMaximumPoolSize(size);
        settings.setMinimumIdle(size);
        settings.setWarmup(true);
        settings.setName("seclume-phase");
        settings.setConnectionTimeout(Duration.ofSeconds(10));
        return new SeclumePool(database.seclume(), settings);
    }
}

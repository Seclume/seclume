package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;

/**
 * The driver tail without a pool and without JMH.
 *
 * <p>{@code TailBenchmark} says the driver is two microseconds ahead at the
 * median and twenty-five behind at p99.9, on the same pool. A pool between the
 * measurement and the driver leaves room for doubt about which of the two the
 * tail belongs to, so this takes the pool out: one connection per driver, one
 * statement, a timestamp around each execution.
 *
 * <p>The two drivers alternate in blocks rather than running one after the
 * other. A machine that slows down halfway through would otherwise put the
 * whole of that slowdown on whichever driver ran second.
 */
public final class TailProbe {

    private TailProbe() {
    }

    public static void main(String[] args) throws Exception {
        int perBlock = args.length > 0 ? Integer.parseInt(args[0]) : 50_000;
        int blocks = args.length > 1 ? Integer.parseInt(args[1]) : 10;

        BenchDatabase database = BenchDatabase.fromSystemProperties();
        String sql = database.selectOne();

        try (Connection own = database.seclume().getConnection();
             Connection vendor = java.sql.DriverManager.getConnection(
                     database.vendorUrl(), database.vendorProperties())) {

            long[] ownTimes = new long[perBlock * blocks];
            long[] vendorTimes = new long[perBlock * blocks];

            // Warm up both, or the first block measures the JIT.
            run(own, sql, new long[perBlock], 0, perBlock);
            run(vendor, sql, new long[perBlock], 0, perBlock);

            for (int block = 0; block < blocks; block++) {
                run(own, sql, ownTimes, block * perBlock, perBlock);
                run(vendor, sql, vendorTimes, block * perBlock, perBlock);
            }
            System.out.println("prepare + execute, one connection, single threaded");
            report("seclume", ownTimes);
            report("pgjdbc  ", vendorTimes);

            // The same again with the statement prepared once. What is left is
            // the execution path - bind, send, read the answer - which is what
            // a pool with a statement cache actually runs.
            try (PreparedStatement ownStatement = own.prepareStatement(sql);
                 PreparedStatement vendorStatement = vendor.prepareStatement(sql)) {
                execute(ownStatement, new long[perBlock], 0, perBlock);
                execute(vendorStatement, new long[perBlock], 0, perBlock);
                for (int block = 0; block < blocks; block++) {
                    execute(ownStatement, ownTimes, block * perBlock, perBlock);
                    execute(vendorStatement, vendorTimes, block * perBlock, perBlock);
                }
            }
            System.out.println("execute only, statement prepared once");
            report("seclume", ownTimes);
            report("pgjdbc  ", vendorTimes);
        }
    }

    /** Runs {@code count} queries and writes their times from {@code offset} on. */
    private static void run(Connection connection, String sql, long[] into, int offset,
            int count) throws Exception {
        for (int i = 0; i < count; i++) {
            long start = System.nanoTime();
            try (PreparedStatement statement = connection.prepareStatement(sql);
                 ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    result.getInt(1);
                }
            }
            into[offset + i] = System.nanoTime() - start;
        }
    }

    /** The same, on a statement that was prepared once. */
    private static void execute(PreparedStatement statement, long[] into, int offset,
            int count) throws Exception {
        for (int i = 0; i < count; i++) {
            long start = System.nanoTime();
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    result.getInt(1);
                }
            }
            into[offset + i] = System.nanoTime() - start;
        }
    }

    private static void report(String name, long[] times) {
        long[] sorted = times.clone();
        Arrays.sort(sorted);
        System.out.printf("%s  p50 %6.1f  p90 %6.1f  p99 %7.1f  p99.9 %8.1f  "
                + "p99.99 %8.1f  max %9.1f us%n",
                name, at(sorted, 0.50), at(sorted, 0.90), at(sorted, 0.99),
                at(sorted, 0.999), at(sorted, 0.9999), sorted[sorted.length - 1] / 1000.0);
    }

    private static double at(long[] sorted, double quantile) {
        int index = (int) (sorted.length * quantile);
        return sorted[Math.min(index, sorted.length - 1)] / 1000.0;
    }
}

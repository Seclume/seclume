package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;

/**
 * Reading rows, where the driver's own work is the whole cost.
 *
 * <p>The opposite measurement to {@code FrameworkShapeProbe}, and it belongs on
 * a <b>local</b> server for exactly the reason that one belongs on a remote
 * one. Round trips are what a network charges for, so saving them shows over a
 * network and vanishes on loopback. Decoding is what a large result charges
 * for, so it shows on loopback and vanishes behind the transfer of a network.
 * Measuring both on the same server would have hidden one of them.
 *
 * <p>The claim under test is the first one in performance.md: this driver does
 * not materialise a {@code String} while reading. Values stay in the receive
 * buffer and become Java objects when - and only when - the caller asks for
 * them. Two access patterns put a number on what that is worth:
 *
 * <ul>
 *   <li><b>all</b> - every column of every row is read, the case that gives the
 *       advantage the least room</li>
 *   <li><b>one</b> - only the first column is read, which is what a query with
 *       {@code select *} behind it usually amounts to</li>
 * </ul>
 */
public final class RowsProbe {

    private RowsProbe() {
    }

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0] : "seclume";
        int rows = args.length > 1 ? Integer.parseInt(args[1]) : 10_000;
        int repeats = args.length > 2 ? Integer.parseInt(args[2]) : 200;

        BenchDatabase database = BenchDatabase.fromSystemProperties();
        String sql = database.selectRows(rows);

        try (Connection connection = "seclume".equals(which)
                ? database.seclume().getConnection()
                : java.sql.DriverManager.getConnection(
                        database.vendorUrl(), database.vendorProperties());
             PreparedStatement statement = connection.prepareStatement(sql)) {

            for (boolean everything : new boolean[] {true, false}) {
                for (int i = 0; i < 20; i++) {
                    read(statement, everything);
                }
                long before = allocated();
                long[] times = new long[repeats];
                for (int i = 0; i < repeats; i++) {
                    long began = System.nanoTime();
                    read(statement, everything);
                    times[i] = System.nanoTime() - began;
                }
                long bytes = allocated() - before;
                Arrays.sort(times);
                System.out.printf("%-9s %6d rows, %-3s columns read: p50 %8.0f  p99 %8.0f us"
                        + "   %6.0f B per row%n",
                        which, rows, everything ? "all" : "one",
                        times[times.length / 2] / 1000.0,
                        times[(int) (times.length * 0.99)] / 1000.0,
                        bytes / (double) repeats / rows);
            }
        }
    }

    private static void read(PreparedStatement statement, boolean everything) throws Exception {
        try (ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                result.getInt(1);
                if (everything) {
                    result.getString(2);
                    result.getBigDecimal(3);
                }
            }
        }
    }

    /**
     * Bytes this thread has allocated, or -1 where the JVM will not say.
     *
     * <p>Through the management bean rather than a profiler: this probe is not
     * run under JMH, and an allocation number that needs a second tool beside
     * it does not get looked at.
     */
    private static long allocated() {
        java.lang.management.ThreadMXBean beans =
                java.lang.management.ManagementFactory.getThreadMXBean();
        if (beans instanceof com.sun.management.ThreadMXBean sun) {
            return sun.getCurrentThreadAllocatedBytes();
        }
        return -1;
    }
}

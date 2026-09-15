package space.seclume.bench;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

/**
 * The execution path under load, with nothing else in the picture.
 *
 * <p>{@code PhaseTailProbe} narrowed the remaining p99.9 gap to the execution
 * phase and showed it appears with concurrency: ahead of pgjdbc on one thread,
 * behind from four on, and the gap grows to ten microseconds at thirty-two.
 * That rules out a rare extra round trip, which would show on one thread too.
 *
 * <p>What it does not rule out is the pool. So this takes the pool away
 * entirely: every thread opens its own connection, prepares once, and does
 * nothing but execute. If the gap survives that, it belongs to the driver's
 * own I/O path under concurrent load and nowhere else. It does: at sixteen
 * threads the gap is still there without any pool at all.
 *
 * <p>And a second measurement, taken with the read and write syscalls timed
 * from inside the driver, says where it is not: on one thread the two calls
 * account for 24.3 us of a 23.2 us median, at sixteen for 77.1 of 78.8. The
 * driver's own work is not measurable beside them. What differs between the
 * drivers at this point is what the kernel and the server do, on a machine
 * where sixteen client threads and sixteen backends share twenty-four cores -
 * which is worth knowing before spending another day on the driver.
 *
 * <pre>
 * java -cp seclume-bench.jar --enable-native-access=ALL-UNNAMED \
 *      space.seclume.bench.ConcurrentExecuteProbe seclume 16 40000
 * </pre>
 */
public final class ConcurrentExecuteProbe {

    private ConcurrentExecuteProbe() {
    }

    public static void main(String[] args) throws Exception {
        String which = args.length > 0 ? args[0] : "seclume";
        int threads = args.length > 1 ? Integer.parseInt(args[1]) : 16;
        int perThread = args.length > 2 ? Integer.parseInt(args[2]) : 40_000;

        BenchDatabase database = BenchDatabase.fromSystemProperties();
        String sql = database.selectOne();

        Connection[] connections = new Connection[threads];
        for (int i = 0; i < threads; i++) {
            connections[i] = "seclume".equals(which)
                    ? database.seclume().getConnection()
                    : java.sql.DriverManager.getConnection(
                            database.vendorUrl(), database.vendorProperties());
        }

        long[][] times = new long[threads][perThread];
        CountDownLatch start = new CountDownLatch(1);
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int index = t;
            workers[t] = new Thread(() -> {
                try (PreparedStatement statement = connections[index].prepareStatement(sql)) {
                    // Warm up outside the measurement, and make sure the plan
                    // exists on the server before the first timed execution.
                    for (int i = 0; i < 200; i++) {
                        drain(statement);
                    }
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        long began = System.nanoTime();
                        drain(statement);
                        times[index][i] = System.nanoTime() - began;
                    }
                } catch (Exception failure) {
                    throw new RuntimeException(failure);
                }
            });
            workers[t].start();
        }
        // Let every thread finish its warm-up before any of them is timed.
        Thread.sleep(500);
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }

        long[] all = new long[threads * perThread];
        for (int t = 0; t < threads; t++) {
            System.arraycopy(times[t], 0, all, t * perThread, perThread);
        }
        Arrays.sort(all);
        System.out.printf("%-9s %2d threads  p50 %6.1f  p99 %7.1f  p99.9 %8.1f  "
                + "p99.99 %8.1f  max %9.1f us%n",
                which, threads, at(all, 0.50), at(all, 0.99), at(all, 0.999),
                at(all, 0.9999), all[all.length - 1] / 1000.0);

        for (Connection connection : connections) {
            connection.close();
        }
    }

    private static void drain(PreparedStatement statement) throws Exception {
        try (ResultSet rows = statement.executeQuery()) {
            while (rows.next()) {
                rows.getInt(1);
            }
        }
    }

    private static double at(long[] sorted, double quantile) {
        return sorted[Math.min((int) (sorted.length * quantile), sorted.length - 1)] / 1000.0;
    }
}

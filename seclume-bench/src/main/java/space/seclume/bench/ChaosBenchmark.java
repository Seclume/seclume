package space.seclume.bench;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.tck.BreakableRelay;

/**
 * What a failure costs, in the numbers an operator actually asks about.
 *
 * <p>Queries per second is what everybody publishes. Nobody publishes how long
 * a failover takes, how many requests fail while it happens, or - the
 * uncomfortable one - <b>how many writes end up in doubt</b>: the client got
 * an error and the server did the work anyway. That last number is the whole
 * reason a driver must not retry silently, and it is measurable here because
 * every row carries the number it was written with.
 *
 * <p><b>How the failure is produced.</b> The driver is pointed at a list of
 * two: a relay in this process and the real server behind it. The relay is cut
 * mid-run, so the connections in flight die exactly the way they do when a
 * database node goes away, and only the second entry is left. That is a
 * rollout in miniature and needs no second server.
 *
 * <p>Deliberately a measuring instrument and not a test: it prints numbers, it
 * does not assert them. What it found on its first run is pinned by a test
 * instead - {@code BrokenConnectionIsNotReusedTest} in the pool module - which
 * is the better arrangement: the instrument may change, the defect it found
 * must not come back.
 *
 * <p><b>What it found.</b> A statement runs on the driver's own object rather
 * than through the pool, so a connection dying mid-statement was never marked
 * as broken. It went back into the pool and came straight out again, because
 * it had been returned a moment ago and the validation window skips the check
 * for half a second. Under load that meant every request failed for as long as
 * the traffic lasted. The first run reported 160 failed requests out of 200
 * and no failover at all; after the fix, 1 and 1 ms.
 *
 * <p>The fix has two halves, and both were needed: a driver now closes its
 * channel when the connection breaks, so {@code isClosed()} tells the truth;
 * and the pool asks that question when a connection comes back, which costs
 * no round trip. Three of the four drivers were not closing - SQL Server
 * already was.
 *
 * <pre>
 * java -cp seclume-bench.jar space.seclume.bench.ChaosBenchmark
 *      -Dbench.db=postgresql -Dbench.host=... -Dbench.password.file=...
 * </pre>
 */
public final class ChaosBenchmark {

    /** What one run found. */
    public record Report(int requestsBefore, int requestsFailed, long failoverMillis,
                         int writesConfirmed, int writesInDoubt, int writesLost,
                         long poolRecoveryMillis, int reportedUnknown, int inDoubtUnreported) {

        @Override
        public String toString() {
            return """
                    requests before the cut   %d
                    requests that failed      %d
                    time to failover          %d ms
                    writes confirmed          %d
                    writes in doubt           %d   (the client saw an error, the row is there)
                    writes lost               %d   (the client saw an error, the row is not)
                    pool back to full         %d ms
                    reported as unknown       %d   (08007 - the client was told it cannot know)
                    in doubt and not told so  %d   (the number that has to be zero)"""
                    .formatted(requestsBefore, requestsFailed, failoverMillis,
                            writesConfirmed, writesInDoubt, writesLost, poolRecoveryMillis,
                            reportedUnknown, inDoubtUnreported);
        }
    }

    private ChaosBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        System.out.println("chaos benchmark against " + database);
        System.out.println(run(database, 200, Duration.ofSeconds(20)));
    }

    /**
     * Writes rows until the relay is cut, then keeps writing until they land
     * again - and afterwards asks the server which of them are there.
     *
     * @param rows    how many rows to write in total
     * @param patience how long to keep trying after the cut before giving up
     */
    public static Report run(BenchDatabase database, int rows, Duration patience)
            throws Exception {
        prepareTable(database);

        try (BreakableRelay relay = BreakableRelay.to(database.host(), database.port())) {
            PoolSettings settings = new PoolSettings();
            settings.setName("chaos");
            settings.setMaximumPoolSize(4);
            settings.setConnectionTimeout(Duration.ofSeconds(5));
            // The default validation window on purpose - half a second, the
            // production setting. Checking every checkout would hide the
            // number this benchmark exists for: a connection returned a
            // moment ago goes out unchecked, and if it dies with a statement
            // on it, that statement is in doubt. Measuring with the check
            // turned up to always would report zero and mean nothing.

            try (SeclumePool pool = new SeclumePool(
                    database.failoverSource("127.0.0.1", relay.port()), settings)) {

                List<Integer> attempted = new ArrayList<>();
                List<Integer> confirmed = new ArrayList<>();
                List<Integer> unknown = new ArrayList<>();
                int failed = 0;
                int before = 0;
                long cutAt = 0;
                long backAt = 0;
                boolean cut = false;
                boolean swallowed = false;

                for (int n = 1; n <= rows; n++) {
                    Outcome outcome = writeOne(pool, n);
                    boolean ok = outcome == Outcome.CONFIRMED;
                    if (outcome == Outcome.UNKNOWN) {
                        unknown.add(n);
                    }
                    attempted.add(n);
                    if (ok) {
                        confirmed.add(n);
                        if (!cut) {
                            before++;
                        } else if (backAt == 0) {
                            backAt = System.nanoTime();
                        }
                    } else {
                        failed++;
                    }
                    // Two failures, in the order they hurt. First the answers
                    // are swallowed for a stretch: the server does the work and
                    // the client is told nothing, which is what puts a write in
                    // doubt. Then the relay is cut outright, which is the
                    // ordinary "the node went away" and is what the failover
                    // time is measured from.
                    if (!swallowed && n == rows / 5) {
                        relay.swallowAnswers();
                        swallowed = true;
                    }
                    if (!cut && n == rows / 4) {
                        cutAt = System.nanoTime();
                        relay.cut();
                        cut = true;
                    }
                    if (cut && backAt == 0
                            && System.nanoTime() - cutAt > patience.toNanos()) {
                        break;
                    }
                }

                long failover = backAt == 0 ? -1 : (backAt - cutAt) / 1_000_000;
                long poolBack = poolRecovery(pool);

                // What the server actually has. A row that is there although
                // the client was told the write failed is the interesting one.
                List<Integer> present = rowsPresent(database);
                int inDoubt = 0;
                int lost = 0;
                int unreported = 0;
                for (int n : attempted) {
                    boolean clientSawSuccess = confirmed.contains(n);
                    boolean serverHasIt = present.contains(n);
                    if (!clientSawSuccess && serverHasIt) {
                        inDoubt++;
                        // Applied, and the client was told only "failed" -
                        // the case 08007 exists to make impossible.
                        if (!unknown.contains(n)) {
                            unreported++;
                        }
                    } else if (!clientSawSuccess) {
                        lost++;
                    }
                }
                return new Report(before, failed, failover,
                        confirmed.size(), inDoubt, lost, poolBack, unknown.size(), unreported);
            }
        }
    }

    /** What the client was told about one write. */
    private enum Outcome { CONFIRMED, FAILED, UNKNOWN }

    /** One write, reporting what the client was told - nothing more. */
    private static Outcome writeOne(SeclumePool pool, int n) {
        try (Connection connection = pool.getConnection();
                PreparedStatement insert = connection.prepareStatement(
                        "insert into zl_chaos (n) values (?)")) {
            insert.setInt(1, n);
            insert.executeUpdate();
            return Outcome.CONFIRMED;
        } catch (SQLException failure) {
            if (System.getProperty("chaos.trace") != null) {
                System.err.println("[chaos] row " + n + " failed: " + failure.getMessage());
            }
            return failure instanceof space.seclume.TransactionResolutionUnknownException
                    ? Outcome.UNKNOWN : Outcome.FAILED;
        }
    }

    /** How long until the pool can hand out a working connection again. */
    private static long poolRecovery(SeclumePool pool) {
        long start = System.nanoTime();
        for (int attempt = 0; attempt < 50; attempt++) {
            try (Connection connection = pool.getConnection();
                    Statement statement = connection.createStatement()) {
                statement.execute("select 1");
                return (System.nanoTime() - start) / 1_000_000;
            } catch (SQLException notYet) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException stopped) {
                    Thread.currentThread().interrupt();
                    return -1;
                }
            }
        }
        return -1;
    }

    private static void prepareTable(BenchDatabase database) throws SQLException {
        try (Connection connection = database.seclume().getConnection();
                Statement statement = connection.createStatement()) {
            try {
                statement.execute("drop table zl_chaos");
            } catch (SQLException none) {
                // It was not there, which is the ordinary case.
            }
            statement.execute(database.kind() == BenchDatabase.Kind.ORACLE
                    ? "create table zl_chaos (n number(9))"
                    : "create table zl_chaos (n int)");
        }
    }

    private static List<Integer> rowsPresent(BenchDatabase database) throws SQLException {
        List<Integer> present = new ArrayList<>();
        try (Connection connection = database.seclume().getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select n from zl_chaos")) {
            while (rows.next()) {
                present.add(rows.getInt(1));
            }
        }
        return present;
    }
}

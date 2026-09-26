package space.seclume.bench;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.PoolStatistics;
import space.seclume.pool.SeclumePool;

/**
 * What a credential rotation costs an application that is busy at the time.
 *
 * <p>The README's claim is that a rotation "does not drop a connection". That
 * is a sentence, and the only thing that makes it a fact is a run with traffic
 * on it. This is that run: a pool under continuous load, a credential that
 * lapses in the middle of it, and two numbers out the other end - <b>how long
 * the pool took to turn over, and how many requests failed while it did</b>.
 * The second one is the claim. Anything above zero and the sentence has to be
 * rewritten rather than explained.
 *
 * <p><b>What is and is not being rotated.</b> The password in the database is
 * not changed - that would need an {@code alter user} against somebody's
 * server, and it is not what the pool's behaviour depends on anyway. What is
 * changed is the <b>expiry the pool is told about</b>, which is exactly the
 * signal a Vault lease or an IAM token gives it. The connections are retired
 * and replaced on that signal, which is the mechanism under test; that the new
 * connection uses the same bytes as the old one is irrelevant to every line of
 * code involved.
 *
 * <p>The distinction is worth being exact about rather than glossing: this
 * measures the pool's response to an expiry, not a secret manager's rotation
 * latency. The second number belongs to Vault and is theirs to publish.
 *
 * <p>A measuring instrument, not a test: it prints numbers and asserts
 * nothing. What must not regress is pinned by {@code CredentialExpiryTest} in
 * the pool module.
 *
 * <pre>
 * java -cp seclume-bench.jar space.seclume.bench.RotationBenchmark
 *      -Dbench.db=postgresql -Dbench.host=... -Dbench.password.file=...
 * </pre>
 */
public final class RotationBenchmark {

    /** What one rotation looked like from the application's side. */
    public record Report(int poolSize, long turnoverMillis, long firstRetirementBeforeExpiryMillis,
                         int requests, int failed, long prewarmed, long retired, long created) {

        @Override
        public String toString() {
            return """
                    pool size                 %d
                    requests during rotation  %d
                    requests that failed      %d   (the number the claim is about)
                    pool turnover             %d ms
                    first retirement before   %d ms   (ahead of the expiry, not after it)
                    connections retired       %d
                    connections opened        %d
                    of those, prewarmed       %d   (opened before the one they replace went)"""
                    .formatted(poolSize, requests, failed, turnoverMillis,
                            firstRetirementBeforeExpiryMillis, retired, created, prewarmed);
        }
    }

    private static final int POOL_SIZE = 6;

    /** How long the traffic runs before the first lease runs out. */
    private static final Duration SETTLE = Duration.ofSeconds(2);

    /** How far ahead of the expiry the pool is asked to act. */
    private static final Duration MARGIN = Duration.ofSeconds(2);

    /**
     * How wide the cohort is spread, and deliberately not the default.
     *
     * <p>The production default is a minute: a pool whose whole cohort was
     * opened in one burst must not retire it in one housekeeping round, and a
     * minute of jitter is how that is avoided. Measuring with it would mean a
     * run of over a minute reporting the width of a random window rather than
     * what a rotation costs, so it is narrowed here and said out loud.
     */
    private static final Duration SPREAD = Duration.ofMillis(500);

    private RotationBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        BenchDatabase database = BenchDatabase.fromSystemProperties();
        System.out.println("rotation benchmark against " + database);
        System.out.println(run(database, Duration.ofSeconds(30)));
    }

    /**
     * Traffic across a lease ending and the next one beginning.
     *
     * <p>Two leases, as a secret manager really hands them out: the first one
     * ends shortly after the traffic has settled, and a connection opened
     * after that point gets the second, which runs for an hour. That is what
     * the supplier below says, and it is the whole fixture - the pool is told
     * nothing else and is never prompted.
     *
     * <p>Modelling it as one expiry that never moves would be the easy
     * version and would be wrong: every connection would then be born already
     * expired, the pool would churn for ever, and the numbers would describe a
     * situation no secret manager produces.
     *
     * @param patience how long to wait for the turnover before giving up
     */
    public static Report run(BenchDatabase database, Duration patience) throws Exception {
        PoolSettings settings = new PoolSettings();
        settings.setName("rotation");
        settings.setMaximumPoolSize(POOL_SIZE);
        settings.setMinimumIdle(POOL_SIZE);
        settings.setConnectionTimeout(Duration.ofSeconds(5));
        // Housekeeping runs at the beat of the validation timeout, so this is
        // the resolution of every number below.
        settings.setValidationTimeout(Duration.ofMillis(200));
        // Only the credential may retire a connection here. Age and idleness
        // would retire connections too and the turnover would be measuring
        // three things at once.
        settings.setMaxLifetime(Duration.ZERO);
        settings.setIdleTimeout(Duration.ZERO);
        settings.setCredentialMargin(MARGIN);
        settings.setCredentialSpread(SPREAD);

        // The earliest the pool may retire anything is margin plus spread
        // before the lease ends, so the lease is placed to make that moment
        // the end of the settle phase - otherwise the rotation happens while
        // the traffic is still warming up and the run measures nothing.
        Instant actsAt = Instant.now().plus(SETTLE);
        Instant firstLeaseEnds = actsAt.plus(MARGIN).plus(SPREAD);
        Instant secondLeaseEnds = Instant.now().plus(Duration.ofHours(1));
        // A connection opened from here on gets the next lease, which is what
        // a client does when the current one is inside its margin. Without
        // that switch the replacements would inherit the lease that is ending
        // and the pool would churn until it did end.
        settings.setCredentialExpiry(() ->
                Instant.now().isBefore(actsAt) ? firstLeaseEnds : secondLeaseEnds);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicInteger requests = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();

        try (SeclumePool pool = new SeclumePool(database.seclume(), settings)) {
            warmUp(pool);
            PoolStatistics before = pool.statistics();

            List<Thread> traffic = new ArrayList<>();
            for (int i = 0; i < POOL_SIZE; i++) {
                traffic.add(Thread.ofVirtual().start(() -> {
                    while (running.get()) {
                        requests.incrementAndGet();
                        if (!selectOne(pool, database)) {
                            failed.incrementAndGet();
                        }
                    }
                }));
            }

            try {
                // Everything up to the moment the pool may act is the quiet
                // half, and it is subtracted below: a rotation that failed
                // nothing is only interesting against the requests that were
                // in flight while it happened.
                sleepUntil(actsAt);
                int quietRequests = requests.get();
                int quietFailures = failed.get();
                long actedAt = System.nanoTime();

                long firstRetirement = 0;
                long finishedAt = 0;
                long deadline = actedAt + patience.toNanos();
                while (System.nanoTime() < deadline) {
                    PoolStatistics now = pool.statistics();
                    if (firstRetirement == 0 && now.retired() > before.retired()) {
                        firstRetirement = System.nanoTime();
                    }
                    if (now.retired() - before.retired() >= POOL_SIZE) {
                        finishedAt = System.nanoTime();
                        break;
                    }
                    Thread.sleep(20);
                }

                running.set(false);
                for (Thread worker : traffic) {
                    worker.join();
                }

                PoolStatistics after = pool.statistics();
                long turnover = finishedAt == 0 ? -1 : (finishedAt - actedAt) / 1_000_000;
                // Positive means the pool acted before the credential lapsed,
                // which is the whole point of the margin. Negative would mean
                // afterwards, and afterwards is an authentication error in
                // somebody's application.
                long beforeExpiry = firstRetirement == 0 ? -1
                        : (actedAt + MARGIN.toNanos() + SPREAD.toNanos() - firstRetirement)
                                / 1_000_000;
                return new Report(POOL_SIZE,
                        turnover,
                        beforeExpiry,
                        requests.get() - quietRequests,
                        failed.get() - quietFailures,
                        after.prewarmed() - before.prewarmed(),
                        after.retired() - before.retired(),
                        after.created() - before.created());
            } finally {
                running.set(false);
                for (Thread worker : traffic) {
                    worker.join();
                }
            }
        }
    }

    private static void sleepUntil(Instant moment) throws InterruptedException {
        long millis = Duration.between(Instant.now(), moment).toMillis();
        if (millis > 0) {
            Thread.sleep(millis);
        }
    }

    /** Every connection of the pool open and back in it before anything is measured. */
    private static void warmUp(SeclumePool pool) throws SQLException {
        List<Connection> held = new ArrayList<>();
        try {
            for (int i = 0; i < POOL_SIZE; i++) {
                held.add(pool.getConnection());
            }
        } finally {
            for (Connection connection : held) {
                try {
                    connection.close();
                } catch (SQLException ignored) {
                    // Returning a connection cannot fail usefully here.
                }
            }
        }
    }

    private static boolean selectOne(SeclumePool pool, BenchDatabase database) {
        try (Connection connection = pool.getConnection();
                Statement statement = connection.createStatement()) {
            statement.execute(database.selectOne());
            return true;
        } catch (SQLException failure) {
            if (System.getProperty("rotation.trace") != null) {
                System.err.println("[rotation] " + failure.getMessage());
            }
            return false;
        }
    }
}

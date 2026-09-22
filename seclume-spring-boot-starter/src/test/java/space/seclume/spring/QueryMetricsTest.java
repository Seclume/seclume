package space.seclume.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import space.seclume.QueryFingerprint;
import space.seclume.jfr.Observed;

/**
 * The events as meters - and the bound that keeps them affordable.
 *
 * <p>Nothing is instrumented twice here: the test emits the same events a
 * driver emits, through the same {@link Observed} the drivers call, and asks
 * whether the bridge turned them into meters. So it also checks the part that
 * cannot be seen in the drivers - that the field names the bridge reads are
 * the ones the events actually carry, which no compiler checks.
 */
@Timeout(120)
class QueryMetricsTest {

    /** A recording stream flushes on its own schedule; this waits for it. */
    private static void until(BooleanSupplier done, String what) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (System.nanoTime() < deadline) {
            if (done.getAsBoolean()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("waited thirty seconds for " + what);
    }

    @Test
    void aSlowStatementBecomesATimerUnderItsFingerprint() throws Exception {
        MeterRegistry registry = new SimpleMeterRegistry();
        // Threshold zero: every statement counts as slow, because a test that
        // needed a genuinely slow one would be a test of the clock.
        try (SeclumeQueryMetrics metrics = new SeclumeQueryMetrics(Duration.ZERO, 100)) {
            metrics.bindTo(registry);

            for (int i = 0; i < 3; i++) {
                Observed.endQuery(Observed.beginQuery("postgresql"), "postgresql",
                        "select * from customer where id = 4711",
                        QueryFingerprint.Dialect.POSTGRESQL, 1, false);
            }

            until(() -> registry.find("seclume.query.slow").timer() != null,
                    "the statement to reach the registry");

            Timer timer = registry.find("seclume.query.slow").timer();
            assertNotNull(timer);
            assertEquals("postgresql", timer.getId().getTag("kind"));
            assertEquals("ok", timer.getId().getTag("outcome"));
            // The fingerprint, not the statement. 4711 must not be a tag
            // value, and it cannot be: the event never carried it.
            assertEquals("select * from customer where id = ?",
                    timer.getId().getTag("fingerprint"));
        }
    }

    /** A cache lookup arrives with its answer, not with its statement. */
    @Test
    void aCacheLookupBecomesACounter() throws Exception {
        MeterRegistry registry = new SimpleMeterRegistry();
        try (SeclumeQueryMetrics metrics = new SeclumeQueryMetrics(Duration.ZERO, 100)) {
            metrics.bindTo(registry);

            Observed.statementCache("select * from invoice where total > 99.95",
                    QueryFingerprint.Dialect.POSTGRESQL, true);

            until(() -> registry.find("seclume.statement.cache").counter() != null,
                    "the cache lookup to reach the registry");

            var counter = registry.find("seclume.statement.cache").counter();
            assertNotNull(counter);
            assertEquals("hit", counter.getId().getTag("result"));
            assertEquals("select * from invoice where total > ?",
                    counter.getId().getTag("fingerprint"));
        }
    }

    /**
     * The bound, which is the point of the whole class.
     *
     * <p>An application with generated SQL has thousands of shapes, and each
     * tag value is a time series somebody's metrics backend keeps forever. So
     * three shapes go in with a bound of two: two get a name and the third
     * becomes {@code other}, with the total still right.
     */
    @Test
    void beyondTheBoundTheShapesAreCountedTogether() throws Exception {
        MeterRegistry registry = new SimpleMeterRegistry();
        try (SeclumeQueryMetrics metrics = new SeclumeQueryMetrics(Duration.ZERO, 2)) {
            metrics.bindTo(registry);

            for (String table : List.of("customer", "invoice", "shipment")) {
                Observed.endQuery(Observed.beginQuery("postgresql"), "postgresql",
                        "select * from " + table + " where id = 1",
                        QueryFingerprint.Dialect.POSTGRESQL, 1, false);
            }

            until(() -> registry.find("seclume.query.slow").timers().size() >= 3,
                    "three shapes to reach the registry");

            Set<String> tags = registry.find("seclume.query.slow").timers().stream()
                    .map(t -> t.getId().getTag("fingerprint"))
                    .collect(Collectors.toSet());
            assertTrue(tags.contains(SeclumeQueryMetrics.OTHER),
                    "the third shape should have been folded into one series: " + tags);
            assertEquals(3, tags.size(), "two named and one other, got " + tags);

            long counted = registry.find("seclume.query.slow").timers().stream()
                    .mapToLong(Timer::count).sum();
            assertEquals(3, counted, "the bound may lose the attribution, never the total");
        }
    }

    /** With the bound at zero there is one series and no attribution at all. */
    @Test
    void aBoundOfZeroKeepsTheTotalsAndNothingElse() {
        SeclumeQueryMetrics metrics = new SeclumeQueryMetrics(Duration.ZERO, 0);
        assertEquals(SeclumeQueryMetrics.OTHER, metrics.bounded("select 1"));
        assertEquals(SeclumeQueryMetrics.OTHER, metrics.bounded("select 2"));
    }

    /**
     * Closing it stops the stream.
     *
     * <p>Which matters more than it sounds: a recording stream that outlives
     * its registry keeps a thread and keeps writing into meters nobody reads.
     * The context calls this on shutdown - see the bean's {@code destroyMethod}.
     */
    @Test
    void closingItStopsTheStream() throws Exception {
        MeterRegistry registry = new SimpleMeterRegistry();
        SeclumeQueryMetrics metrics = new SeclumeQueryMetrics(Duration.ZERO, 10);
        metrics.bindTo(registry);
        Observed.endQuery(Observed.beginQuery("postgresql"), "postgresql", "select 1",
                QueryFingerprint.Dialect.POSTGRESQL, 1, false);
        until(() -> registry.find("seclume.query.slow").timer() != null,
                "the statement to reach the registry");
        metrics.close();

        // A shape of its own, because "select 1" and "select 2" are the same
        // shape and would land in the timer that is already there - which is
        // what the first version of this test managed to miss.
        for (int i = 0; i < 5; i++) {
            Observed.endQuery(Observed.beginQuery("postgresql"), "postgresql",
                    "select * from after_close where id = 1",
                    QueryFingerprint.Dialect.POSTGRESQL, 1, false);
        }
        Thread.sleep(3000);

        assertNull(registry.find("seclume.query.slow")
                        .tag("fingerprint", "select * from after_close where id = ?").timer(),
                "a statement recorded after the close reached the registry");
    }
}

package space.seclume;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import space.seclume.jfr.Observed;
import space.seclume.jfr.StatementListener;

/**
 * What the detector must find, and the four things it must not call a storm.
 *
 * <p>The misses are the harder half. A detector that reports a busy
 * application is worse than none: it is turned off within a week and then it
 * finds nothing at all, which is the same outcome as never having written it
 * and costs more.
 */
class QueryStormsTest {

    @AfterEach
    void removeTheListener() {
        Observed.listen(null);
    }

    private static void run(QueryStorms storms, String fingerprint, int times) {
        for (int i = 0; i < times; i++) {
            storms.begin("postgresql").end(fingerprint, 1, false);
        }
    }

    @Test
    void aLoopOfTheSameShapeIsFound() {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms storms = QueryStorms.watching(5, Duration.ofSeconds(10), found::add);

        run(storms, "select * from item where order_id = ?", 20);

        assertEquals(1, found.size(), "expected exactly one report, got " + found);
        QueryStorms.Storm storm = found.get(0);
        assertEquals("select * from item where order_id = ?", storm.fingerprint());
        assertEquals("postgresql", storm.kind());
        assertEquals(5, storm.executions(),
                "reported at the threshold, not at the end - the loop is still running "
                + "and waiting for it to finish is waiting for the damage");
    }

    /**
     * Once per window, not once per statement.
     *
     * <p>A loop of a thousand would otherwise report itself nine hundred and
     * ninety-five times, and the report of a performance problem would be a
     * performance problem.
     */
    @Test
    void itIsReportedOnceAndNotOncePerStatement() {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms storms = QueryStorms.watching(3, Duration.ofSeconds(10), found::add);
        run(storms, "select ?", 1000);
        assertEquals(1, found.size(), "reported " + found.size() + " times");
    }

    @Test
    void aVariedRequestIsNotAStorm() {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms storms = QueryStorms.watching(5, Duration.ofSeconds(10), found::add);
        // Forty statements, all different: a complicated request, which is not
        // the same thing and must not be reported as one.
        for (int i = 0; i < 40; i++) {
            storms.begin("mysql").end("select * from t" + i + " where id = ?", 1, false);
        }
        assertTrue(found.isEmpty(), "a varied request was called a storm: " + found);
    }

    @Test
    void theSameStatementSpreadOverTimeIsNotAStorm() throws Exception {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms storms = QueryStorms.watching(3, Duration.ofMillis(40), found::add);
        for (int i = 0; i < 10; i++) {
            run(storms, "select 1", 2);
            Thread.sleep(50);
        }
        assertTrue(found.isEmpty(),
                "a statement run twice every fifty milliseconds is a cache doing its job, "
                + "not a storm: " + found);
    }

    /**
     * Two threads each doing a little is not one thread doing a lot.
     *
     * <p>Counting per process would turn every busy server into a permanent
     * storm report. An N+1 is a loop in somebody's method, and a loop runs on
     * the thread that entered it.
     */
    @Test
    void workSpreadOverThreadsIsNotAStorm() throws Exception {
        List<QueryStorms.Storm> found = new CopyOnWriteArrayList<>();
        QueryStorms storms = QueryStorms.watching(10, Duration.ofSeconds(10), found::add);

        CountDownLatch done = new CountDownLatch(8);
        for (int i = 0; i < 8; i++) {
            Thread worker = new Thread(() -> {
                run(storms, "select * from customer where id = ?", 5);
                done.countDown();
            });
            worker.setDaemon(true);
            worker.start();
        }
        assertTrue(done.await(30, TimeUnit.SECONDS));
        assertTrue(found.isEmpty(),
                "forty statements over eight threads is a busy server, not a loop: " + found);
    }

    @Test
    void aReporterThatThrowsDoesNotTakeTheStatementWithIt() {
        QueryStorms storms = QueryStorms.watching(2, Duration.ofSeconds(10), storm -> {
            throw new IllegalStateException("the application's logger is broken");
        });
        // The point is that this returns at all.
        run(storms, "select 1", 10);
    }

    @Test
    void itHandsEveryStatementOnToTheListenerItComposesWith() {
        List<String> seen = new CopyOnWriteArrayList<>();
        StatementListener other = kind -> (fingerprint, rows, failed) -> seen.add(fingerprint);
        QueryStorms storms = QueryStorms.watching(3, Duration.ofSeconds(10), storm -> { })
                .alongside(other);
        run(storms, "select 1", 4);
        assertEquals(4, seen.size(), "the composed listener saw " + seen.size() + " of 4");
    }

    @Test
    void theBoundsAreRefusedRatherThanRounded() {
        assertThrows(IllegalArgumentException.class,
                () -> QueryStorms.watching(1, Duration.ofSeconds(1), storm -> { }));
        assertThrows(IllegalArgumentException.class,
                () -> QueryStorms.watching(5, Duration.ZERO, storm -> { }));
    }

    @Test
    void installingItMakesItTheListener() {
        QueryStorms storms = QueryStorms.watching(storm -> { });
        assertTrue(!Observed.isListening(), "something was listening before this test");
        storms.install();
        assertTrue(Observed.isListening(), "install did not install anything");
    }
}

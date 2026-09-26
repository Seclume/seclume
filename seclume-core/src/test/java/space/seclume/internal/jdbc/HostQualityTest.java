package space.seclume.internal.jdbc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.sql.SQLInvalidAuthorizationSpecException;
import java.sql.SQLNonTransientConnectionException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import space.seclume.internal.JdbcUrl;

/**
 * Choosing a server by what was measured about it.
 *
 * <p>Time is the test's: the clock the back-off and the staleness are read
 * from is replaced, so "thirty seconds later" is a statement and not a wait.
 * Connect times are fed in directly where the ranking is under test, and
 * measured for real - a sleeping opener - where the question is whether
 * {@link HostList} writes them down at all.
 */
class HostQualityTest {

    private static final long SECOND = 1_000_000_000L;
    private static final long MILLI = 1_000_000L;

    private final AtomicLong now = new AtomicLong(1_000 * SECOND);

    private static final HostList.Host A = new HostList.Host("a", 1);
    private static final HostList.Host B = new HostList.Host("b", 1);
    private static final HostList.Host C = new HostList.Host("c", 1);
    private static final List<HostList.Host> ABC = List.of(A, B, C);

    @BeforeEach
    void ownClock() {
        HostQuality.forget();
        HostQuality.clock = now::get;
    }

    @AfterEach
    void realClock() {
        HostQuality.clock = System::nanoTime;
        HostQuality.forget();
    }

    private int[] order() {
        return HostQuality.order(ABC, TargetServer.ANY);
    }

    @Test
    void knowingNothingMeansTheListAsWritten() {
        assertArrayEquals(new int[] {0, 1, 2}, order());
    }

    @Test
    void theFastestMeasuredServerComesFirst() {
        HostQuality.succeeded(A, 40 * MILLI);
        HostQuality.succeeded(B, 5 * MILLI);
        HostQuality.succeeded(C, 12 * MILLI);
        assertArrayEquals(new int[] {1, 2, 0}, order());
    }

    /** A server nothing is known about is tried before the measured ones - once. */
    @Test
    void anUnmeasuredServerIsTriedToLearnAboutIt() {
        HostQuality.succeeded(A, 5 * MILLI);
        HostQuality.succeeded(B, 6 * MILLI);
        assertArrayEquals(new int[] {2, 0, 1}, order());
        HostQuality.succeeded(C, 50 * MILLI);
        assertArrayEquals(new int[] {0, 1, 2}, order(), "measured now, and slow");
    }

    @Test
    void aServerThatJustFailedIsTriedLastAndComesBackAfterItsBackOff() {
        HostQuality.succeeded(A, 5 * MILLI);
        HostQuality.succeeded(B, 20 * MILLI);
        HostQuality.succeeded(C, 30 * MILLI);
        HostQuality.failed(A);
        assertArrayEquals(new int[] {1, 2, 0}, order(), "in back-off: last");

        now.addAndGet(HostQuality.backoff(1));
        // Out of back-off, but its record now carries a failure: it is
        // weighed, not forgiven. 5 ms at a failure rate of 0.3 scores 11 ms.
        assertArrayEquals(new int[] {0, 1, 2}, order());
    }

    @Test
    void theBackOffDoublesAndStopsAtThirtySeconds() {
        assertEquals(1 * SECOND, HostQuality.backoff(1));
        assertEquals(2 * SECOND, HostQuality.backoff(2));
        assertEquals(16 * SECOND, HostQuality.backoff(5));
        assertEquals(30 * SECOND, HostQuality.backoff(6));
        assertEquals(30 * SECOND, HostQuality.backoff(60));
    }

    /** Fast and unreliable loses to reliable and a little slower. */
    @Test
    void aFlakyFastServerLosesToASteadyOne() {
        for (int i = 0; i < 5; i++) {
            HostQuality.succeeded(A, 4 * MILLI);
            HostQuality.failed(A);
            now.addAndGet(HostQuality.MAX_BACKOFF_NANOS);   // out of back-off each time
            HostQuality.succeeded(B, 8 * MILLI);
        }
        HostQuality.succeeded(A, 4 * MILLI);
        HostQuality.succeeded(C, 100 * MILLI);
        int[] order = order();
        assertEquals(1, order[0], "the steady one first: " + HostQuality.snapshot());
        assertEquals(0, order[1]);
    }

    /** A dead server that never answered stays behind every one that did. */
    @Test
    void aServerThatNeverAnsweredStaysBehindTheOthers() {
        HostQuality.failed(A);
        HostQuality.succeeded(B, 80 * MILLI);
        HostQuality.succeeded(C, 90 * MILLI);
        now.addAndGet(HostQuality.backoff(1));
        assertArrayEquals(new int[] {1, 2, 0}, order());
    }

    /**
     * Exploration: a slow server's measurement goes stale, and then it is
     * asked again - which is how a node that was slow during a restart gets
     * its traffic back.
     */
    @Test
    void aStaleMeasurementIsRenewed() {
        HostQuality.succeeded(A, 50 * MILLI);
        HostQuality.succeeded(B, 5 * MILLI);
        HostQuality.succeeded(C, 6 * MILLI);
        assertEquals(0, order()[2]);

        now.addAndGet(HostQuality.STALE_NANOS - 1);
        HostQuality.succeeded(B, 5 * MILLI);          // B and C are in use,
        HostQuality.succeeded(C, 6 * MILLI);          // so theirs stay fresh
        now.addAndGet(1);
        assertEquals(0, order()[0], "A's figure is a minute old - ask it again");

        HostQuality.succeeded(A, 3 * MILLI);          // it recovered
        assertEquals(2, order()[2], "and it now ranks on its new figure: " + HostQuality.snapshot());
    }

    /** A list asking for a primary asks the one that was the primary first. */
    @Test
    void theLastKnownRoleOrdersAListLookingForOne() {
        HostQuality.succeeded(A, 5 * MILLI);
        HostQuality.succeeded(B, 20 * MILLI);
        HostQuality.succeeded(C, 30 * MILLI);
        HostQuality.role(A, ServerRole.STANDBY);
        HostQuality.role(B, ServerRole.PRIMARY);
        HostQuality.role(C, ServerRole.STANDBY);
        assertArrayEquals(new int[] {1, 0, 2}, HostQuality.order(ABC, TargetServer.PRIMARY));
        assertArrayEquals(new int[] {0, 2, 1}, HostQuality.order(ABC, TargetServer.SECONDARY));
        assertArrayEquals(new int[] {0, 1, 2}, HostQuality.order(ABC, TargetServer.ANY));
    }

    // ------------------------------------------------ through the host list --

    /** Measured for real: the opener sleeps, and the list learns from it. */
    @Test
    void theListMeasuresAndThenPrefersTheFasterServer() throws SQLException {
        HostList list = HostList.parse("slow:1,fast:1", 5432).selecting(HostSelection.QUALITY);
        Map<String, Long> delay = Map.of("slow", 40L, "fast", 1L);
        List<String> asked = new ArrayList<>();
        HostList.Opener<String> opener = host -> {
            asked.add(host.host());
            try {
                Thread.sleep(delay.get(host.host()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return host.host();
        };
        assertEquals("slow", list.open(opener), "nothing known yet: the list as written");
        assertEquals("fast", list.open(opener), "the unmeasured one is asked next");
        for (int i = 0; i < 5; i++) {
            assertEquals("fast", list.open(opener));
        }
        assertEquals(List.of("slow", "fast", "fast", "fast", "fast", "fast", "fast"), asked);
        HostQuality.Sample slow = HostQuality.snapshot().stream()
                .filter(s -> s.host().host().equals("slow")).findFirst().orElseThrow();
        assertTrue(slow.connectMillis() >= 30, "measured: " + slow);
    }

    /** The default does not reorder anything - but it still measures. */
    @Test
    void orderedKeepsTheListAndStillMeasures() throws SQLException {
        HostList list = HostList.parse("a:1,b:1", 5432);
        assertEquals(HostSelection.ORDERED, list.selection());
        HostQuality.succeeded(A, 900 * MILLI);
        HostQuality.succeeded(B, 1 * MILLI);
        assertEquals("a", list.open(host -> host.host()), "ordered means as written");
        Map<String, Long> samples = new java.util.HashMap<>();
        HostQuality.snapshot().forEach(s -> samples.put(s.host().host(), s.samples()));
        assertEquals(Map.of("a", 2L, "b", 1L), samples, "the open was measured all the same");
    }

    @Test
    void aFailedConnectIsCountedAndARejectedLoginIsNot() {
        HostList list = HostList.parse("a:1,b:1", 5432).selecting(HostSelection.QUALITY);
        assertThrows(SQLException.class, () -> list.open(host -> {
            if (host.host().equals("a")) {
                throw new SQLNonTransientConnectionException("refused", "08001");
            }
            throw new SQLInvalidAuthorizationSpecException("wrong password", "28000");
        }));
        Map<String, HostQuality.Sample> by = new java.util.HashMap<>();
        HostQuality.snapshot().forEach(s -> by.put(s.host().host(), s));
        assertEquals(1, by.get("a").consecutiveFailures());
        assertEquals(Set.of("a"), by.keySet(),
                "a rejected password says nothing about the server and is not recorded");
    }

    @Test
    void theUrlSaysWhichWayAndATypoIsRefused() {
        JdbcUrl.Parsed parsed = JdbcUrl.parse("jdbc:x://a:1,b:2/db?hostSelection=quality",
                new java.util.Properties(), "jdbc:x:", 5432);
        assertEquals(HostSelection.QUALITY, parsed.hosts().selection());
        assertEquals(HostSelection.ORDERED, JdbcUrl.parse("jdbc:x://a:1,b:2/db",
                new java.util.Properties(), "jdbc:x:", 5432).hosts().selection());
        IllegalArgumentException typo = assertThrows(IllegalArgumentException.class,
                () -> HostSelection.of("qualty"));
        assertTrue(typo.getMessage().contains("ordered, quality"), typo.getMessage());
    }
}

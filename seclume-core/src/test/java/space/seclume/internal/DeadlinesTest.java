package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Deadlines on nanoTime: compared by difference, spans clamped. A deadline of
 * "for ever" - Long.MAX_VALUE nanoseconds, a millisecond count multiplied
 * past the range, a Duration of a million years - wrapped into the past and
 * expired at once. And a comparison with {@code <} was wrong wherever the
 * clock stood near the end of its range.
 */
class DeadlinesTest {

    @Test
    void aHugeSpanIsForEverNotThePast() {
        for (long deadline : new long[] {Deadlines.after(Long.MAX_VALUE),
                Deadlines.afterMillis(Long.MAX_VALUE), Deadlines.afterMillis(Long.MAX_VALUE / 1000),
                Deadlines.after(Duration.ofDays(365L * 1_000_000))}) {
            assertFalse(Deadlines.passed(deadline));
            assertTrue(Deadlines.remainingNanos(deadline) > Deadlines.FOREVER_NANOS / 2);
        }
    }

    @Test
    void aNegativeOrZeroSpanHasPassed() {
        assertTrue(Deadlines.passed(Deadlines.after(-5)));
        assertTrue(Deadlines.passed(Deadlines.afterMillis(0)));
        assertTrue(Deadlines.passed(Deadlines.after(Duration.ofSeconds(-3))));
        assertEquals(0, Deadlines.remainingMillis(Deadlines.after(-1)));
    }

    @Test
    void aShortSpanPassesAndRoundsUp() throws Exception {
        long deadline = Deadlines.afterMillis(50);
        assertFalse(Deadlines.passed(deadline));
        long left = Deadlines.remainingMillis(deadline);
        assertTrue(left >= 1 && left <= 50, left + " ms");
        Thread.sleep(80);
        assertTrue(Deadlines.passed(deadline));
    }

    /** The difference is right across the end of the range; {@code <} is not. */
    @Test
    void differencesHoldWhereTheClockWraps() {
        long now = Long.MAX_VALUE - 10;
        long deadline = now + 100;                 // wrapped: a negative number
        assertTrue(deadline - now > 0, "the deadline is ahead");
        assertFalse(now < deadline, "what '<' says - the reason for the rule");
    }
}

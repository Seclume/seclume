package space.seclume.internal;

import java.time.Duration;

/**
 * Deadlines on {@link System#nanoTime()}, written once and right.
 *
 * <p>The clock's origin is arbitrary and it may be anywhere, near the end of
 * the {@code long} range too: a deadline is compared with the time by their
 * difference ({@code deadline - now > 0}), never with {@code <}, which is
 * wrong once the sum has wrapped. And a span is clamped before it is added:
 * a "wait for ever" of {@code Long.MAX_VALUE} nanoseconds, or a millisecond
 * count multiplied past the range, would otherwise put the deadline in the
 * past. The wall clock plays no part - it jumps with NTP and with a restored
 * checkpoint, and a deadline on it can expire at once or never.
 */
public final class Deadlines {

    /**
     * The longest span a deadline is given - about 146 years. Half the range,
     * so that the difference between any deadline and any time read before
     * it stays positive.
     */
    public static final long FOREVER_NANOS = Long.MAX_VALUE / 2;

    private Deadlines() {
    }

    /** The deadline {@code nanos} from now; a negative span is now, a huge one about for ever. */
    public static long after(long nanos) {
        return System.nanoTime() + Math.min(Math.max(0, nanos), FOREVER_NANOS);
    }

    /** The deadline {@code millis} from now, the multiplication saturated. */
    public static long afterMillis(long millis) {
        return after(toNanos(millis));
    }

    /** The deadline {@code span} from now; a span past the range is about for ever. */
    public static long after(Duration span) {
        long nanos;
        try {
            nanos = span.toNanos();
        } catch (ArithmeticException tooLong) {
            nanos = span.isNegative() ? 0 : FOREVER_NANOS;
        }
        return after(nanos);
    }

    /** Whether {@code deadline} has come. */
    public static boolean passed(long deadline) {
        return deadline - System.nanoTime() <= 0;
    }

    /** What is left until {@code deadline}, never less than zero. */
    public static long remainingNanos(long deadline) {
        return Math.max(0, deadline - System.nanoTime());
    }

    /** What is left until {@code deadline} in whole milliseconds, rounded up; zero once it has come. */
    public static long remainingMillis(long deadline) {
        long nanos = remainingNanos(deadline);
        return nanos == 0 ? 0 : (nanos + 999_999) / 1_000_000;
    }

    /** Milliseconds as nanoseconds, saturated instead of wrapped. */
    public static long toNanos(long millis) {
        if (millis <= 0) {
            return 0;
        }
        return millis > FOREVER_NANOS / 1_000_000 ? FOREVER_NANOS : millis * 1_000_000;
    }
}

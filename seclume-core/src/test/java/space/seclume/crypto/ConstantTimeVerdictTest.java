package space.seclume.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * How {@link ConstantTimeLeakageTest} decides from its rounds, without timing
 * anything: code leaks only when every round says so, the negative control is
 * seen when one round does, and the rounds stop as soon as the verdict is in.
 */
class ConstantTimeVerdictTest {

    /** The t values of successive rounds, and which rounds were asked for. */
    private static ConstantTimeLeakageTest.Round rounds(List<Integer> asked, double... ts) {
        return round -> {
            asked.add(round);
            return ts[round];
        };
    }

    @Test
    void oneQuietRoundIsQuietAndEndsTheMeasurement() {
        List<Integer> asked = new ArrayList<>();
        assertEquals(1.2, ConstantTimeLeakageTest.quiet("x", 3, rounds(asked, 1.2, 99, 99)));
        assertEquals(List.of(0), asked);
        asked.clear();
        assertEquals(-4.49, ConstantTimeLeakageTest.quiet("x", 3, rounds(asked, 8, -12, -4.49)), "the third round");
        assertEquals(List.of(0, 1, 2), asked);
    }

    @Test
    void aLeakIsALeakInEveryRound() {
        List<Integer> asked = new ArrayList<>();
        AssertionError e = assertThrows(AssertionError.class,
                () -> ConstantTimeLeakageTest.quiet("the GCM tag check", 3, rounds(asked, 4.5, -7.25, 30)));
        assertEquals("the GCM tag check leaks: |t| above 4.5 in all 3 rounds (t = 4.50, -7.25, 30.00)",
                e.getMessage(), "exactly the threshold is not below it");
        assertEquals(List.of(0, 1, 2), asked);
    }

    @Test
    void theControlIsSeenInOneRound() {
        List<Integer> asked = new ArrayList<>();
        assertEquals(-40.0, ConstantTimeLeakageTest.seen("an early exit", 3, rounds(asked, 2, -40, 1)));
        assertEquals(List.of(0, 1), asked);
        AssertionError e = assertThrows(AssertionError.class,
                () -> ConstantTimeLeakageTest.seen("an early exit", 3, rounds(new ArrayList<>(), 4.5, -1, 0)));
        assertEquals("an early exit was not seen in 3 rounds (t = 4.50, -1.00, 0.00) - the measurement cannot tell a "
                + "leak from none", e.getMessage());
    }

    @Test
    void theNightlyRunTakesThreeRounds() {
        assertEquals(3, ConstantTimeLeakageTest.ROUNDS);
    }
}

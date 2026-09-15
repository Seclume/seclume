package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

/**
 * Choosing a transport, and the two ways that choice can go wrong quietly.
 *
 * <p>No server anywhere in here: what is being checked is which class gets
 * asked, not whether a connection succeeds.
 */
class TransportsTest {

    /** An unknown name is refused, and the message says what is known. */
    @Test
    void anUnknownTransportSaysWhatTheKnownOnesAre() {
        IOException failure = assertThrows(IOException.class,
                () -> Transports.open("quantum", "127.0.0.1", 1, 10));
        assertTrue(failure.getMessage().contains("socket"), failure.getMessage());
        assertTrue(failure.getMessage().contains("ffm"), failure.getMessage());
    }

    /**
     * Asking whether the FFM transport is available must not be what breaks.
     *
     * <p>The first version answered this question by reading a constant out of
      * a native implementation - which binds nine libc handles in its static
     * initialiser, and on anything that is not Linux the first of them throws
     * an {@code UnsatisfiedLinkError}. So the probe meant to answer „no, not
     * here" was itself the failure, and {@code ffm-if-available} broke on
     * exactly the systems it exists for. This test is that control, kept.
     */
    @Test
    void askingWhetherFfmIsAvailableWorksEverywhere() {
        // the alternate transport, developed separately
        assertEquals(System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
        // the alternate transport, developed separately
    }

    /**
     * And the fallback falls back rather than failing.
     *
     * <p>On Linux this connects to a closed port and fails for that reason; off
     * Linux it has to reach the socket transport and fail for the same reason.
     * Either way what must not happen is a linkage error.
     */
    @Test
    void theFallbackReachesATransportOnEverySystem() {
        IOException failure = assertThrows(IOException.class,
                () -> Transports.open("ffm-if-available", "127.0.0.1", 1, 200));
        assertTrue(failure.getMessage() != null && !failure.getMessage().isBlank(),
                "a refused connection should say something");
    }

    /** Explicitly asking for ffm off Linux is refused with a sentence, not a stack. */
    @Test
    void ffmOffLinuxIsRefusedWithAReason() {
        // the alternate transport, developed separately
            return;                                  // on Linux there is nothing to refuse
        }
        IOException failure = assertThrows(IOException.class,
                () -> Transports.open("ffm", "127.0.0.1", 1, 10));
        assertTrue(failure.getMessage().contains("Linux only"), failure.getMessage());
    }
}

package space.seclume.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

/**
 * What this release's opt-outs say, and that an expiring checkpoint hold
 * lets every waiter go, not only the one whose time ran out. Isolated: the
 * checkpoint gate, a system property and once-per-process warnings are the
 * JVM's.
 */
@Isolated
class ChangedLineWarningsTest {

    /**
     * Opted out with holdExpiry=release: the hold that runs out ends for
     * every login waiting on it, at once, and that is said.
     */
    @Test
    void anExpiredHoldOptedOutLetsEveryWaiterGoAndSaysSo() throws Exception {
        Checkpoint.hold();
        try {
            Thread waiter = Thread.ofPlatform().start(() -> Checkpoint.awaitOpen(60_000, true));
            Thread.sleep(100);
            List<String> warned = listen("space.seclume.crac", () -> Checkpoint.awaitOpen(50, true));
            waiter.join(5_000);
            assertFalse(waiter.isAlive(), "a waiter was not woken when the hold ended");
            assertFalse(Checkpoint.holding());
            assertEquals(1, warned.size(), warned.toString());
            assertTrue(warned.get(0).contains("seclume.crac.holdExpiry=release"), warned.get(0));
        } finally {
            Checkpoint.release();
        }
    }

    /** A lowered SCRAM floor is said once; the default itself is no lowering. */
    @Test
    void aLoweredScramFloorIsSaidAndTheDefaultIsNot() throws Exception {
        java.lang.reflect.Field said = Scram.class.getDeclaredField("WEAKENED_SAID");
        said.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicBoolean) said.get(null)).set(false);
        String before = System.getProperty(Scram.MIN_ITERATIONS_PROPERTY);
        try {
            System.setProperty(Scram.MIN_ITERATIONS_PROPERTY,
                    String.valueOf(Scram.DEFAULT_MIN_ITERATIONS));
            assertTrue(listen(Scram.class.getName(), Scram::configuredMinimum).isEmpty(),
                    "the default was said to be a lowering");
            System.setProperty(Scram.MIN_ITERATIONS_PROPERTY,
                    String.valueOf(Scram.DEFAULT_MIN_ITERATIONS - 1));
            List<String> warned = listen(Scram.class.getName(), Scram::configuredMinimum);
            assertEquals(1, warned.size(), warned.toString());
        } finally {
            if (before == null) {
                System.clearProperty(Scram.MIN_ITERATIONS_PROPERTY);
            } else {
                System.setProperty(Scram.MIN_ITERATIONS_PROPERTY, before);
            }
        }
    }

    private interface Action {
        void run() throws Exception;
    }

    private static List<String> listen(String name, Action action) throws Exception {
        List<String> warned = new CopyOnWriteArrayList<>();
        Logger logger = Logger.getLogger(name);
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel() == java.util.logging.Level.WARNING) {
                    warned.add(record.getMessage());
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            action.run();
        } finally {
            logger.removeHandler(handler);
        }
        return warned;
    }
}
